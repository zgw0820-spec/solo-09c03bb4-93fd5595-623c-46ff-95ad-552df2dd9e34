# 设备故障日志 API（两班组共用）

FastAPI + psycopg + PostgreSQL 16。两个班组共用一套服务与一张表，
班组间隔离由**数据库行级安全（RLS）**兜底，而非仅靠应用层过滤。

## 架构

```
值班员浏览器(Swagger) ──► api1 :8001 ─┐
                                      ├─► PostgreSQL 16 (db, 不对外暴露端口)
值班员浏览器(Swagger) ──► api2 :8002 ─┘
```

- 两台接口实例（`api1`/`api2`）配置相同、共享同一数据库，任一实例均可读写。
- 接口以**非表主角色** `api_user` 连接数据库，仅有 `SELECT`/`INSERT` 权限。
- 每个请求在独立事务内用 `set_config('app.team_id', 班组, true)`（事务本地）
  绑定班组身份；RLS 策略按该值过滤行。事务结束身份即失效，
  连接复用、请求报错、并发交错、实例重启都不会串用班组身份。
- 班组身份只来自服务端"令牌→班组"映射；请求体/查询参数里的班组号一律忽略。

## 启动

```bash
docker compose up -d --build
# Swagger UI: http://127.0.0.1:8001/docs  或  http://127.0.0.1:8002/docs
```

首次启动会执行 `db/init/01_init.sh`：建表、启用并 FORCE RLS、建策略、
建 `api_user` 角色并最小授权。

### 配置（生产环境务必覆盖默认值）

| 环境变量 | 说明 | 默认值（仅开发用） |
|---|---|---|
| `TEAM_TOKENS` | 逗号分隔的 `令牌:班组` 对 | `token-alpha:team_a,token-bravo:team_b` |
| `API_DB_PASSWORD` | `api_user` 的数据库口令 | `api_dev_password` |
| `POSTGRES_PASSWORD` | 超级用户口令 | `postgres_dev_password` |

可用 `.env` 文件或环境注入覆盖，例如 `TEAM_TOKENS='s3cr3t-a:team_a,s3cr3t-b:team_b'`。

## 使用

Swagger UI 右上角 **Authorize** 填入本班组令牌后：

- `POST /faults`：写入 `equipment_id`（设备号）、`occurred_at`（UTC 时间，
  须带时区如 `2026-11-19T08:30:00Z`）、`content`（故障内容）。
  `team_id` 由服务端按令牌注入，请求体里伪造班组号无效。
- `GET /faults?start=...&end=...`：按时间范围查询**本班组**记录（参数可选）。
- `GET /whoami`、`GET /healthz`：查看当前令牌对应班组 / 健康检查。

```bash
curl -X POST http://127.0.0.1:8001/faults \
  -H 'Authorization: Bearer token-alpha' -H 'Content-Type: application/json' \
  -d '{"equipment_id":"PUMP-01","occurred_at":"2026-11-19T08:30:00Z","content":"轴承过热"}'

curl 'http://127.0.0.1:8002/faults?start=2026-11-19T00:00:00Z&end=2026-11-20T00:00:00Z' \
  -H 'Authorization: Bearer token-alpha'
```

## 隔离机制与故障行为

- **RLS 策略**（`db/init/01_init.sh`）：`team_id = nullif(current_setting('app.team_id', true), '')`，
  `USING` 与 `WITH CHECK` 双向约束。GUC 未设置（NULL）或已失效（空串）时
  比较结果为 NULL → **默认拒绝**，空身份状态下读写均被拒。
- **身份绑定**：仅存在于单个事务内（`set_config(..., is_local=true)`），
  提交/回滚即清除；连接池复用的物理连接不携带上一请求的身份。
- **数据库不可用**：请求明确返回 `503 {"detail":"database unavailable"}`；
  实例无需重启，数据库恢复后连接池自动重连，按正确身份继续服务。
- **伪造防护**：令牌之外没有任何途径指定班组；越组写入被 `WITH CHECK` 拒绝。

### 信任边界说明

- 自定义 GUC 任何角色都能 `SET`，因此 `api_user` 的数据库口令本身即信任边界；
  班组与令牌的对应关系由 API 层强制。超级用户不受 RLS 约束（管理用途），
  表已 `FORCE ROW LEVEL SECURITY`，非超级用户的表主同样受限。
- `api_user` 无 `UPDATE`/`DELETE` 权限，故障记录只能追加、不可篡改。

## 自测

```bash
# Docker Compose 部署下（默认模式，含停库/重启实例用例）
python3 tests/selftest.py

# 无 docker 的环境：用钩子命令注入数据库/实例控制方式（见脚本头部注释）
python3 tests/selftest.py --mode local --psql-cmd "..." --db-stop-cmd "..." ...
```

覆盖：认证拒绝、写入归属、伪造请求体/查询参数、跨实例读取隔离、时间过滤、
40 路并发交错、RLS 直查（未设 GUC→0 行、越组过滤→0 行、越组写入被拒）、
停库→503→恢复、实例重启后身份正确。
