# 设备故障日志 API（两班组共用，支持数据库口令在线轮换）

FastAPI + psycopg + PostgreSQL 16。两个班组共用一套服务与一张表，
班组间隔离由**数据库行级安全（RLS）**兜底，而非仅靠应用层过滤。
另提供 `api_user` 数据库口令的在线轮换能力：两台实例不停机、不中断在途事务即可换密。

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
| `OPS_TOKEN` | 独立运维令牌，仅用于口令轮换接口 | `ops-token-dev` |
| `API_DB_PASSWORD` | `api_user` 的当前（旧）数据库口令 | `api_dev_password` |
| `API_DB_PASSWORD_NEW` | `api_user` 轮换后的新口令（预置） | `api_dev_password_new` |
| `ROTATOR_PASSWORD` | 最小权限轮换角色 `api_rotator` 的口令 | `rotator_dev_password` |
| `POSTGRES_PASSWORD` | 超级用户口令 | `postgres_dev_password` |

可用 `.env` 文件或环境注入覆盖（参考 `.env.example`，`.env` 已在 `.gitignore`），
例如 `TEAM_TOKENS='s3cr3t-a:team_a,s3cr3t-b:team_b'`。

## 口令轮换（在 Swagger 发起）

新旧口令、轮换角色口令均由 Docker Compose 预置，运行时不需要、也不接受在请求体里传口令。

### 角色与最小权限

- `api_user`：业务连接角色，仅 `SELECT`/`INSERT`，受 RLS 约束，无任何角色管理权。
- `api_rotator`：轮换专用角色，**无 `CREATEROLE`/`SUPERUSER`**，只能执行属主定义的
  `SECURITY DEFINER` 函数 `rotate_api_password(text)` 来改 `api_user` 的口令，
  不能直接 `ALTER ROLE`，也不能改轮换协调状态之外的任何业务数据。
- 库内 `password_rotation_state`（单行协调状态）与 `password_rotation_members`
  （各实例确认记录）是多实例协同与断点续做的事实来源。

### 双令牌体系（互不通用）

- **班组令牌**（`TEAM_TOKENS`）：只能调用 `/faults`、`/whoami` 等业务接口。
- **运维令牌**（`OPS_TOKEN`）：只能调用 `/ops/rotate-password`、`/ops/rotation-status`。
  Swagger UI 的 Authorize 中有两个独立授权项，分别填两类令牌；任一类令牌都无法访问对方接口。

### 轮换流程（`POST /ops/rotate-password`，幂等可重入）

1. 库内协调状态 `idle → rotating` 并生成新一代 `generation`（中断续做时复用同一代）。
2. 以 `api_rotator` 调用属主函数执行 `ALTER ROLE api_user PASSWORD <新口令>`；
   同值重复执行无副作用，因此中断后重放安全。
3. 发起实例先用新口令独立探活，成功后**新建新口令连接池**，再延迟关闭旧池——
   旧池等待已借出连接全部归还，**不主动 kill 会话**，在途原事务可正常提交。
4. 其余实例的后台观察线程轮询协调状态，检测到轮换后同样切到新口令池，
   并以新口令连接写入本实例确认；即使观察线程尚未到节拍，业务请求在取连接失败时
   也会探测新口令并自愈重试一次，补建连接的读写不因换密失败。
5. 协调方等待 `EXPECTED_INSTANCES`（`api1,api2`）**全部以新口令实际建连确认**。
6. **实测旧口令无法登录**（SQLSTATE 28P01；网络不通等不确定结果一律不放行）后，
   状态置为 `completed`。只有 5、6 同时满足才报完成。
7. 响应（`RotationStatusOut`）与日志均不含任何口令/连接串明文。

### 中断与重启语义（绝不切回旧口令）

- **改密回执丢失**：协调状态停在 `rotating`。重调接口先核实库内状态，复用同一
  `generation` 续做（再改一次同值口令是幂等的），不新开一代、不回退旧口令。
- **实例中途重启**：实例启动时对旧/新口令分别探活，自动选用当前有效口令建池；
  观察线程随后收敛。重启后重调接口仍按库内状态续做。
- **确认超时**：有实例始终不确认时返回 `504` 且状态置 `failed`，不会假报完成；
  故障实例恢复后重调即可续做至完成。

```bash
# 发起/续做轮换（也可在 Swagger 用「运维令牌」Authorize 后点 Try it out）
curl -X POST http://127.0.0.1:8001/ops/rotate-password -H 'Authorization: Bearer ops-token-dev'
curl http://127.0.0.1:8001/ops/rotation-status -H 'Authorization: Bearer ops-token-dev'
```

> 当前实现面向“一次性预置新旧口令”的轮换；再次轮换前需更新 Compose 中的
> `API_DB_PASSWORD`/`API_DB_PASSWORD_NEW` 并重新部署（或重建数据卷）。

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
# 1) 基线能力（Docker Compose 部署，含停库/重启实例用例）
python3 tests/selftest.py

# 2) 口令轮换专项（双令牌边界、在线轮换、换密期读写、幂等、中断续做、重启续用、不泄密）
python3 tests/rotation_selftest.py

# 无 docker 的环境：用钩子命令注入数据库/实例控制方式（见两个脚本头部注释）
python3 tests/selftest.py --mode local --psql-cmd "..." --db-stop-cmd "..." ...
```

基线覆盖：认证拒绝、写入归属、伪造请求体/查询参数、跨实例读取隔离、时间过滤、
40 路并发交错、RLS 直查（未设 GUC→0 行、越组过滤→0 行、越组写入被拒）、
停库→503→恢复、实例重启后身份正确。

轮换专项覆盖：班组/运维令牌互不可越权、fresh 在线轮换（两实例确认 + 旧口令实测被拒）、
换密期持续读写零失败、重复调用幂等同代、制造 `rotating` 中断现场后续做不新开代、
轮换中途重启后观察线程收敛到新口令、全程响应无口令明文。
