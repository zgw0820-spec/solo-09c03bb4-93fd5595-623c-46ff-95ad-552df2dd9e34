#!/bin/sh
# 数据库首次初始化脚本（由 postgres 官方镜像的 /docker-entrypoint-initdb.d 机制执行）。
# 职责：建表、建行级安全策略、建接口专用的非表主角色并最小授权。
set -eu

: "${API_DB_PASSWORD:?API_DB_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" \
     --set api_password="$API_DB_PASSWORD" <<'SQL'

-- 接口专用角色：仅登录，不拥有任何表，受 RLS 约束。
CREATE ROLE api_user LOGIN PASSWORD :'api_password';

CREATE TABLE fault_logs (
    id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    team_id      text        NOT NULL,                -- 班组标识，由服务端按令牌写入
    equipment_id text        NOT NULL,
    occurred_at  timestamptz NOT NULL,                -- 故障发生时间（UTC）
    content      text        NOT NULL,                -- 故障内容
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX fault_logs_team_time_idx ON fault_logs (team_id, occurred_at);

-- 启用并强制行级安全：非表主角色只能看到/写入 app.team_id 对应的班组行。
-- current_setting(..., true) 在 GUC 未设置时返回 NULL；事务内 set_config 结束后
-- 占位符可能残留为空字符串。nullif(..., '') 把两种情况统一归一为 NULL，
-- 比较结果为 NULL → 默认拒绝（fail-closed），空身份状态下读写均被拒。
ALTER TABLE fault_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE fault_logs FORCE ROW LEVEL SECURITY;

CREATE POLICY fault_logs_team_isolation ON fault_logs
    AS PERMISSIVE
    FOR ALL
    TO api_user
    USING      (team_id = nullif(current_setting('app.team_id', true), ''))
    WITH CHECK (team_id = nullif(current_setting('app.team_id', true), ''));

-- 最小授权：只允许追加和查询，不允许改/删历史记录。
REVOKE ALL ON fault_logs FROM PUBLIC;
GRANT SELECT, INSERT ON fault_logs TO api_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO api_user;

SQL
