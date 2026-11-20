#!/bin/sh
# 数据库首次初始化脚本（由 postgres 官方镜像的 /docker-entrypoint-initdb.d 机制执行）。
# 职责：
#   1. 建表、建行级安全策略、建接口专用的非表主角色并最小授权；
#   2. 建口令轮换专用角色（无 CREATEROLE）与 SECURITY DEFINER 改密函数（最小权限）；
#   3. 建轮换状态表（协调状态 + 各实例确认），供多实例协同与断点续做。
set -eu

: "${API_DB_PASSWORD:?API_DB_PASSWORD must be set}"
: "${API_DB_PASSWORD_NEW:?API_DB_PASSWORD_NEW must be set}"
: "${ROTATOR_PASSWORD:?ROTATOR_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" \
     --set api_password="$API_DB_PASSWORD" \
     --set rotator_password="$ROTATOR_PASSWORD" <<'SQL'

-- =====================================================================
-- 一、业务角色与行级安全
-- =====================================================================

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

-- =====================================================================
-- 二、口令轮换专用角色与改密函数（最小权限）
-- =====================================================================

-- 轮换角色：仅可登录，无 CREATEROLE/SUPERUSER，不直接持有任何角色管理权。
CREATE ROLE api_rotator LOGIN PASSWORD :'rotator_password';

-- 轮换协调状态：单行表（id 恒为 1）。
CREATE TABLE password_rotation_state (
    id                    int PRIMARY KEY DEFAULT 1,
    phase                 text NOT NULL DEFAULT 'idle'
                          CHECK (phase IN ('idle','rotating','completed','failed')),
    generation            int  NOT NULL DEFAULT 0,          -- 每发起一次轮换 +1
    initiator             text,                             -- 发起实例标识（不记录口令）
    old_password_invalid  boolean NOT NULL DEFAULT false,   -- 旧口令是否已实测无法登录
    last_error            text,
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT rotation_state_singleton CHECK (id = 1)
);
INSERT INTO password_rotation_state (id, phase, generation) VALUES (1, 'idle', 0);

-- 各实例对当前轮换的确认：一行 = 一个实例“已用新口令实际建连”的证据。
CREATE TABLE password_rotation_members (
    generation     int  NOT NULL,
    instance_id    text NOT NULL,
    confirmed_at   timestamptz NOT NULL DEFAULT now(),
    detail         text,
    PRIMARY KEY (generation, instance_id)
);

REVOKE ALL ON password_rotation_state, password_rotation_members FROM PUBLIC;
-- api_user 需读状态表（后台轮询）并登记本实例确认（INSERT 即可，幂等靠 ON CONFLICT）。
GRANT SELECT ON password_rotation_state TO api_user;
GRANT SELECT, INSERT ON password_rotation_members TO api_user;
-- 轮换角色负责协调状态变更（begin/completed/failed）与状态核实。
GRANT SELECT, UPDATE ON password_rotation_state TO api_rotator;

-- 属主级 SECURITY DEFINER 改密函数：仅 api_rotator 可执行。
-- 动态 SQL 保证新口令作为值传入（quote_literal），不进入标识符位置。
-- 函数内部不读取、不打印口令明文；pg 系统目录只存 SCRAM 哈希。
CREATE OR REPLACE FUNCTION rotate_api_password(new_password text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    EXECUTE format('ALTER ROLE api_user PASSWORD %L', new_password);
END;
$$;

REVOKE ALL ON FUNCTION rotate_api_password(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rotate_api_password(text) TO api_rotator;

SQL
