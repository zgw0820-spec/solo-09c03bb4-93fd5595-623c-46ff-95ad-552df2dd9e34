"""设备故障日志 API。

两个班组共用一套服务与一张表。隔离由数据库行级安全（RLS）兜底：
本进程以非表主角色 api_user 连接，每个请求在独立事务内用
set_config('app.team_id', ..., true)（事务本地）绑定班组身份，
事务结束身份即失效，连接归还连接池时不携带任何班组状态。
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool, PoolTimeout
from pydantic import BaseModel, ConfigDict, Field, field_validator

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("faultlog")

DATABASE_URL = os.environ["DATABASE_URL"]


def _parse_tokens(spec: str) -> dict[str, str]:
    """解析预置令牌配置：逗号分隔的 token:team 对。

    例：TEAM_TOKENS=token-alpha:team_a,token-bravo:team_b
    """
    out: dict[str, str] = {}
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        token, sep, team = part.partition(":")
        if not sep or not token or not team:
            raise ValueError(f"TEAM_TOKENS 项格式应为 token:team，收到: {part!r}")
        out[token] = team
    return out


# 预置令牌 -> 班组 映射（令牌与班组号中不得含冒号、逗号）
TEAM_TOKENS: dict[str, str] = _parse_tokens(os.environ.get("TEAM_TOKENS", ""))
if not TEAM_TOKENS:
    log.warning("TEAM_TOKENS 为空：所有请求都将以 401 拒绝")
DB_ACQUIRE_TIMEOUT = float(os.environ.get("DB_ACQUIRE_TIMEOUT", "5"))

_pool: Optional[ConnectionPool] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 惰性建池：数据库未就绪时进程照常启动，请求会得到明确的 503，
    # 数据库恢复后连接池自动重连，无需重启实例。
    global _pool
    _pool = ConnectionPool(
        conninfo=DATABASE_URL,
        min_size=1,
        max_size=int(os.environ.get("DB_POOL_MAX", "10")),
        kwargs={"row_factory": dict_row},
        open=False,
    )
    _pool.open(wait=False)
    log.info("connection pool created (lazy connect)")
    try:
        yield
    finally:
        _pool.close()
        _pool = None


app = FastAPI(title="设备故障日志 API", version="1.0.0", lifespan=lifespan)
bearer = HTTPBearer(description="值班员预置令牌")


def current_team(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> str:
    """令牌 -> 班组。班组身份只来源于服务端令牌映射，不采信请求体/参数。"""
    team = TEAM_TOKENS.get(creds.credentials)
    if team is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="invalid token")
    return team


@contextmanager
def team_connection(team: str) -> Iterator[psycopg.Connection]:
    """取一条连接，在一个事务内绑定班组身份后交给业务使用。

    set_config(..., true) 是事务本地设置：提交/回滚后自动失效，
    因此连接复用、请求报错、并发交错都不会把班组身份带给下一个请求。
    """
    if _pool is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="database pool not ready")
    try:
        with _pool.connection(timeout=DB_ACQUIRE_TIMEOUT) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('app.team_id', %s, true)", (team,))
                yield conn
    except HTTPException:
        raise
    except (psycopg.OperationalError, PoolTimeout):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="database unavailable")
    except psycopg.Error:
        log.exception("unexpected database error")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="internal database error")


class FaultIn(BaseModel):
    # 客户端多传的 team_id 等字段一律忽略，班组只由令牌决定。
    model_config = ConfigDict(extra="ignore")

    equipment_id: str = Field(min_length=1, max_length=128)
    occurred_at: datetime
    content: str = Field(min_length=1, max_length=8000)

    @field_validator("occurred_at")
    @classmethod
    def must_be_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("occurred_at 必须带时区（应为 UTC，如 2026-11-19T08:30:00Z）")
        return v.astimezone(timezone.utc)


class FaultOut(BaseModel):
    id: int
    team_id: str
    equipment_id: str
    occurred_at: datetime
    content: str
    created_at: datetime


def _aware(v: Optional[datetime], name: str) -> Optional[datetime]:
    if v is None:
        return None
    if v.tzinfo is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=f"{name} 必须带时区偏移（UTC）")
    return v.astimezone(timezone.utc)


@app.post("/faults", response_model=FaultOut, status_code=status.HTTP_201_CREATED)
def create_fault(body: FaultIn, team: str = Depends(current_team)):
    """写入一条故障记录。team_id 由服务端按令牌注入，伪造班组号无效。"""
    with team_connection(team) as conn:
        row = conn.execute(
            """
            INSERT INTO fault_logs (team_id, equipment_id, occurred_at, content)
            VALUES (%s, %s, %s, %s)
            RETURNING id, team_id, equipment_id, occurred_at, content, created_at
            """,
            (team, body.equipment_id, body.occurred_at, body.content),
        ).fetchone()
    log.info("fault recorded: team=%s id=%s", team, row["id"])
    return row


@app.get("/faults", response_model=list[FaultOut])
def list_faults(
    start: Optional[datetime] = Query(None, description="起始时间（含），UTC"),
    end: Optional[datetime] = Query(None, description="结束时间（不含），UTC"),
    limit: int = Query(500, ge=1, le=5000),
    team: str = Depends(current_team),
):
    """按时间范围查询本班组记录。SQL 不带班组条件，隔离由 RLS 强制。"""
    start = _aware(start, "start")
    end = _aware(end, "end")
    sql = ("SELECT id, team_id, equipment_id, occurred_at, content, created_at"
           " FROM fault_logs")
    conds: list[str] = []
    params: list = []
    if start is not None:
        conds.append("occurred_at >= %s")
        params.append(start)
    if end is not None:
        conds.append("occurred_at < %s")
        params.append(end)
    if conds:
        sql += " WHERE " + " AND ".join(conds)
    sql += " ORDER BY occurred_at ASC, id ASC LIMIT %s"
    params.append(limit)
    with team_connection(team) as conn:
        rows = conn.execute(sql, params).fetchall()
    return rows


@app.get("/whoami")
def whoami(team: str = Depends(current_team)):
    return {"team_id": team}


@app.get("/healthz")
def healthz():
    if _pool is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="database pool not ready")
    try:
        with _pool.connection(timeout=2) as conn:
            conn.execute("SELECT 1")
    except (psycopg.OperationalError, PoolTimeout):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="database unavailable")
    return {"status": "ok"}
