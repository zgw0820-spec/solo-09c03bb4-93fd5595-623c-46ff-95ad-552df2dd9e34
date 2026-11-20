"""设备故障日志 API（含 api_user 数据库口令在线轮换）。

两个班组共用一套服务与一张表。隔离由数据库行级安全（RLS）兜底：
本进程以非表主角色 api_user 连接，每个请求在独立事务内用
set_config('app.team_id', ..., true)（事务本地）绑定班组身份，
事务结束身份即失效，连接归还连接池时不携带任何班组状态。

口令轮换设计（见 README「口令轮换」一节）：
- 业务请求用「班组令牌」，轮换接口用独立的「运维令牌」，两套身份互不等价。
- 库内 password_rotation_state/members 表是多实例协同与断点续做的事实来源；
  实例后台线程轮询该表，检测到轮换即把连接池切换到新口令，
  旧池等连接全部归还后再关闭——已借出连接上的原事务不受影响。
- 任何响应、日志都不包含口令明文；改密经属主 SECURITY DEFINER 函数完成，
  轮换角色本身无 CREATEROLE 权限。
"""
from __future__ import annotations

import logging
import os
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool, PoolTimeout
from pydantic import BaseModel, ConfigDict, Field, field_validator

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("faultlog")

# ---------------------------------------------------------------------
# 配置（口令全部来自环境，由 Docker Compose 预置，代码与响应中不出现明文）
# ---------------------------------------------------------------------
DATABASE_URL = os.environ["DATABASE_URL"]            # 旧/当前口令连接串
DATABASE_URL_NEW = os.environ["DATABASE_URL_NEW"]    # 新口令连接串
ROTATOR_DATABASE_URL = os.environ["ROTATOR_DATABASE_URL"]  # 轮换角色连接串
OPS_TOKEN = os.environ.get("OPS_TOKEN", "")
INSTANCE_ID = os.environ.get("INSTANCE_ID", "api")
EXPECTED_INSTANCES = [
    x.strip() for x in os.environ.get("EXPECTED_INSTANCES", INSTANCE_ID).split(",") if x.strip()
]
WATCH_INTERVAL = float(os.environ.get("ROTATION_WATCH_INTERVAL", "1"))
ROTATION_WAIT_TIMEOUT = float(os.environ.get("ROTATION_WAIT_TIMEOUT", "90"))
DB_ACQUIRE_TIMEOUT = float(os.environ.get("DB_ACQUIRE_TIMEOUT", "5"))
POOL_MAX = int(os.environ.get("DB_POOL_MAX", "10"))

NEW_PASSWORD = urlsplit(DATABASE_URL_NEW).password or ""
OLD_PASSWORD = urlsplit(DATABASE_URL).password or ""


def redact_url(url: str) -> str:
    """日志用：把连接串中的口令替换为 ***。"""
    parts = urlsplit(url)
    if parts.password is None:
        return url
    masked = parts.netloc.replace(":" + parts.password + "@", ":***@", 1)
    return urlunsplit(parts._replace(netloc=masked))


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
    log.warning("TEAM_TOKENS 为空：所有业务请求都将以 401 拒绝")
if not OPS_TOKEN:
    log.warning("OPS_TOKEN 为空：口令轮换接口将拒绝一切调用")


# ---------------------------------------------------------------------
# 口令失效识别
# ---------------------------------------------------------------------
def is_invalid_password_error(exc: BaseException) -> bool:
    """识别“口令认证失败”（SQLSTATE 28P01）。网络错误等不算，避免误切。"""
    if not isinstance(exc, psycopg.OperationalError):
        return False
    if getattr(exc, "sqlstate", None) == "28P01":
        return True
    return "password authentication failed" in str(exc).lower()


# ---------------------------------------------------------------------
# 连接池管理：在线切换口令，不打断在途事务
# ---------------------------------------------------------------------
class PoolManager:
    """持有当前有效口令的连接池，支持轮换期无感切换。

    切换方式：先用新口令独立探活，成功后开新池，再等旧池连接全部归还后关闭。
    已借出的旧连接不被主动 kill，其上原事务可正常提交/回滚。
    """

    def __init__(self, old_url: str, new_url: str, max_size: int):
        self._old_url = old_url
        self._new_url = new_url
        self._max_size = max_size
        self._lock = threading.RLock()
        self._pool: Optional[ConnectionPool] = None
        self._using_new = False

    def _make_pool(self, url: str) -> ConnectionPool:
        return ConnectionPool(
            conninfo=url,
            min_size=1,
            max_size=self._max_size,
            kwargs={"row_factory": dict_row},
            open=False,
        )

    @staticmethod
    def probe(url: str, timeout: float = 3.0) -> bool:
        """用独立短连接验证某条连接串能否登录（不改池状态）。"""
        try:
            with psycopg.connect(url, connect_timeout=timeout) as conn:
                conn.execute("SELECT 1")
            return True
        except psycopg.Error:
            return False

    def start(self) -> None:
        with self._lock:
            # 优先按预置的当前（旧）口令建池；失败则实测两个口令后选有效者，
            # 覆盖“实例在轮换后重启”的场景，绝不盲目假定旧口令仍有效。
            if self.probe(self._old_url):
                self._open_pool(self._old_url, using_new=False)
                return
            if self.probe(self._new_url):
                self._open_pool(self._new_url, using_new=True)
                return
            log.warning("启动时两个口令均无法建连：开惰性池，数据库恢复后自动重连")
            self._pool = self._make_pool(self._old_url)
            self._pool.open(wait=False)

    def _open_pool(self, url: str, using_new: bool) -> None:
        self._pool = self._make_pool(url)
        self._pool.open(wait=True)
        self._using_new = using_new
        log.info("连接池已建立（%s口令）", "新" if using_new else "旧")

    @staticmethod
    def _safe_close(pool: ConnectionPool) -> None:
        try:
            pool.close(timeout=60.0)
        except Exception:
            log.warning("旧连接池后台关闭仍未排空，将继续等待")
            try:
                pool.close(timeout=300.0)
            except Exception:
                log.exception("旧连接池关闭失败")

    def ensure_new_password(self) -> None:
        """确保池已切到新口令。幂等：已切换则立即返回。"""
        with self._lock:
            if self._using_new:
                return
            # 先独立探活：新口令未生效（如 ALTER 尚未执行）时不动现有池。
            if not self.probe(self._new_url):
                raise RuntimeError("新口令探活失败，暂不切换连接池")
            old_pool = self._pool
            new_pool = self._make_pool(self._new_url)
            new_pool.open(wait=True)
            self._pool = new_pool
            self._using_new = True
            # 旧池延迟关闭：等在途连接归还，不主动终止会话与事务。
            old_pool and threading.Thread(
                target=self._safe_close, args=(old_pool,), daemon=True
            ).start()
            log.info("连接池已切换到新口令；旧池等待在途事务结束后关闭")

    def switch_if_new_password_works(self) -> bool:
        """非抛出式自愈：新口令可建连时切池并返回 True，否则返回 False。
        供业务请求与健康检查在取连接失败时调用，不依赖底层异常文本——
        错误口令下连接池通常抛 PoolTimeout，28P01 只存在于池内部日志。"""
        if self.using_new:
            return True
        if not self.probe(self._new_url):
            return False
        self.ensure_new_password()
        return True

    def pool(self) -> Optional[ConnectionPool]:
        with self._lock:
            return self._pool

    @property
    def using_new(self) -> bool:
        with self._lock:
            return self._using_new

    def stop(self) -> None:
        with self._lock:
            if self._pool is not None:
                self._pool.close()
                self._pool = None


# ---------------------------------------------------------------------
# 轮换状态存储：独立短连接，不经过业务连接池
# ---------------------------------------------------------------------
class RotationStore:
    """对库内轮换状态表的全部访问。连接按需建立，优先新口令、回退旧口令，
    因此轮换前后、实例重启后都能读到协调状态。"""

    def __init__(self, old_url: str, new_url: str, rotator_url: str):
        self._old_url = old_url
        self._new_url = new_url
        self._rotator_url = rotator_url

    def _connect(self) -> psycopg.Connection:
        """api_user 连接：读协调状态、登记本实例确认（仅需 SELECT/INSERT 权限）。
        优先新口令、回退旧口令，因此轮换前后、实例重启后都能读到状态。"""
        last_exc: Optional[Exception] = None
        for url in (self._new_url, self._old_url):
            try:
                return psycopg.connect(url, connect_timeout=3,
                                       row_factory=dict_row, autocommit=True)
            except psycopg.OperationalError as exc:
                last_exc = exc
                continue
        raise psycopg.OperationalError("两个口令均无法连接状态库") from last_exc

    def _connect_rotator(self) -> psycopg.Connection:
        """api_rotator 连接：协调状态的变更（begin/complete/failed）。
        轮换角色口令不随本次轮换变化，连接串固定。"""
        return psycopg.connect(self._rotator_url, connect_timeout=5,
                               row_factory=dict_row, autocommit=True)

    def get_state(self) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT s.phase, s.generation, s.initiator, s.old_password_invalid,
                       s.last_error, s.updated_at,
                       COALESCE((
                           SELECT array_agg(instance_id ORDER BY instance_id)
                           FROM password_rotation_members m
                           WHERE m.generation = s.generation), '{}') AS members
                FROM password_rotation_state s
                WHERE s.id = 1
                """
            ).fetchone()
        return dict(row)

    def begin_rotation(self, generation: int, initiator: str) -> None:
        with self._connect_rotator() as conn:
            conn.execute(
                """
                UPDATE password_rotation_state
                   SET phase = 'rotating', generation = %s, initiator = %s,
                       old_password_invalid = false, last_error = NULL,
                       updated_at = now()
                 WHERE id = 1
                """,
                (generation, initiator),
            )

    def apply_new_password(self, new_password: str) -> None:
        """经轮换角色调用属主改密函数。重复执行同值 ALTER ROLE 是幂等的。"""
        with psycopg.connect(self._rotator_url, connect_timeout=5,
                             autocommit=True) as conn:
            conn.execute("SELECT rotate_api_password(%s)", (new_password,))
        log.info("ALTER ROLE 改密已执行（口令不落日志）")

    def confirm(self, generation: int, instance_id: str, detail: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO password_rotation_members (generation, instance_id, detail)
                VALUES (%s, %s, %s)
                ON CONFLICT (generation, instance_id) DO NOTHING
                """,
                (generation, instance_id, detail),
            )

    def mark_completed(self, generation: int) -> None:
        with self._connect_rotator() as conn:
            conn.execute(
                """
                UPDATE password_rotation_state
                   SET phase = 'completed', old_password_invalid = true,
                       last_error = NULL, updated_at = now()
                 WHERE id = 1 AND generation = %s
                """,
                (generation,),
            )

    def mark_failed(self, reason: str) -> None:
        with self._connect_rotator() as conn:
            conn.execute(
                """
                UPDATE password_rotation_state
                   SET phase = 'failed', last_error = %s, updated_at = now()
                 WHERE id = 1
                """,
                (reason,),
            )

    def verify_old_password_rejected(self) -> tuple[bool, str]:
        """旧口令必须实测无法登录。网络不通等“不确定”结果一律按未通过处理。"""
        try:
            conn = psycopg.connect(self._old_url, connect_timeout=3, autocommit=True)
        except psycopg.OperationalError as exc:
            if is_invalid_password_error(exc):
                return True, ""
            return False, f"旧口令核验结果不确定: {exc.__class__.__name__}"
        conn.close()
        return False, "旧口令仍可登录"


# ---------------------------------------------------------------------
# 轮换协调服务
# ---------------------------------------------------------------------
class RotationService:
    """实现并串行化本实例发起/续做轮换的完整流程。全部步骤幂等，
    任何一步中断后重新调用都会先核实库内状态再继续，不会切回旧口令。"""

    def __init__(self, manager: PoolManager, store: RotationStore):
        self._manager = manager
        self._store = store
        self._lock = threading.RLock()

    def status(self) -> dict[str, Any]:
        st = self._store.get_state()
        return self._render(st)

    def _render(self, st: dict[str, Any]) -> dict[str, Any]:
        confirmed = list(st["members"])
        return {
            "phase": st["phase"],
            "generation": st["generation"],
            "initiator": st["initiator"],
            "instance_id": INSTANCE_ID,
            "using_new_password": self._manager.using_new,
            "expected_instances": EXPECTED_INSTANCES,
            "confirmed_instances": confirmed,
            "all_instances_confirmed": all(i in confirmed for i in EXPECTED_INSTANCES),
            "old_password_rejected": st["old_password_invalid"],
            "last_error": st["last_error"],
            "updated_at": st["updated_at"],
        }

    def rotate(self) -> dict[str, Any]:
        with self._lock:
            st = self._store.get_state()

            # 已完成：幂等回显，绝不重复改密、绝不回退口令。
            if st["phase"] == "completed":
                log.info("轮换已完成（generation=%s），幂等回显状态", st["generation"])
                return self._render(st)

            # idle → 开新一代；rotating/failed → 续做同一代（回执丢失/中途重启场景）。
            if st["phase"] == "idle":
                generation = st["generation"] + 1
                self._store.begin_rotation(generation, INSTANCE_ID)
                log.info("发起口令轮换 generation=%s 发起实例=%s", generation, INSTANCE_ID)
            else:
                generation = st["generation"]
                log.info("检测到未完成轮换 generation=%s phase=%s，核实状态后续做",
                         generation, st["phase"])

            # 1) 改密。同值重复执行无副作用，续做时直接再执行一次即可。
            self._store.apply_new_password(NEW_PASSWORD)

            # 2) 本实例连接池切新口令（内部先探活，幂等）。
            self._manager.ensure_new_password()

            # 3) 登记本实例“已用新口令实际建连”的证据（ON CONFLICT 幂等）。
            self._store.confirm(generation, INSTANCE_ID, "coordinator")

            # 4) 等待所有预期实例确认。每台实例的确认都来自它自己的新口令连接。
            deadline = time.monotonic() + ROTATION_WAIT_TIMEOUT
            while True:
                st = self._store.get_state()
                confirmed = set(st["members"])
                if all(i in confirmed for i in EXPECTED_INSTANCES):
                    break
                if time.monotonic() > deadline:
                    msg = f"等待实例确认超时，已确认: {sorted(confirmed)}"
                    self._store.mark_failed(msg)
                    raise HTTPException(
                        status.HTTP_504_GATEWAY_TIMEOUT,
                        detail="rotation timeout: waiting for instance confirmations",
                    )
                time.sleep(0.5)

            # 5) 旧口令实测必须无法登录（未核验过才核验；不确定不放行）。
            if not st["old_password_invalid"]:
                ok, reason = self._store.verify_old_password_rejected()
                if not ok:
                    # 幂等补偿：再改一次后复测。
                    self._store.apply_new_password(NEW_PASSWORD)
                    ok, reason = self._store.verify_old_password_rejected()
                if not ok:
                    self._store.mark_failed(reason)
                    raise HTTPException(
                        status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="rotation verification failed: old password check did not pass",
                    )

            # 6) 标记完成并回显（响应中不含任何口令）。
            self._store.mark_completed(generation)
            log.info("口令轮换完成 generation=%s，全部实例已确认且旧口令失效", generation)
            return self._render(self._store.get_state())


# ---------------------------------------------------------------------
# 后台观察线程：被动跟随轮换状态，保证不经过协调实例也能切池
# ---------------------------------------------------------------------
def watch_loop(stop_event: threading.Event, manager: PoolManager,
               store: RotationStore) -> None:
    while not stop_event.wait(WATCH_INTERVAL):
        try:
            st = store.get_state()
            if st["phase"] not in ("rotating", "completed", "failed"):
                continue
            if not manager.using_new:
                # 先探活再切换；ALTER 未落地时探活失败，下一拍重试。
                manager.ensure_new_password()
            if manager.using_new:
                store.confirm(st["generation"], INSTANCE_ID, "watcher")
        except Exception:
            # 观察线程任何异常都不能杀死线程，下一拍继续。
            log.debug("轮换观察节拍异常（将在下个节拍重试）", exc_info=True)


# ---------------------------------------------------------------------
# FastAPI 装配
# ---------------------------------------------------------------------
manager = PoolManager(DATABASE_URL, DATABASE_URL_NEW, POOL_MAX)
store = RotationStore(DATABASE_URL, DATABASE_URL_NEW, ROTATOR_DATABASE_URL)
service = RotationService(manager, store)


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("实例 %s 启动；预期协同实例: %s；旧连接串=%s",
             INSTANCE_ID, ",".join(EXPECTED_INSTANCES), redact_url(DATABASE_URL))
    manager.start()
    stop_event = threading.Event()
    watcher = threading.Thread(
        target=watch_loop, args=(stop_event, manager, store),
        name="rotation-watcher", daemon=True,
    )
    watcher.start()
    try:
        yield
    finally:
        stop_event.set()
        manager.stop()


app = FastAPI(title="设备故障日志 API", version="2.0.0",
              lifespan=lifespan,
              description="两班组故障日志读写（RLS 行级隔离）+ api_user 口令在线轮换。")
team_bearer = HTTPBearer(auto_error=False, scheme_name="班组令牌",
                         description="值班员预置令牌（TEAM_TOKENS），用于业务读写")
ops_bearer = HTTPBearer(auto_error=False, scheme_name="运维令牌",
                        description="独立运维令牌（OPS_TOKEN），仅用于口令轮换接口")


def current_team(creds: Optional[HTTPAuthorizationCredentials] = Depends(team_bearer)) -> str:
    """令牌 -> 班组。班组身份只来源于服务端令牌映射，不采信请求体/参数。"""
    if creds is None or not creds.credentials:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="not authenticated")
    team = TEAM_TOKENS.get(creds.credentials)
    if team is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="invalid token")
    return team


def require_ops(creds: Optional[HTTPAuthorizationCredentials] = Depends(ops_bearer)) -> None:
    """运维令牌校验。班组令牌与运维令牌互不等价，不能互相调用对方接口。"""
    if creds is None or not creds.credentials or creds.credentials != OPS_TOKEN:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="invalid ops token")


@contextmanager
def _team_conn_once(team: str):
    pool = manager.pool()
    if pool is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="database pool not ready")
    with pool.connection(timeout=DB_ACQUIRE_TIMEOUT) as conn:
        with conn.transaction():
            conn.execute("SELECT set_config('app.team_id', %s, true)", (team,))
            yield conn


@contextmanager
def team_connection(team: str):
    """取一条连接，在一个事务内绑定班组身份后交给业务使用。

    set_config(..., true) 是事务本地设置：提交/回滚后自动失效，
    因此连接复用、请求报错、并发交错都不会把班组身份带给下一个请求。
    若取连接失败且池仍在用旧口令（轮换刚落地、观察线程尚未切池的窗口），
    不依赖底层异常文本——只要新口令实测可建连就切池并重试一次，
    保证补建连接时的读写不因换密失败。
    """
    try:
        with _team_conn_once(team) as conn:
            yield conn
    except HTTPException:
        raise
    except (psycopg.OperationalError, PoolTimeout):
        # PoolTimeout 本身也是 psycopg.OperationalError 的子类。
        if not manager.using_new and manager.switch_if_new_password_works():
            log.info("业务请求取连接失败且旧口令池失效，已切新口令并重试一次")
            with _team_conn_once(team) as conn:
                yield conn
            return
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="database unavailable")
    except psycopg.Error:
        log.exception("unexpected database error")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="internal database error")


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


class RotationStatusOut(BaseModel):
    """轮换状态回执。刻意不含任何口令/连接串字段。"""
    phase: str
    generation: int
    initiator: Optional[str] = None
    instance_id: str
    using_new_password: bool
    expected_instances: list[str]
    confirmed_instances: list[str]
    all_instances_confirmed: bool
    old_password_rejected: bool
    last_error: Optional[str] = None
    updated_at: datetime


def _aware(v: Optional[datetime], name: str) -> Optional[datetime]:
    if v is None:
        return None
    if v.tzinfo is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=f"{name} 必须带时区偏移（UTC）")
    return v.astimezone(timezone.utc)


# ---------------------------------------------------------------------
# 业务接口（班组令牌）
# ---------------------------------------------------------------------
@app.post("/faults", response_model=FaultOut, status_code=status.HTTP_201_CREATED,
          tags=["业务-故障日志"])
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


@app.get("/faults", response_model=list[FaultOut], tags=["业务-故障日志"])
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


@app.get("/whoami", tags=["业务-故障日志"])
def whoami(team: str = Depends(current_team)):
    return {"team_id": team}


@app.get("/healthz", tags=["运维"])
def healthz():
    pool = manager.pool()
    if pool is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="database pool not ready")
    try:
        with pool.connection(timeout=2) as conn:
            conn.execute("SELECT 1")
    except (psycopg.OperationalError, PoolTimeout):
        # 与业务请求同样的自愈：旧口令池失效时切到已生效的新口令再验一次。
        if not manager.using_new and manager.switch_if_new_password_works():
            log.info("健康检查触发连接池切新口令")
            with manager.pool().connection(timeout=2) as conn:
                conn.execute("SELECT 1")
            return {"status": "ok"}
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="database unavailable")
    return {"status": "ok"}


# ---------------------------------------------------------------------
# 口令轮换接口（独立运维令牌）
# ---------------------------------------------------------------------
@app.post("/ops/rotate-password", response_model=RotationStatusOut,
          tags=["运维-口令轮换"])
def rotate_password(_: None = Depends(require_ops)):
    """发起或续做一次 api_user 口令轮换（Swagger 中用「运维令牌」Authorize）。

    流程幂等：改密 → 本实例切池 → 全部预期实例以新口令实际建连确认 →
    实测旧口令无法登录 → 标记完成。任一步中断后重调本接口都会先核实
    库内状态再继续，不会切回旧口令，响应中不返回任何口令。
    """
    return service.rotate()


@app.get("/ops/rotation-status", response_model=RotationStatusOut,
         tags=["运维-口令轮换"])
def rotation_status(_: None = Depends(require_ops)):
    """查询当前轮换状态（不含口令）。"""
    return service.status()
