#!/usr/bin/env python3
"""口令轮换端到端自测：双令牌边界、在线轮换、换密期读写、幂等、中断续做、重启续用、不泄密。

默认对接 Docker Compose 部署（docker compose exec/psql/restart）。
无 docker 的环境可用 --mode local 注入钩子，例如：

  python3 tests/rotation_selftest.py --mode local \
    --psql-super-cmd "/tmp/.../psql -h /sock -p 55432 -U postgres -d faultlog -v ON_ERROR_STOP=1 -qAt" \
    --login-env-prefix "env PGPASSWORD" \
    --login-psql-cmd "/tmp/.../psql -h 127.0.0.1 -p 55432 -U api_user -d faultlog -tAc" \
    --api1-restart-cmd "bash /tmp/harness/hook.sh api1-restart"

说明：
- --psql-super-cmd：以超管身份执行任意 SQL（SQL 经 stdin），用于制造中断现场与查状态；
- --login-psql-cmd + --login-env-prefix：以 api_user 身份做口令登录实测；
- 缺少重启钩子时，“轮换中途重启”用例计 SKIP。
脚本可重复执行：fresh 轮换仅在库处于 idle 时运行；中断续做用例通过把状态拨到
rotating（同代）后经 API 续做完成，不依赖干净环境。
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

RESULTS: list[tuple[str, str, str]] = []
SECRETS: list[str] = []


def check(name: str, ok: bool, detail: str = ""):
    RESULTS.append(("PASS" if ok else "FAIL", name, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail and not ok else ""))


def skip(name: str, reason: str):
    RESULTS.append(("SKIP", name, reason))
    print(f"[SKIP] {name}  -- {reason}")


def http(method, url, token=None, body=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None), raw.decode(errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw or b"null"), raw.decode(errors="replace")
        except Exception:
            return e.code, None, raw.decode(errors="replace")
    except (urllib.error.URLError, OSError) as e:
        return None, None, str(e)


def wait_until(fn, timeout_s, interval=1.0):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def run_cmd(cmd: list[str], input_text: str | None = None, timeout=120, extra_env: dict | None = None):
    env = None
    if extra_env:
        env = dict(os.environ); env.update(extra_env)
    p = subprocess.run(cmd, input=input_text, capture_output=True, text=True,
                       timeout=timeout, env=env)
    return p.returncode, p.stdout, p.stderr


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api1", default="http://127.0.0.1:8001")
    ap.add_argument("--api2", default="http://127.0.0.1:8002")
    ap.add_argument("--ops-token", default="ops-token-dev")
    ap.add_argument("--team-token", default="token-alpha")
    ap.add_argument("--old-password", default="api_dev_password")
    ap.add_argument("--new-password", default="api_dev_password_new")
    ap.add_argument("--rotator-password", default="rotator_dev_password")
    ap.add_argument("--mode", choices=["docker", "local"], default="docker")
    ap.add_argument("--compose-file",
                    default=str(Path(__file__).resolve().parent.parent / "docker-compose.yml"))
    ap.add_argument("--psql-super-cmd", default=None)
    ap.add_argument("--login-psql-cmd", default=None,
                    help="api_user 登录用 psql 命令（口令经 PGPASSWORD 环境变量注入）")
    ap.add_argument("--login-env-prefix", default="",
                    help="local 模式下登录命令前缀（如 'env'）；docker 模式自动加 -e")
    ap.add_argument("--api1-restart-cmd", default=None)
    args = ap.parse_args()

    global SECRETS
    SECRETS = [args.old_password, args.new_password, args.rotator_password]

    api1, api2 = args.api1.rstrip("/"), args.api2.rstrip("/")
    run_id = uuid.uuid4().hex[:8]

    super_psql = args.psql_super_cmd
    login_psql = args.login_psql_cmd
    login_prefix = args.login_env_prefix
    api1_restart = args.api1_restart_cmd
    if args.mode == "docker":
        base = ["docker", "compose", "-f", args.compose_file]
        super_psql = super_psql or " ".join(base) + \
            " exec -T db psql -U postgres -d faultlog -v ON_ERROR_STOP=1 -qAt"
        # 登录实测：PGPASSWORD 经容器环境变量注入，不落在进程命令行。
        login_psql = login_psql or " ".join(base) + \
            " exec -T db psql -h 127.0.0.1 -U api_user -d faultlog -t -A"
        login_prefix = "DOCKER"  # 特殊标记：docker 模式用 -e 注入
        api1_restart = api1_restart or " ".join(base) + " restart api1"

    print(f"== rotation selftest run_id={run_id} mode={args.mode}")

    def sql_super(stmt: str):
        return run_cmd(shlex.split(super_psql), stmt)

    def login_as(password: str):
        """用给定口令以 api_user 实测登录，返回 (rc, out, stderr)。

        psql 的 -c 需要内联语句参数（不接受 stdin 补位），因此把探测语句
        作为 -c 的参数一并传入；口令只经 PGPASSWORD 环境变量注入。
        """
        cmd = shlex.split(login_psql)
        probe_sql = "SELECT current_user;"
        if login_prefix == "DOCKER":
            # 在 exec 后、容器名前插入 -e PGPASSWORD=...
            idx = cmd.index("exec") + 2
            cmd = cmd[:idx] + ["-e", f"PGPASSWORD={password}"] + cmd[idx:]
            return run_cmd(cmd + [probe_sql])
        # 本地模式：标准化组合短选项（如 -tAc → -t -A -c），并把探测语句
        # 作为 -c 的内联参数，避免与 env 前缀连写时被 argparse 误判。
        normalized: list[str] = []
        for tok in cmd:
            if tok.startswith("-") and not tok.startswith("--") and len(tok) > 2:
                normalized.extend("-" + ch for ch in tok[1:])
            else:
                normalized.append(tok)
        if "-c" in normalized:
            # -c 原本无独立参数（组合选项形式），在其后插入语句参数。
            normalized.insert(normalized.index("-c") + 1, probe_sql)
        else:
            normalized += ["-c", probe_sql]
        prefix = shlex.split(login_prefix) if login_prefix else []
        return run_cmd(prefix + normalized, None,
                       extra_env={"PGPASSWORD": password})

    # ---------- 0. 就绪 ----------
    ok = wait_until(lambda: http("GET", api1 + "/healthz")[0] == 200
                    and http("GET", api2 + "/healthz")[0] == 200, 90)
    check("两个接口实例就绪", ok)

    # ---------- 1. 双令牌边界 ----------
    st, _, _ = http("POST", api1 + "/ops/rotate-password", token=args.team_token)
    check("班组令牌不能调用轮换接口(401)", st == 401, f"status={st}")
    st, _, _ = http("GET", api1 + "/ops/rotation-status", token=args.team_token)
    check("班组令牌不能查询轮换状态(401)", st == 401, f"status={st}")
    st, _, _ = http("GET", api1 + "/faults", token=args.ops_token)
    check("运维令牌不能调用业务接口(401)", st == 401, f"status={st}")
    st, _, _ = http("POST", api1 + "/ops/rotate-password")
    check("无令牌调用轮换接口被拒(401)", st == 401, f"status={st}")

    # ---------- 2. 初始状态 ----------
    st, body, raw = http("GET", api1 + "/ops/rotation-status", token=args.ops_token)
    check("状态查询成功(200)且不含口令明文",
          st == 200 and all(s not in raw for s in SECRETS if s), f"status={st}")
    initial_phase = body.get("phase") if isinstance(body, dict) else None
    initial_gen = body.get("generation") if isinstance(body, dict) else None
    print(f"   初始轮换状态: phase={initial_phase} generation={initial_gen}")

    # ---------- 3. fresh 轮换（仅 idle 时）+ 换密期持续读写 ----------
    if initial_phase == "idle":
        stop = threading.Event()
        traffic_fail: list[str] = []
        counts = {"n": 0}

        def traffic(port: int):
            i = 0
            while not stop.is_set():
                i += 1
                st_t, _, _ = http("GET", f"http://127.0.0.1:{port}/faults",
                                  token=args.team_token, timeout=10)
                counts["n"] += 1
                if st_t != 200:
                    traffic_fail.append(f"GET :{port}->{st_t}")
                st_t, b, _ = http("POST", f"http://127.0.0.1:{port}/faults",
                                  token=args.team_token, timeout=10, body={
                                      "equipment_id": f"rot-traf-{run_id}-{port}-{i}",
                                      "occurred_at": iso(datetime.now(timezone.utc)),
                                      "content": "换密期持续读写"})
                counts["n"] += 1
                if st_t != 201:
                    traffic_fail.append(f"POST :{port}->{st_t}")
                time.sleep(0.05)

        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = [ex.submit(traffic, 8001), ex.submit(traffic, 8002)]
            time.sleep(1.5)
            st, body, raw = http("POST", api1 + "/ops/rotate-password",
                                 token=args.ops_token, timeout=120)
            stop.set()
            for f in futs:
                f.result(timeout=10)

        check("轮换接口返回完成(200)", st == 200 and isinstance(body, dict),
              f"status={st} body={body}")
        if isinstance(body, dict):
            check("两台实例均以新口令实际建连确认",
                  body.get("all_instances_confirmed") is True
                  and sorted(body.get("confirmed_instances", [])) == ["api1", "api2"],
                  str(body))
            check("回执声明旧口令已无法登录", body.get("old_password_rejected") is True)
            check("协调实例自身已切新口令", body.get("using_new_password") is True)
            check("响应不含任何口令明文", all(s not in raw for s in SECRETS if s))
        check(f"换密期间持续读写零失败（共{counts['n']}次）", not traffic_fail,
              "; ".join(traffic_fail[:5]))

        # 旧/新口令实测
        rc_old, _, err_old = login_as(args.old_password)
        check("旧口令实测无法登录", rc_old != 0 and "password authentication failed" in err_old,
              f"rc={rc_old} err={err_old.strip()[:120]}")
        rc_new, out, _ = login_as(args.new_password)
        check("新口令实测可登录", rc_new == 0 and "api_user" in out, f"rc={rc_new} out={out!r}")

        # 幂等：再次调用应回显同一代
        st, body2, _ = http("POST", api2 + "/ops/rotate-password", token=args.ops_token)
        check("重复轮换调用幂等回显同一代",
              st == 200 and body2.get("phase") == "completed"
              and body2.get("generation") == body.get("generation"), str(body2))
    else:
        skip("fresh 在线轮换（库已非 idle，初始状态=%s）" % initial_phase,
             "请在全新栈（docker compose down -v 后）上运行以覆盖该用例")

    # ---------- 4. 中断续做：拨到 rotating 同代现场后经 API 续做 ----------
    st, body, _ = http("GET", api1 + "/ops/rotation-status", token=args.ops_token)
    gen_before = body["generation"]
    # 模拟“改密已落地、回执丢失、状态停在 rotating、确认表清空”的崩溃现场。
    rc, _, err = sql_super(
        "UPDATE password_rotation_state SET phase='rotating', last_error=NULL, "
        f"updated_at=now() WHERE id=1;\n"
        f"DELETE FROM password_rotation_members WHERE generation={gen_before};\n")
    check("制造中断现场(rotating/清空确认)成功", rc == 0, f"rc={rc} err={err.strip()[:120]}")

    # 可选：轮换中途重启一台实例（无钩子则跳过）
    if api1_restart:
        rc, _, err = run_cmd(shlex.split(api1_restart))
        check("轮换中途重启 api1 命令成功", rc == 0, f"rc={rc} err={err.strip()[:120]}")
        ok_ready = wait_until(lambda: http("GET", api1 + "/healthz")[0] == 200, 90)
        # 重启后实例可能先用旧口令串惰性建池，观察线程会在一个节拍内切到新口令。
        # 这里等待状态收敛到新口令，而不是要求重启瞬间即完成切换。
        def _on_new():
            st_c, body_c, _ = http("GET", api1 + "/ops/rotation-status", token=args.ops_token)
            return st_c == 200 and isinstance(body_c, dict) \
                and body_c.get("using_new_password") is True
        ok_converged = wait_until(_on_new, 15, interval=0.5)
        check("api1 重启后恢复就绪且观察线程收敛到新口令（不切回旧口令）",
              ok_ready and ok_converged,
              f"ready={ok_ready} converged={ok_converged}")
    else:
        skip("轮换中途重启", "未提供 --api1-restart-cmd")

    st, body, raw = http("POST", api2 + "/ops/rotate-password",
                         token=args.ops_token, timeout=120)
    check("中断后重试轮换成功(200)", st == 200 and isinstance(body, dict),
          f"status={st} body={body}")
    if isinstance(body, dict):
        check("续做未新开一代（generation 不变）", body.get("generation") == gen_before,
              f"before={gen_before} after={body.get('generation')}")
        check("续做后两台实例重新确认", body.get("all_instances_confirmed") is True)
        check("续做后旧口令仍被拒且响应无口令",
              body.get("old_password_rejected") is True
              and all(s not in raw for s in SECRETS if s))

    rc_old, _, err_old = login_as(args.old_password)
    check("最终态：旧口令依旧无法登录",
          rc_old != 0 and "password authentication failed" in err_old,
          f"rc={rc_old} err={err_old.strip()[:120]}")

    # ---------- 5. 全程接口响应不泄密扫描 ----------
    leak = False
    for url, tok in ((api1 + "/healthz", None), (api1 + "/whoami", args.team_token),
                     (api1 + "/faults", args.team_token),
                     (api2 + "/ops/rotation-status", args.ops_token)):
        _, _, raw = http("GET", url, token=tok)
        if any(s and s in raw for s in SECRETS):
            leak = True
            print("   LEAK:", url)
    check("所有接口响应均不含口令明文", not leak)

    # ---------- 汇总 ----------
    n_pass = sum(1 for s, _, _ in RESULTS if s == "PASS")
    n_fail = sum(1 for s, _, _ in RESULTS if s == "FAIL")
    n_skip = sum(1 for s, _, _ in RESULTS if s == "SKIP")
    print(f"\n== 结果: {n_pass} PASS, {n_fail} FAIL, {n_skip} SKIP")
    if n_fail:
        for s, name, detail in RESULTS:
            if s == "FAIL":
                print(f"  - {name}: {detail}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
