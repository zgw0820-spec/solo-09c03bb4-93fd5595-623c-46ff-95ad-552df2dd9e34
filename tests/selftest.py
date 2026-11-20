#!/usr/bin/env python3
"""端到端自测：令牌隔离、伪造班组、并发交错、RLS 兜底、停库恢复、实例重启。

默认假设 Docker Compose 部署（docker compose ... 控制数据库与实例）。
无 docker 的环境可用 --mode local 并通过钩子命令注入控制方式，例如：

  python3 tests/selftest.py --mode local \
    --psql-cmd "/path/psql -h 127.0.0.1 -U postgres -d faultlog -v ON_ERROR_STOP=1 -qAt" \
    --db-stop-cmd "/path/pg_ctl -D /tmp/pgdata stop -m fast -w" \
    --db-start-cmd "/path/pg_ctl -D /tmp/pgdata start -w -l /tmp/pgdata.log" \
    --api1-restart-cmd "bash /tmp/local_harness/restart_api1.sh"

缺少钩子的测试组会计为 SKIP 而不是 PASS。
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

RESULTS: list[tuple[str, str, str]] = []  # (status, name, detail)


def check(name: str, ok: bool, detail: str = ""):
    RESULTS.append(("PASS" if ok else "FAIL", name, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail and not ok else ""))


def skip(name: str, reason: str):
    RESULTS.append(("SKIP", name, reason))
    print(f"[SKIP] {name}  -- {reason}")


def http(method, url, token=None, body=None, query=None, timeout=15):
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except Exception:
            return e.code, None
    except (urllib.error.URLError, OSError) as e:
        return None, str(e)


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


def run_cmd(cmd: list[str], input_text: str | None = None, timeout=120):
    p = subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api1", default="http://127.0.0.1:8001")
    ap.add_argument("--api2", default="http://127.0.0.1:8002")
    ap.add_argument("--token-a", default="token-alpha")
    ap.add_argument("--token-b", default="token-bravo")
    ap.add_argument("--mode", choices=["docker", "local"], default="docker")
    ap.add_argument("--compose-file",
                    default=str(Path(__file__).resolve().parent.parent / "docker-compose.yml"))
    ap.add_argument("--psql-cmd", default=None, help="执行 SQL 的命令（SQL 经 stdin 传入）")
    ap.add_argument("--db-stop-cmd", default=None)
    ap.add_argument("--db-start-cmd", default=None)
    ap.add_argument("--api1-restart-cmd", default=None)
    args = ap.parse_args()

    api1, api2 = args.api1.rstrip("/"), args.api2.rstrip("/")
    tok_a, tok_b = args.token_a, args.token_b
    run_id = uuid.uuid4().hex[:8]
    now = datetime.now(timezone.utc)

    psql_cmd = args.psql_cmd
    db_stop_cmd, db_start_cmd = args.db_stop_cmd, args.db_start_cmd
    api1_restart_cmd = args.api1_restart_cmd
    if args.mode == "docker":
        base = ["docker", "compose", "-f", args.compose_file]
        psql_cmd = psql_cmd or " ".join(base) + \
            " exec -T db psql -U postgres -d faultlog -v ON_ERROR_STOP=1 -qAt"
        db_stop_cmd = db_stop_cmd or " ".join(base) + " stop db"
        db_start_cmd = db_start_cmd or " ".join(base) + " start db"
        api1_restart_cmd = api1_restart_cmd or " ".join(base) + " restart api1"

    print(f"== selftest run_id={run_id} api1={api1} api2={api2} mode={args.mode}")

    # ---------- 0. 就绪 ----------
    ok = wait_until(lambda: http("GET", api1 + "/healthz")[0] == 200
                    and http("GET", api2 + "/healthz")[0] == 200, 90)
    check("两个接口实例就绪", ok)

    # ---------- 1. 认证 ----------
    st, _ = http("GET", api1 + "/faults")
    check("无令牌被拒绝(401)", st == 401, f"status={st}")
    st, _ = http("GET", api1 + "/faults", token="wrong-token")
    check("错误令牌被拒绝(401)", st == 401, f"status={st}")

    # ---------- 2. 写入（含伪造班组字段） ----------
    a1_time = now - timedelta(hours=1)
    st, body = http("POST", api1 + "/faults", token=tok_a, body={
        "equipment_id": f"eq-a-{run_id}",
        "occurred_at": iso(a1_time),
        "content": "班组A记录的故障",
        "team_id": "team_b",  # 伪造字段，必须被忽略
    })
    a1_id = body.get("id") if isinstance(body, dict) else None
    check("A经api1写入成功(201)", st == 201, f"status={st} body={body}")
    check("伪造请求体team_id无效(仍为team_a)",
          isinstance(body, dict) and body.get("team_id") == "team_a", f"body={body}")

    st, body_b = http("POST", api2 + "/faults", token=tok_b, body={
        "equipment_id": f"eq-b-{run_id}",
        "occurred_at": iso(now - timedelta(minutes=30)),
        "content": "班组B记录的故障",
    })
    b1_id = body_b.get("id") if isinstance(body_b, dict) else None
    check("B经api2写入成功(201)", st == 201 and body_b.get("team_id") == "team_b",
          f"status={st} body={body_b}")

    # 无时区时间必须被拒绝
    st, _ = http("POST", api1 + "/faults", token=tok_a, body={
        "equipment_id": "eq-x", "occurred_at": "2026-11-19T08:00:00", "content": "x"})
    check("无时区时间被拒绝(422)", st == 422, f"status={st}")

    # ---------- 3. 跨实例读取隔离 ----------
    st, rows = http("GET", api2 + "/faults", token=tok_a)
    ok = st == 200 and all(r["team_id"] == "team_a" for r in rows) \
        and any(r["id"] == a1_id for r in rows)
    check("A令牌经api2只见本班组记录(含刚写入的)", ok, f"status={st} rows={rows}")

    st, rows = http("GET", api1 + "/faults", token=tok_b)
    ok = st == 200 and all(r["team_id"] == "team_b" for r in rows) \
        and any(r["id"] == b1_id for r in rows)
    check("B令牌经api1只见本班组记录(含刚写入的)", ok, f"status={st} rows={rows}")

    # ---------- 4. 时间范围过滤 ----------
    st, rows = http("GET", api1 + "/faults", token=tok_a,
                    query={"start": iso(now - timedelta(minutes=45))})
    ok = st == 200 and all(r["equipment_id"] != f"eq-a-{run_id}" for r in rows)
    check("时间过滤生效(范围外记录不出现)", ok, f"status={st}")

    st, rows = http("GET", api1 + "/faults", token=tok_a,
                    query={"start": iso(now - timedelta(hours=2)),
                           "end": iso(now)})
    ok = st == 200 and any(r["id"] == a1_id for r in rows) \
        and all(r["team_id"] == "team_a" for r in rows)
    check("时间范围内本班组记录可见", ok, f"status={st}")

    # ---------- 5. 伪造查询参数不能扩大权限 ----------
    st, rows = http("GET", api1 + "/faults", token=tok_a, query={"team_id": "team_b"})
    ok = st == 200 and all(r["team_id"] == "team_a" for r in rows)
    check("伪造查询参数team_id无效", ok, f"status={st}")

    # ---------- 6. 并发交错 ----------
    def job(i):
        token = tok_a if i % 2 == 0 else tok_b
        team = "team_a" if i % 2 == 0 else "team_b"
        base = api1 if (i // 2) % 2 == 0 else api2
        if i % 4 < 2:
            st, rows = http("GET", base + "/faults", token=token)
            if st != 200:
                return f"GET status={st}"
            if not all(r["team_id"] == team for r in rows):
                return f"cross-team row visible for {team}"
            return None
        st, body = http("POST", base + "/faults", token=token, body={
            "equipment_id": f"eq-conc-{run_id}-{i}",
            "occurred_at": iso(now - timedelta(minutes=5)),
            "content": "并发探针"})
        if st != 201:
            return f"POST status={st}"
        if not isinstance(body, dict) or body.get("team_id") != team:
            return f"POST wrong team: {body}"
        return None

    with ThreadPoolExecutor(max_workers=16) as ex:
        errs = [e for e in ex.map(job, range(40)) if e]
    check("并发交错40请求身份不串用", not errs, "; ".join(errs[:3]))

    # ---------- 7. RLS 直查数据库 ----------
    if not psql_cmd:
        skip("RLS直查(未设GUC→0行)", "未提供 --psql-cmd")
        skip("RLS直查(越组过滤/越组写入拒绝)", "未提供 --psql-cmd")
    else:
        cmd = shlex.split(psql_cmd)
        rc, out, err = run_cmd(cmd, "SET ROLE api_user;\nSELECT count(*) FROM fault_logs;\n")
        nums = [ln for ln in out.splitlines() if ln.strip().isdigit()]
        check("RLS: api_user未设班组GUC查询→0行",
              rc == 0 and nums and nums[-1] == "0", f"rc={rc} out={out!r} err={err!r}")

        rc, out, err = run_cmd(cmd, (
            "SET ROLE api_user;\n"
            "SET app.team_id = 'team_a';\n"
            "SELECT count(*) FROM fault_logs;\n"
            "SELECT count(*) FROM fault_logs WHERE team_id <> 'team_a';\n"))
        nums = [ln for ln in out.splitlines() if ln.strip().isdigit()]
        ok = rc == 0 and len(nums) >= 2 and int(nums[-2]) >= 1 and nums[-1] == "0"
        check("RLS: 设team_a后只见team_a(越组条件仍0行)", ok, f"rc={rc} out={out!r} err={err!r}")

        rc, out, err = run_cmd(cmd, (
            "SET ROLE api_user;\n"
            "SET app.team_id = 'team_a';\n"
            "INSERT INTO fault_logs (team_id, equipment_id, occurred_at, content) "
            "VALUES ('team_b', 'rls-probe', now(), 'rls probe');\n"))
        check("RLS: 越组写入被拒绝(WITH CHECK)",
              rc != 0 and "row-level security" in err, f"rc={rc} err={err!r}")

    # ---------- 8. 数据库停用/恢复 ----------
    if not db_stop_cmd or not db_start_cmd:
        skip("数据库停用→503", "未提供 --db-stop-cmd/--db-start-cmd")
        skip("数据库恢复→按正确身份服务", "未提供 --db-stop-cmd/--db-start-cmd")
    else:
        rc, _, err = run_cmd(shlex.split(db_stop_cmd))
        check("数据库停用命令执行成功", rc == 0, f"rc={rc} err={err!r}")
        ok = wait_until(lambda: http("GET", api1 + "/faults", token=tok_a)[0] == 503, 40)
        st2, _ = http("GET", api2 + "/faults", token=tok_b)
        st3, _ = http("POST", api1 + "/faults", token=tok_a, body={
            "equipment_id": "eq-down", "occurred_at": iso(now), "content": "x"})
        check("数据库停用后两实例明确拒绝(503)", ok and st2 == 503 and st3 == 503,
              f"api1_get_503={ok} api2_get={st2} api1_post={st3}")

        rc, _, err = run_cmd(shlex.split(db_start_cmd))
        check("数据库恢复命令执行成功", rc == 0, f"rc={rc} err={err!r}")
        ok = wait_until(lambda: http("GET", api1 + "/healthz")[0] == 200
                        and http("GET", api2 + "/healthz")[0] == 200, 90)
        check("数据库恢复后两实例恢复服务", ok)

        st, rows = http("GET", api2 + "/faults", token=tok_a)
        ok1 = st == 200 and all(r["team_id"] == "team_a" for r in rows)
        st, body = http("POST", api1 + "/faults", token=tok_b, body={
            "equipment_id": f"eq-b2-{run_id}", "occurred_at": iso(now), "content": "恢复后写入"})
        ok2 = st == 201 and isinstance(body, dict) and body.get("team_id") == "team_b"
        check("恢复后按正确身份服务(读隔离/写归属正确)", ok1 and ok2,
              f"read_ok={ok1} write={st} {body}")

    # ---------- 9. 实例重启 ----------
    if not api1_restart_cmd:
        skip("实例重启后身份正确", "未提供 --api1-restart-cmd")
    else:
        rc, _, err = run_cmd(shlex.split(api1_restart_cmd))
        check("api1重启命令执行成功", rc == 0, f"rc={rc} err={err!r}")
        ok = wait_until(lambda: http("GET", api1 + "/healthz")[0] == 200, 90)
        check("api1重启后恢复就绪", ok)
        st, rows = http("GET", api1 + "/faults", token=tok_b)
        ok1 = st == 200 and all(r["team_id"] == "team_b" for r in rows)
        st, rows = http("GET", api1 + "/faults", token=tok_a)
        ok2 = st == 200 and all(r["team_id"] == "team_a" for r in rows)
        check("重启后班组身份不串用", ok1 and ok2)

    # ---------- 汇总 ----------
    n_pass = sum(1 for s, _, _ in RESULTS if s == "PASS")
    n_fail = sum(1 for s, _, _ in RESULTS if s == "FAIL")
    n_skip = sum(1 for s, _, _ in RESULTS if s == "SKIP")
    print(f"\n== 结果: {n_pass} PASS, {n_fail} FAIL, {n_skip} SKIP")
    if n_fail:
        print("失败项:")
        for s, name, detail in RESULTS:
            if s == "FAIL":
                print(f"  - {name}: {detail}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
