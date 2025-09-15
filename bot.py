#!/usr/bin/env python3
import argparse, asyncio, sys, time, random
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

import httpx
import pyotp  # OTP 테스트용
import csv

BANNER = r"""
== zt-attack-bot ==
For use ONLY against targets you own & have explicit permission to test.
Modes:
  - wordlist                (기존: 비번만 테스트)
  - otp-invalid-spray       (잘못된 6자리 OTP 분사, 레이트리밋/락 계측)
  - otp-replay              (동일 타임스텝 OTP 재사용 정책 계측)
  - otp-window              (이전/현재/다음 스텝 허용창 계측)
"""

# CSV 컬럼(모든 모드를 포괄하는 슈퍼셋, 한글 설명 포함)
CSV_FIELDS = [
    "mode(모드)",
    "started_at(실행시작시각)",
    "ended_at(종료시각)",
    "base(API기본URL)",
    "user(대상계정)",
    "concurrency(동시수)",
    "qps(QPS상한)",
    "duration_budget_s(예산초)",
    "duration_actual_s(실제초)",
    "attempts(시도수)",
    "status_200",
    "status_400",
    "status_401",
    "status_403",
    "status_429",
    "status_other",
    "first_success_s(첫성공초)",
    "first_password(첫성공비번)",
    "first_note(첫성공메모)",
    "otp_code(테스트코드)",
    "first_status(첫상태)",
    "second_status(재사용상태)",
    "status_prev(이전스텝)",
    "status_now(현재스텝)",
    "status_next(다음스텝)",
    "latency_p50_ms",
    "latency_p95_ms",
]

def write_csv_row(row: dict, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    file_exists = path.exists() and path.stat().st_size > 0
    # UTF-8-SIG로 저장하면 엑셀에서 한글 헤더가 바로 읽힘
    with path.open("a", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if not file_exists:
            w.writeheader()
        # 누락 컬럼은 빈칸으로 채움
        safe = {k: row.get(k, "") for k in CSV_FIELDS}
        w.writerow(safe)

# ------------------------
# CLI
# ------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Password/MFA login tester (your own system only).")

    # 공통 안전장치/타겟
    p.add_argument("--i-own-this-target", choices=["yes"], required=True, help="Safety switch. Must be 'yes'.")
    p.add_argument("--base", required=True, help="API base, e.g., http://localhost:8000")
    p.add_argument("--user", required=True, help="Target account email")
    p.add_argument("--allowlist", default="localhost,127.0.0.1", help="Comma-separated allowed hosts")

    # 모드
    p.add_argument("--mode",
                   choices=["wordlist", "otp-invalid-spray", "otp-replay", "otp-window"],
                   default="wordlist",
                   help="Test mode (default: wordlist)")

    # wordlist 모드(비번 브루트포스)
    p.add_argument("--wordlist", help="Path to password list (UTF-8) [wordlist mode]")
    p.add_argument("--concurrency", type=int, default=5, help="Max concurrent attempts (default 5)")
    p.add_argument("--qps", type=float, default=3.0, help="Requests per second cap (default 3)")
    p.add_argument("--duration", type=int, default=120, help="Max seconds to run (default 120)")
    p.add_argument("--stop-on-success", action="store_true", help="Stop on first success (wordlist mode)")

    # OTP 모드용
    p.add_argument("--known-password", help="Correct password to enter MFA stage [OTP modes]")
    p.add_argument("--otp-secret", help="BASE32 TOTP secret (for replay/window) [OTP modes]")

    # CSV 출력
    p.add_argument("--csv", default="logs/zt_attack_results.csv",
                   help="CSV file path to append results (default: logs/zt_attack_results.csv)")

    return p.parse_args()


# ------------------------
# Rate limiter
# ------------------------
class RateLimiter:
    def __init__(self, qps: float):
        self.qps = max(qps, 0.1)
        self._interval = 1.0 / self.qps
        self._lock = asyncio.Lock()
        self._last = 0.0
    async def wait(self):
        async with self._lock:
            now = asyncio.get_running_loop().time()
            wait = max(0.0, (self._last + self._interval) - now)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = asyncio.get_running_loop().time()


# ------------------------
# 공통 HTTP 헬퍼
# ------------------------
def safe_json(res: httpx.Response):
    try:
        return res.json()
    except Exception:
        try:
            return {"raw": res.text}
        except Exception:
            return {}

async def login_password_only(client: httpx.AsyncClient, base: str, email: str, password: str):
    return await client.post(f"{base}/auth/login",
                             json={"email": email, "password": password},
                             timeout=10.0,
                             headers={"Content-Type": "application/json"})

async def verify_otp_code(client: httpx.AsyncClient, base: str, code: str):
    return await client.post(f"{base}/auth/mfa/totp/verify-login",
                             json={"code": code},
                             timeout=10.0,
                             headers={"Content-Type": "application/json"})

async def must_enter_mfa_stage(client: httpx.AsyncClient, base: str, email: str, password: str):
    res = await login_password_only(client, base, email, password)
    data = safe_json(res)
    if res.status_code != 200:
        raise RuntimeError(f"Cannot enter MFA stage: status={res.status_code}, data={data}")
    if data.get("mfa_enroll_required"):
        raise RuntimeError("Account requires TOTP enrollment first.")
    if not data.get("mfa_required"):
        raise RuntimeError("Server did not require MFA for this account.")
    return True


# ------------------------
# WORDLIST (기존)
# ------------------------
async def try_password(client: httpx.AsyncClient, limiter: RateLimiter, base: str,
                       email: str, password: str, state: dict, sem: asyncio.Semaphore):
    await limiter.wait()
    t0 = time.perf_counter()
    status = None
    try:
        res = await login_password_only(client, base, email, password)
        status = res.status_code
        if status == 200:
            data = safe_json(res)
            if state.get("first_success_ts") is None:
                state["first_success_ts"] = time.perf_counter()
                state["first_password"] = password
                state["first_note"] = "password accepted (mfa may be required)" if data.get("mfa_required") else "login complete"
                if state.get("stop_on_success"):
                    state["stop"] = True
    except Exception:
        status = -1
    finally:
        elapsed = time.perf_counter() - t0
        state["attempts"] += 1
        state["by_status"][status] = state["by_status"].get(status, 0) + 1
        state["latencies"].append(elapsed)
        sem.release()

async def run_wordlist(args):
    state = {
        "attempts": 0,
        "first_success_ts": None,
        "first_password": None,
        "first_note": None,
        "by_status": {},
        "latencies": [],
        "stop_on_success": args.stop_on_success,
        "stop": False,
    }
    wl_path = Path(args.wordlist)
    if not wl_path or not wl_path.exists():
        raise SystemExit(f"[ERROR] wordlist not found: {wl_path}")
    with wl_path.open("r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]
    if not passwords:
        raise SystemExit("[ERROR] empty wordlist")

    limiter = RateLimiter(args.qps)
    sem = asyncio.Semaphore(args.concurrency)
    started_wall = datetime.now()
    start = time.perf_counter()
    deadline = start + args.duration

    async with httpx.AsyncClient(follow_redirects=False) as client:
        tasks = []
        for pwd in passwords:
            if state["stop"] or time.perf_counter() > deadline:
                break
            await sem.acquire()
            tasks.append(asyncio.create_task(
                try_password(client, limiter, args.base, args.user, pwd, state, sem)
            ))
        await asyncio.gather(*tasks, return_exceptions=True)

    total = time.perf_counter() - start
    lat = sorted(state["latencies"])
    p50 = lat[max(0, int(0.50*len(lat))-1)] if lat else None
    p95 = lat[max(0, int(0.95*len(lat))-1)] if lat else None

    # Summary
    print("\n=== SUMMARY(wordlist) ===")
    print(f"Target         : {args.base} (user={args.user})")
    print(f"Duration(s)    : {total:.2f} (budget {args.duration}s)")
    print(f"Concurrency    : {args.concurrency}, QPS cap: {args.qps}")
    print(f"Attempts       : {state['attempts']}")
    print(f"Status counts  : " + ", ".join([f"{k}:{v}" for k,v in sorted(state['by_status'].items())]))
    if state["first_success_ts"] is not None:
        ttfc = state["first_success_ts"] - start
        print(f"FIRST SUCCESS  : {ttfc:.2f}s (password='{state['first_password']}', note={state['first_note']})")
    else:
        ttfc = None
        print("FIRST SUCCESS  : (none)")
    if p50 is not None:
        print(f"Latency (p50)  : {p50*1000:.1f} ms")
    if p95 is not None:
        print(f"Latency (p95)  : {p95*1000:.1f} ms")
    print("=========================\n")

    # CSV 저장
    status_counts = state["by_status"]
    row = {
        "mode(모드)": "wordlist",
        "started_at(실행시작시각)": started_wall.isoformat(),
        "ended_at(종료시각)": datetime.now().isoformat(),
        "base(API기본URL)": args.base,
        "user(대상계정)": args.user,
        "concurrency(동시수)": args.concurrency,
        "qps(QPS상한)": args.qps,
        "duration_budget_s(예산초)": args.duration,
        "duration_actual_s(실제초)": round(total, 3),
        "attempts(시도수)": state["attempts"],
        "status_200": status_counts.get(200, 0),
        "status_400": status_counts.get(400, 0),
        "status_401": status_counts.get(401, 0),
        "status_403": status_counts.get(403, 0),
        "status_429": status_counts.get(429, 0),
        "status_other": sum(v for k,v in status_counts.items() if k not in (200,400,401,403,429)),
        "first_success_s(첫성공초)": round(ttfc, 3) if ttfc is not None else "",
        "first_password(첫성공비번)": state.get("first_password") or "",
        "first_note(첫성공메모)": state.get("first_note") or "",
        "latency_p50_ms": round((p50 or 0)*1000, 1) if p50 is not None else "",
        "latency_p95_ms": round((p95 or 0)*1000, 1) if p95 is not None else "",
    }
    write_csv_row(row, Path(args.csv))


# ------------------------
# OTP MODES
# ------------------------
async def run_otp_invalid_spray(args):
    """랜덤 6자리 코드 분사: 레이트리밋/락/응답분포 + 지연 측정"""
    if not args.known_password:
        raise SystemExit("[ERROR] --known-password is required for OTP modes")

    limiter = RateLimiter(args.qps)
    sem = asyncio.Semaphore(args.concurrency)
    stats = {"attempts": 0, "by_status": {}, "latencies": []}
    started_wall = datetime.now()
    start = time.perf_counter()
    deadline = start + args.duration

    async with httpx.AsyncClient(follow_redirects=False) as client:
        # MFA 단계 진입
        await must_enter_mfa_stage(client, args.base, args.user, args.known_password)

        async def worker():
            await limiter.wait()
            code = f"{random.randrange(0, 1_000_000):06d}"
            t0 = time.perf_counter()
            try:
                r = await verify_otp_code(client, args.base, code)
                stats["by_status"][r.status_code] = stats["by_status"].get(r.status_code, 0) + 1
            except Exception:
                stats["by_status"][-1] = stats["by_status"].get(-1, 0) + 1
            finally:
                stats["attempts"] += 1
                stats["latencies"].append(time.perf_counter() - t0)
                sem.release()

        tasks = []
        while time.perf_counter() < deadline:
            await sem.acquire()
            tasks.append(asyncio.create_task(worker()))
        await asyncio.gather(*tasks, return_exceptions=True)

    total = time.perf_counter() - start
    lat = sorted(stats["latencies"])
    p50 = lat[max(0, int(0.50*len(lat))-1)] if lat else None
    p95 = lat[max(0, int(0.95*len(lat))-1)] if lat else None

    print("\n=== SUMMARY(otp-invalid-spray) ===")
    print(f"Target         : {args.base} (user={args.user})")
    print(f"Duration(s)    : {total:.2f} (budget {args.duration}s)")
    print(f"Concurrency    : {args.concurrency}, QPS cap: {args.qps}")
    print(f"Attempts       : {stats['attempts']}")
    print(f"Status counts  : " + ", ".join([f"{k}:{v}" for k,v in sorted(stats['by_status'].items())]))
    print("Expect to see 400/429 mostly; 200 should be ~0 if protections work.")
    print("==================================\n")

    status_counts = stats["by_status"]
    row = {
        "mode(모드)": "otp-invalid-spray",
        "started_at(실행시작시각)": started_wall.isoformat(),
        "ended_at(종료시각)": datetime.now().isoformat(),
        "base(API기본URL)": args.base,
        "user(대상계정)": args.user,
        "concurrency(동시수)": args.concurrency,
        "qps(QPS상한)": args.qps,
        "duration_budget_s(예산초)": args.duration,
        "duration_actual_s(실제초)": round(total, 3),
        "attempts(시도수)": stats["attempts"],
        "status_200": status_counts.get(200, 0),
        "status_400": status_counts.get(400, 0),
        "status_401": status_counts.get(401, 0),
        "status_403": status_counts.get(403, 0),
        "status_429": status_counts.get(429, 0),
        "status_other": sum(v for k,v in status_counts.items() if k not in (200,400,401,403,429)),
        "latency_p50_ms": round((p50 or 0)*1000, 1) if p50 is not None else "",
        "latency_p95_ms": round((p95 or 0)*1000, 1) if p95 is not None else "",
    }
    write_csv_row(row, Path(args.csv))


async def run_otp_replay(args):
    """동일 타임스텝 코드 재사용 시 정책 계측(1회만 허용 권장)"""
    if not args.known_password or not args.otp_secret:
        raise SystemExit("[ERROR] --known-password and --otp-secret are required for otp-replay")

    started_wall = datetime.now()
    start = time.perf_counter()

    async with httpx.AsyncClient(follow_redirects=False) as client:
        await must_enter_mfa_stage(client, args.base, args.user, args.known_password)
        t = pyotp.TOTP(args.otp_secret)
        code = t.now()
        r1 = await verify_otp_code(client, args.base, code)
        r2 = await verify_otp_code(client, args.base, code)

    total = time.perf_counter() - start
    print("\n=== SUMMARY(otp-replay) ===")
    print(f"code(step now): {code}")
    print(f"first use     : {r1.status_code}")
    print(f"second(reuse) : {r2.status_code}")
    print("====================================\n")

    status_counts = {r1.status_code:1, r2.status_code:1}
    row = {
        "mode(모드)": "otp-replay",
        "started_at(실행시작시각)": started_wall.isoformat(),
        "ended_at(종료시각)": datetime.now().isoformat(),
        "base(API기본URL)": args.base,
        "user(대상계정)": args.user,
        "duration_actual_s(실제초)": round(total, 3),
        "attempts(시도수)": 2,
        "status_200": status_counts.get(200, 0),
        "status_400": status_counts.get(400, 0),
        "status_401": status_counts.get(401, 0),
        "status_403": status_counts.get(403, 0),
        "status_429": status_counts.get(429, 0),
        "status_other": sum(v for k,v in status_counts.items() if k not in (200,400,401,403,429)),
        "otp_code(테스트코드)": code,
        "first_status(첫상태)": r1.status_code,
        "second_status(재사용상태)": r2.status_code,
    }
    write_csv_row(row, Path(args.csv))


async def run_otp_window(args):
    """±30초 허용창 계측(prev/now/next)"""
    if not args.known_password or not args.otp_secret:
        raise SystemExit("[ERROR] --known-password and --otp-secret are required for otp-window")

    started_wall = datetime.now()
    start = time.perf_counter()

    async with httpx.AsyncClient(follow_redirects=False) as client:
        await must_enter_mfa_stage(client, args.base, args.user, args.known_password)
        t = pyotp.TOTP(args.otp_secret)
        now_ts = int(time.time())
        codes = {
            "prev": t.at(now_ts - 30),
            "now" : t.at(now_ts),
            "next": t.at(now_ts + 30),
        }
        results = {}
        for label, code in codes.items():
            r = await verify_otp_code(client, args.base, code)
            results[label] = r.status_code

    total = time.perf_counter() - start
    print("\n=== SUMMARY(otp-window) ===")
    for k,v in results.items():
        print(f"{k:>4} : {v}")
    print("====================================\n")

    status_counts = {}
    for v in results.values():
        status_counts[v] = status_counts.get(v, 0) + 1
    row = {
        "mode(모드)": "otp-window",
        "started_at(실행시작시각)": started_wall.isoformat(),
        "ended_at(종료시각)": datetime.now().isoformat(),
        "base(API기본URL)": args.base,
        "user(대상계정)": args.user,
        "duration_actual_s(실제초)": round(total, 3),
        "attempts(시도수)": 3,
        "status_200": status_counts.get(200, 0),
        "status_400": status_counts.get(400, 0),
        "status_401": status_counts.get(401, 0),
        "status_403": status_counts.get(403, 0),
        "status_429": status_counts.get(429, 0),
        "status_other": sum(v for k,v in status_counts.items() if k not in (200,400,401,403,429)),
        "status_prev(이전스텝)": results.get("prev",""),
        "status_now(현재스텝)": results.get("now",""),
        "status_next(다음스텝)": results.get("next",""),
    }
    write_csv_row(row, Path(args.csv))


# ------------------------
# main
# ------------------------
def safety_check(args):
    host = urlparse(args.base).hostname or ""
    allowed = {h.strip() for h in args.allowlist.split(",") if h.strip()}
    if host not in allowed:
        print(f"[ABORT] Host '{host}' not in allowlist: {sorted(allowed)}")
        sys.exit(2)

async def main_async(args):
    print(BANNER)
    safety_check(args)

    if args.mode == "wordlist":
        if not args.wordlist:
            raise SystemExit("[ERROR] --wordlist is required for wordlist mode")
        await run_wordlist(args)

    elif args.mode == "otp-invalid-spray":
        await run_otp_invalid_spray(args)

    elif args.mode == "otp-replay":
        await run_otp_replay(args)

    elif args.mode == "otp-window":
        await run_otp_window(args)

def main():
    args = parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Bye.")

if __name__ == "__main__":
    main()
