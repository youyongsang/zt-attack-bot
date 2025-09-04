#!/usr/bin/env python3
import argparse, asyncio, sys, time
from pathlib import Path
from urllib.parse import urlparse

import httpx

BANNER = r"""
== zt-attack-bot (password-only login tester) ==
For use ONLY against targets you own & have explicit permission to test.
"""

def parse_args():
    p = argparse.ArgumentParser(description="Password-only login attack tester (for your own system).")
    p.add_argument("--i-own-this-target", choices=["yes"], required=True,
                   help="Safety switch. Must be 'yes'.")
    p.add_argument("--base", required=True, help="API base, e.g., http://localhost:8000")
    p.add_argument("--user", required=True, help="Target account email")
    p.add_argument("--wordlist", required=True, help="Path to password list (UTF-8)")
    p.add_argument("--concurrency", type=int, default=5, help="Max concurrent attempts (default 5)")
    p.add_argument("--qps", type=float, default=3.0, help="Requests per second cap (default 3)")
    p.add_argument("--duration", type=int, default=120, help="Max seconds to run (default 120)")
    p.add_argument("--allowlist", default="localhost,127.0.0.1",
                   help="Comma-separated hosts allowed. Default: localhost,127.0.0.1")
    p.add_argument("--stop-on-success", action="store_true",
                   help="Stop immediately when a password works (default: keep collecting stats until duration/wordlist end)")
    return p.parse_args()

class RateLimiter:
    """Very simple global rate limiter (~QPS)."""
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

async def try_password(client: httpx.AsyncClient, limiter: RateLimiter, base: str,
                       email: str, password: str, state: dict, sem: asyncio.Semaphore):
    await limiter.wait()
    t0 = time.perf_counter()
    status = None
    try:
        res = await client.post(
            f"{base}/auth/login",
            json={"email": email, "password": password},
            timeout=10.0,
            headers={"Content-Type": "application/json"},
        )
        status = res.status_code
        # auth-min 서버 기준:
        # - 200: ok:true → 로그인 성공 (세션 쿠키 발급)
        # - 401: Invalid credentials
        # - 403: Email not verified (이메일 인증 미완료)
        # 그 외: 기타 오류
        if status == 200:
            if state.get("first_success_ts") is None:
                state["first_success_ts"] = time.perf_counter()
                state["first_password"] = password
                if state.get("stop_on_success"):
                    state["stop"] = True
    except Exception as e:
        status = -1
    finally:
        elapsed = time.perf_counter() - t0
        # 메트릭 갱신
        state["attempts"] += 1
        state["by_status"][status] = state["by_status"].get(status, 0) + 1
        state["latencies"].append(elapsed)
        sem.release()

async def run(args):
    print(BANNER)
    # Safety checks
    host = urlparse(args.base).hostname or ""
    allowed = {h.strip() for h in args.allowlist.split(",") if h.strip()}
    if host not in allowed:
        print(f"[ABORT] Host '{host}' not in allowlist: {sorted(allowed)}")
        sys.exit(2)

    # Load wordlist
    wl_path = Path(args.wordlist)
    if not wl_path.exists():
        print(f"[ERROR] wordlist not found: {wl_path}")
        sys.exit(2)
    with wl_path.open("r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    if not passwords:
        print("[ERROR] empty wordlist")
        sys.exit(2)

    # Shared state
    state = {
        "attempts": 0,
        "first_success_ts": None,
        "first_password": None,
        "by_status": {},       # {status: count}
        "latencies": [],       # per-attempt elapsed
        "stop_on_success": args.stop_on_success,
        "stop": False,
    }

    limiter = RateLimiter(args.qps)
    sem = asyncio.Semaphore(args.concurrency)
    start = time.perf_counter()
    deadline = start + args.duration

    async with httpx.AsyncClient(follow_redirects=False) as client:
        tasks = []
        for pwd in passwords:
            if state["stop"]:
                break
            if time.perf_counter() > deadline:
                break
            await sem.acquire()
            # schedule worker
            tasks.append(asyncio.create_task(
                try_password(client, limiter, args.base, args.user, pwd, state, sem)
            ))
        # Drain
        await asyncio.gather(*tasks, return_exceptions=True)

    total = time.perf_counter() - start
    # Summary
    print("\n=== SUMMARY ===")
    print(f"Target         : {args.base} (user={args.user})")
    print(f"Duration(s)    : {total:.2f} (budget {args.duration}s)")
    print(f"Concurrency    : {args.concurrency}, QPS cap: {args.qps}")
    print(f"Attempts       : {state['attempts']}")
    print(f"Status counts  : " + ", ".join([f"{k}:{v}" for k,v in sorted(state['by_status'].items())]) )
    if state["first_success_ts"] is not None:
        ttfc = state["first_success_ts"] - start
        print(f"FIRST SUCCESS  : {ttfc:.2f}s (password='{state['first_password']}')")
    else:
        print("FIRST SUCCESS  : (none)")
    if state["latencies"]:
        lat = sorted(state["latencies"])
        p50 = lat[int(0.50*len(lat))-1]
        p95 = lat[int(0.95*len(lat))-1]
        print(f"Latency (p50)  : {p50*1000:.1f} ms")
        print(f"Latency (p95)  : {p95*1000:.1f} ms")
    print("================\n")
    if state["first_success_ts"] is not None:
        print("[NOTE] For responsible testing, rotate/delete this test account password immediately.")

def main():
    args = parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Bye.")

if __name__ == "__main__":
    main()
