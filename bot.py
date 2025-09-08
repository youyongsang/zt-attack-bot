#!/usr/bin/env python3
import argparse, asyncio, sys, time, math, csv
from pathlib import Path
from urllib.parse import urlparse
import datetime as dt

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
    p.add_argument("--csv", help="Append run summary to this CSV file")
    p.add_argument("--mutate", action="store_true",
                   help="Apply simple mutations to each word (Capitalize, upper, suffixes, light leet).")
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

def variants(word: str):
    """간단 변형: 대/소문자, 흔한 접미사, 얕은 leet 치환"""
    yield word
    yield word.capitalize()
    yield word.upper()
    for suf in ("1", "12", "123", "!", "2025", "!1"):
        yield word + suf
    table = str.maketrans({"a":"@", "e":"3", "i":"1", "o":"0", "s":"5"})
    w2 = word.translate(table)
    if w2 != word:
        yield w2

def percentile(values, p: float):
    if not values:
        return None
    xs = sorted(values)
    k = (len(xs) - 1) * p
    f, c = math.floor(k), math.ceil(k)
    if f == c:
        return xs[int(k)]
    return xs[f] * (c - k) + xs[c] * (k - f)

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
            headers={
                "Content-Type": "application/json",
                "X-Test-Bot": "zt-attack-bot"  # 서버 로그 식별용
            },
        )
        status = res.status_code

        # 429면 Retry-After를 존중
        if status == 429:
            retry_after = float(res.headers.get("Retry-After", "0") or 0)
            await asyncio.sleep(min(5.0, max(0.0, retry_after)))

        # auth-min 서버 기준:
        # - 200: ok:true → 로그인 성공 (세션 쿠키 발급)
        # - 401: Invalid credentials
        # - 403: Email not verified (이메일 인증 미완료)
        if status == 200:
            if state.get("first_success_ts") is None:
                state["first_success_ts"] = time.perf_counter()
                state["first_password"] = password
                if state.get("stop_on_success"):
                    state["stop"] = True
    except Exception:
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
    parsed = urlparse(args.base)
    host = parsed.hostname or ""
    scheme = parsed.scheme
    if scheme not in {"http", "https"}:
        print(f"[ABORT] base must start with http/https: {args.base}")
        sys.exit(2)
    allowed = {h.strip() for h in args.allowlist.split(",") if h.strip()}
    if host not in allowed:
        print(f"[ABORT] Host '{host}' not in allowlist: {sorted(allowed)}")
        sys.exit(2)

    # Load wordlist
    wl_path = Path(args.wordlist)
    if not wl_path.exists():
        print(f"[ERROR] wordlist not found: {wl_path}")
        sys.exit(2)

    def candidate_iter():
        with wl_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip()
                if not w:
                    continue
                if args.mutate:
                    for v in variants(w):
                        yield v
                else:
                    yield w

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
    started_wall = dt.datetime.now(dt.timezone.utc)
    deadline = start + args.duration

    max_inflight = args.concurrency * 2  # task 적체 방지
    async with httpx.AsyncClient(follow_redirects=False) as client:
        tasks = []
        for pwd in candidate_iter():
            if state["stop"]:
                break
            if time.perf_counter() > deadline:
                break
            await sem.acquire()
            tasks.append(asyncio.create_task(
                try_password(client, limiter, args.base, args.user, pwd, state, sem)
            ))
            if len(tasks) >= max_inflight:
                await asyncio.gather(*tasks, return_exceptions=True)
                tasks.clear()
        if tasks:
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
        ttfc = None
        print("FIRST SUCCESS  : (none)")
    if state["latencies"]:
        p50 = percentile(state["latencies"], 0.50)
        p95 = percentile(state["latencies"], 0.95)
        print(f"Latency (p50)  : {p50*1000:.1f} ms")
        print(f"Latency (p95)  : {p95*1000:.1f} ms")
    else:
        p50 = p95 = None
    print("================\n")
    if state["first_success_ts"] is not None:
        print("[NOTE] For responsible testing, rotate/delete this test account password immediately.")

    # CSV 저장(옵션)
    if args.csv:
        row = {
            "started_at": started_wall.isoformat(),
            "base": args.base,
            "user": args.user,
            "concurrency": args.concurrency,
            "qps": args.qps,
            "duration_budget_s": args.duration,
            "duration_actual_s": round(total, 3),
            "attempts": state["attempts"],
            "counts_200": state["by_status"].get(200, 0),
            "counts_401": state["by_status"].get(401, 0),
            "counts_403": state["by_status"].get(403, 0),
            "counts_429": state["by_status"].get(429, 0),
            "first_success_s": round(ttfc, 3) if ttfc is not None else "",
            "p50_ms": round((p50 or 0)*1000, 1) if p50 is not None else "",
            "p95_ms": round((p95 or 0)*1000, 1) if p95 is not None else "",
            "mutate": bool(args.mutate),
            "stop_on_success": bool(args.stop_on_success),
        }
        header = list(row.keys())
        path = Path(args.csv)
        new_file = not path.exists()
        with path.open("a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=header)
            if new_file:
                w.writeheader()
            w.writerow(row)

def main():
    args = parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Bye.")

if __name__ == "__main__":
    main()
