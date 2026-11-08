"""Basic load test (sirf apne staging par chalayein, kisi aur ki site par kabhi nahi).
    python scripts/loadtest.py --base-url https://staging.example.com --concurrency 20 --duration 30
Public pages hit karta hai (login nahi). Global rate limit (default 300/min per IP) 429 dega: wo expected hai,
isliye staging par test ke waqt GLOBAL_RATE_LIMIT_PER_MINUTE=0 karein ya 429 ko alag ginti mein dekhein."""
import argparse
import statistics
import threading
import time
from collections import Counter

import httpx

PATHS = ["/health", "/login", "/signup", "/privacy"]


def worker(base: str, stop_at: float, latencies: list, codes: Counter, lock: threading.Lock) -> None:
    with httpx.Client(base_url=base, timeout=10.0) as client:
        i = 0
        while time.monotonic() < stop_at:
            path = PATHS[i % len(PATHS)]
            i += 1
            started = time.monotonic()
            try:
                status = client.get(path).status_code
            except httpx.HTTPError as exc:
                status = type(exc).__name__
            elapsed = (time.monotonic() - started) * 1000
            with lock:
                latencies.append(elapsed)
                codes[status] += 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--duration", type=int, default=20)
    args = parser.parse_args()
    latencies: list[float] = []
    codes: Counter = Counter()
    lock = threading.Lock()
    stop_at = time.monotonic() + args.duration
    threads = [threading.Thread(target=worker, args=(args.base_url, stop_at, latencies, codes, lock))
               for _ in range(args.concurrency)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    latencies.sort()
    total = len(latencies)
    if not total:
        print("Koi request complete nahi hui")
        return
    p = lambda q: latencies[min(total - 1, int(total * q))]  # noqa: E731
    print(f"requests={total} rps={total / args.duration:.1f} p50={p(.5):.0f}ms p95={p(.95):.0f}ms "
          f"p99={p(.99):.0f}ms mean={statistics.mean(latencies):.0f}ms")
    print("status codes:", dict(codes))


if __name__ == "__main__":
    main()
