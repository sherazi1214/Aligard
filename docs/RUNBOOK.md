# Runbook

## Services
| Service | Kaam | Check |
|---|---|---|
| web | FastAPI, UI + API | `/health` (liveness), `/health/ready` (DB+Redis) |
| worker | Gmail scanning, alerts, retention purge | `/health/worker` (heartbeat) |
| db | Postgres 16 | `pg_isready` |
| redis | rate limit, locks, OAuth state, budgets, heartbeat | `redis-cli ping` |

Logs: JSON, secrets/emails masked. VPS: `docker compose -f docker-compose.prod.yml logs -f web worker`.

## Aam masail
| Alamat | Wajah / Kya karein |
|---|---|
| `/health/worker` 503 `stale` | Worker atka/band: `docker compose ... restart worker`; logs mein `Worker scheduler cycle fail` dekhein |
| `/health/worker` 503 `unknown` | Redis down ya worker kabhi chala hi nahi |
| User ka Gmail "needs_reauth" | Token revoke/expire: user dashboard se Reconnect kare. Worker khud account ko `needs_reauth` karke notice bhejta hai |
| `BUDGET_ALARM ... 80%` | OpenAI/VT daily call limit ke qareeb. Limit barhayein (`*_DAILY_CALL_LIMIT`) ya wait; 100% par layer band hoti hai aur engine degraded verdict deta hai, scanning chalti rehti hai |
| 429 bohat zyada | `GLOBAL_RATE_LIMIT_PER_MINUTE` (per IP). Proxy ke peeche `TRUST_PROXY_HEADERS=true` na ho to sab users ek IP dikhte hain |
| App start nahi hoti | Config validator ki wajah: SECRET_KEY<32, ENCRYPTION_KEY khali, EMAIL_BACKEND!=smtp, redirect URI https nahi (production) |
| Gmail API 429/5xx | Client khud retry+backoff karta hai; account `consecutive_failures` ke saath exponential backoff (60s..1h) |

## Failure drills (staging par, expected behaviour)
Automated tests (`tests/test_phase4.py`) simulate karte hain; asli drill ye hai:
1. **Redis band:** `docker compose ... stop redis`
   Expected: site chalti rahe (login/dashboard/manual check), `/health` 200, `/health/ready` 503 (`redis:false`),
   `/health/worker` 503, Gmail connect 503 (fail-closed), paid APIs skip. Naye requests slow nahi (breaker 10s). Phir `start redis`: sab wapas.
2. **DB band:** `docker compose ... stop db`
   Expected: pages/API generic 500 (koi SQL/password detail nahi), `/health` 200, `/health/ready` 503. Worker har cycle error log kare, crash na kare. `start db` ke baad recover.
3. **Gmail 429:** asli quota hit karna mushkil hai; `tests/test_phase4.py::test_drill_gmail_429_*` retry/backoff verify karte hain. Live par logs mein `Gmail ... status=429` aur account `next_run_at` badhna dekhein.
4. **Worker crash:** `docker kill <worker>`; restart ke baad duplicate scan/alert nahi (unique constraint + pending-action reconcile; `tests/test_worker_scanner.py`).
Har drill ke natije yahan (date, kya hua) likhein.

## Release / rollback
1. Deploy se pehle `./scripts/backup.sh` (ya Render snapshot).
2. Naya image deploy; `migrate` pehle chalta hai.
3. Rollback (code): pichla image/commit dobara deploy. Migration sirf additive rakhein taake purana code naye schema par chal sake.
4. Rollback (schema): `alembic downgrade -1` sirf tab, aur pehle backup. Data-khoney wale downgrade se bachein; behtar hai backup se restore (docs/BACKUP_RESTORE.md).

## Incident checklist
1. Sentry/uptime alert dekhein, `/health/ready` + `/health/worker`.
2. Logs (masked) mein pehla error dhundein.
3. Mitigate (restart, limit, feature band: e.g. `VT_API_KEY`/`OPENAI_API_KEY` khali karein).
4. Agar secret leak ka shak ho: docs/KEY_ROTATION.md, saare sessions revoke (SECRET_KEY badalne se CSRF invalid hota hai; sessions DB mein hain: `UPDATE sessions SET revoked_at = now() WHERE revoked_at IS NULL;`).
5. User data breach ho to qanooni notification ka process (lawyer).
