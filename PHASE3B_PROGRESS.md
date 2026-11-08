# Phase 3B - implementation update

## Is update mein add hua
- `backend/app/worker/scanner.py`: per-account Redis lock, Gmail history polling, initial backfill, unique scan dedupe, body ko DB mein store kiye baghair analysis, large email ke liye headers-only fallback, planned actions ki reconciliation, bounded run budget aur exponential backoff.
- `backend/app/worker/scheduler.py`: bounded thread-pool concurrency, due accounts selection aur continuous scheduler.
- `backend/app/worker/__main__.py`: `python -m backend.app.worker`, `--once` aur `--once --force` CLI.
- `POST /api/scans/{id}/restore`: sirf user ki apni quarantined email ko Gmail Inbox mein restore karta hai; expired/revoked authorization par account `needs_reauth` hota hai.
- `POST /api/scans/{id}/feedback`: unique `not_phishing` feedback; feedback se model automatic retrain nahi hota.
- `/api/settings`: alerts, thresholds, whitelist, Telegram link/unlink aur irreversible Delete My Data endpoint.
- `web/templates/settings.html` + `web/static/settings.js`: settings UI; user-controlled strings `textContent` se render hoti hain.
- Dashboard detail mein restore aur feedback actions, Settings links, aur `needs_reauth` account ke liye reconnect button.
- Gmail reconnect: same account ko re-authorize karne par account limit se ghalat block nahi hota; expired access token ke baad ek refresh retry hoti hai.
- Re-auth notice best-effort alert, settings/action/worker tests, README aur CI mein worker one-shot smoke command.

## Worker kaise chalana hai
```bash
python -m backend.app.worker --once
python -m backend.app.worker --once --force
python -m backend.app.worker
```
Worker ko alag process/container mein chalayein, web server ke andar nahi. Redis, database, Gmail OAuth aur encryption configuration pehle theek honi chahiye.

## Zaroori safety details
- Email body database mein store nahi hoti; sirf sender/subject, verdict, reasons, layer scores aur defanged URLs store hote hain.
- Gmail action `pending` pehle DB mein commit hota hai, phir Gmail par action lagta hai; restart par worker pending actions reconcile karta hai.
- Gmail message/account unique constraint duplicate scan rows ko rokta hai.
- Quarantine sirf `PHISHING` + score threshold + confidence threshold par hoti hai; baqi suspicious emails label ho sakti hain.
- Whitelist action suppress karne ke liye trusted Gmail authentication result mein DMARC pass lazmi hai. Whitelist ML verdict ko rewrite nahi karti.
- Restore aur settings routes har user ki ownership check karte hain; mutation routes par CSRF lazmi hai.
- Delete My Data irreversible hai; database data delete hota hai, Google token revoke best-effort hai. Redis transient cleanup bhi best-effort hai.

## Verification (is update mein khud chala ke dekha)
- `ruff check .`: clean. `pytest -q`: 182 pass. `pip-audit -r requirements.txt`: no known vulnerabilities.
- Purane 4 failing tests theek kiye: Gmail account limit ab callback par lagti hai (tests update), aur production config
  tests mein https `base_url` add hua.
- Naye `tests/test_worker_scanner.py` (12 tests): backfill + label/quarantine, repeat run par duplicate scan/action/alert nahi,
  crash ke baad pending action recover, Redis lock (overlap, release, doosre ka lock na chhedna), Redis down par fail-closed,
  exponential backoff (60/120/240), invalid_grant => needs_reauth (notice ek hi bar), history expired => backfill,
  time budget par bookmark aage nahi, bari email par headers-only, ek account fail par baqi chalein + user isolation.

## Abhi bhi live verification zaroori hai (tests mein cover NAHI)
- Gmail API, Telegram, SMTP aur Google OAuth ke asli credentials: apne test Gmail account par verify karein.
- Worker tests mein Gmail/engine/alert service fake hain; asli Gmail history/backfill/restore live account par check karein.
- Parallel worker threads (`WORKER_CONCURRENCY` > 1) tests mein SQLite ki wajah se serial hain; Postgres par staging mein verify karein.
- Alembic migrations real Postgres par (CI smoke test mein hain, yahan nahi chala).
- Bundled ML model synthetic data par trained hai; real-world performance independently validated nahi.
- Isay abhi "production-ready" nahi kaha ja sakta; staging mein verify karna zaroori hai.
