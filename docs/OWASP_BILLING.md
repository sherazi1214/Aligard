# Plans, payment aur OWASP Top 10 (2021) - kya laga hai

Flow: signup -> login -> /plans -> (Free: seedha / Pro-Business: Stripe Checkout par card) -> payment confirm -> dashboard -> Gmail connect lazmi.

| OWASP | Is feature mein |
|---|---|
| A01 Broken Access Control | Har product endpoint server par gated: 402 `plan_required`, 428 `gmail_required`. Billing endpoints sirf apni subscription. Sync par Stripe ka `client_reference_id` user se match. Telegram/inbox limits plan se. |
| A02 Crypto failures | Card data hamare paas kabhi nahi (Stripe hosted Checkout, PCI SAQ-A). Gmail tokens Fernet encrypted, passwords Argon2id, HSTS. |
| A03 Injection | SQLAlchemy ORM, Pydantic strict (`extra=forbid`, Literal plan, session_id regex). |
| A04 Insecure design | Plan sirf signed webhook / server-to-server Stripe lookup se active. Price server-side. Double-charge guard, idempotent events, out-of-order events ignore. |
| A05 Misconfiguration | Production mein mock payments, test keys, missing webhook secret par app start nahi hoti. Docs off in prod. |
| A06 Components | requirements pinned; CI mein pip-audit. |
| A07 Auth failures | Lockout, rate limits, 2FA, session rotation (pehle se) + billing rate limits. |
| A08 Integrity | Webhook HMAC-SHA256 + 5 min timestamp tolerance + constant-time compare + event-id replay block. |
| A09 Logging | Audit log: plan_free_selected, checkout_*, subscription_*; Stripe error text user ko nahi. |
| A10 SSRF | Stripe host fixed; redirect URLs server banata hai; Stripe se aaya URL host-check hota hai. |

Baqi (zaroor karein): Stripe Dashboard mein webhook endpoint + Prices banana; `PAYMENTS_PROVIDER=stripe`; HTTPS domain.
