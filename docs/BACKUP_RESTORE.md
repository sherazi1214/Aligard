# Backup aur restore

## Kya backup hota hai
Sirf Postgres (users, sessions, Gmail encrypted tokens, scans, settings). Redis transient hai (rate limits, locks) - backup nahi.
**Zaroori:** `ENCRYPTION_KEY` (aur purani keys) ka alag secure backup rakhein. Uske baghair restore kiye hue Gmail/2FA secrets decrypt nahi honge
(users ko dobara connect/2FA setup karna hoga). Key ko database backup ke saath ek hi jagah mat rakhein.

## VPS
- Roz: `./scripts/backup.sh` (cron 03:17). Custom-format dump + SHA-256, `pg_restore --list` se validity check, `KEEP_DAYS=14` purane delete.
- Offsite copy lazmi (server ke saath disk ja sakti hai): `rclone copy backups/ remote:aliguard-backups` ya `scp`. Backup files mein user data hai: encrypted storage, restricted access.
- **Restore test (mahine mein ek bar, aur pehli deploy par):**
  `./scripts/restore_test.sh backups/aliguard-<stamp>.dump`
  Scratch DB mein restore karta hai, checksum, table count, alembic revision aur users count print karta hai, phir scratch drop. Production ko nahi chhuta.
- **Asli restore (disaster):** `./scripts/restore.sh backups/aliguard-<stamp>.dump` (confirmation maangta hai, web/worker rokta hai, DB replace, dobara start).
  Phir `/health/ready`, `/health/worker`, aur ek test login check karein.

## Render
Managed Postgres ke automatic backups/point-in-time recovery plan par depend hain: dashboard mein enabled aur retention verify karein.
Restore Render ke dashboard se naye database mein; phir `DATABASE_URL` badlein. Is ka restore test bhi ek bar karke result yahan likhein.

## Privacy se taluq
"Delete my data" live database se data hata deta hai; purane backups mein data backup-retention (14 din default) tak reh sakta hai. Privacy Policy mein ye likha hai.
Restore ke baad jo users pehle delete ho chuke hon unhein dobara delete karna zaroori hai (deletion log rakhein agar qanoon maange).

## Restore test log (apna record)
| Tareekh | Backup | Natija |
|---|---|---|
| (abhi tak nahi kiya) | | |
