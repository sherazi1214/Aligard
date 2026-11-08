#!/usr/bin/env bash
# VPS (docker-compose.prod.yml) Postgres backup: custom-format dump + SHA-256, purane backups saaf.
# cron: 17 3 * * *  cd /opt/aliguard && ./scripts/backup.sh >> /var/log/aliguard-backup.log 2>&1
# Backup ko doosri jagah (offsite) bhi copy karein: docs/BACKUP_RESTORE.md
set -euo pipefail
cd "$(dirname "$0")/.."
BACKUP_DIR="${BACKUP_DIR:-./backups}"
KEEP_DAYS="${KEEP_DAYS:-14}"
COMPOSE=(docker compose -f docker-compose.prod.yml --env-file .env.prod)
mkdir -p "$BACKUP_DIR"
umask 077
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$BACKUP_DIR/aliguard-$stamp.dump"
"${COMPOSE[@]}" exec -T db pg_dump -U aliguard -d aliguard --format=custom --no-owner > "$out.partial"
# Khali/chhoti file backup nahi: pg_restore --list se dump ki validity check
"${COMPOSE[@]}" exec -T db pg_restore --list < "$out.partial" > /dev/null
mv "$out.partial" "$out"
sha256sum "$out" > "$out.sha256"
find "$BACKUP_DIR" -name 'aliguard-*.dump*' -mtime +"$KEEP_DAYS" -delete
echo "OK backup: $out ($(du -h "$out" | cut -f1))"
