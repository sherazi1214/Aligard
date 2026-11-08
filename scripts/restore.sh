#!/usr/bin/env bash
# ASAL restore (disaster). Production DB ko replace karta hai. Pehle web/worker band hote hain.
# Usage: ./scripts/restore.sh backups/aliguard-....dump
set -euo pipefail
cd "$(dirname "$0")/.."
dump="${1:?backup file ka path dein}"
COMPOSE=(docker compose -f docker-compose.prod.yml --env-file .env.prod)
read -r -p "Ye maujooda database ko $dump se REPLACE kar dega. 'yes' likhein: " ok
[ "$ok" = "yes" ] || { echo "Cancel"; exit 1; }
[ -f "$dump.sha256" ] && sha256sum -c "$dump.sha256"
"${COMPOSE[@]}" stop web worker
"${COMPOSE[@]}" exec -T db psql -U aliguard -d postgres -v ON_ERROR_STOP=1 \
  -c "DROP DATABASE IF EXISTS aliguard WITH (FORCE)" -c "CREATE DATABASE aliguard"
"${COMPOSE[@]}" exec -T db pg_restore -U aliguard -d aliguard --no-owner --exit-on-error < "$dump"
"${COMPOSE[@]}" up -d web worker
echo "Restore complete. /health/ready aur /health/worker check karein."
