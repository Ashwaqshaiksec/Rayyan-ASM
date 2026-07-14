#!/usr/bin/env bash
# Backup Rayyan ASM PostgreSQL database and screenshot store.
# Usage: ./scripts/backup.sh [backup_dir]
set -euo pipefail

BACKUP_DIR="${1:-/var/backups/rayyan-asm}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_PATH="${BACKUP_DIR}/${TIMESTAMP}"

mkdir -p "$BACKUP_PATH"

# Load config
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-rayyan_asm}"
DB_USER="${DB_USER:-rayyan}"
PGPASSWORD="${DB_PASSWORD:-}"

echo "=== Rayyan ASM Backup: ${TIMESTAMP} ==="

# Database dump
echo "Backing up database..."
export PGPASSWORD
pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" \
  --format=custom --compress=9 \
  -f "${BACKUP_PATH}/database.dump" \
  "$DB_NAME"
echo "  -> ${BACKUP_PATH}/database.dump ($(du -sh "${BACKUP_PATH}/database.dump" | cut -f1))"

# Screenshots
SCREENSHOT_DIR="${SCREENSHOT_DIR:-/var/rayyan-asm/screenshots}"
if [[ -d "$SCREENSHOT_DIR" ]]; then
  echo "Backing up screenshots..."
  tar -czf "${BACKUP_PATH}/screenshots.tar.gz" -C "$(dirname "$SCREENSHOT_DIR")" "$(basename "$SCREENSHOT_DIR")"
  echo "  -> ${BACKUP_PATH}/screenshots.tar.gz ($(du -sh "${BACKUP_PATH}/screenshots.tar.gz" | cut -f1))"
fi

# Create manifest
cat > "${BACKUP_PATH}/manifest.json" << JSON
{
  "timestamp": "${TIMESTAMP}",
  "version": "$(git describe --tags --always 2>/dev/null || echo 'unknown')",
  "files": ["database.dump", "screenshots.tar.gz"]
}
JSON

echo "=== Backup complete: ${BACKUP_PATH} ==="

# Rotate old backups (keep last 14)
find "$BACKUP_DIR" -maxdepth 1 -type d -name '20*' | sort | head -n -14 | xargs rm -rf
echo "Old backups rotated (keeping last 14 days)"
