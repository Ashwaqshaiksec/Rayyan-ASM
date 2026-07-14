#!/usr/bin/env bash
# Restore Rayyan ASM from a backup.
# Usage: ./scripts/restore.sh /var/backups/rayyan-asm/20240101-120000
set -euo pipefail

BACKUP_PATH="${1:?Usage: $0 <backup_path>}"

[[ -d "$BACKUP_PATH" ]] || { echo "Backup not found: $BACKUP_PATH"; exit 1; }

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-rayyan_asm}"
DB_USER="${DB_USER:-rayyan}"
PGPASSWORD="${DB_PASSWORD:-}"
SCREENSHOT_DIR="${SCREENSHOT_DIR:-/var/rayyan-asm/screenshots}"

echo "=== Rayyan ASM Restore from: ${BACKUP_PATH} ==="
echo "WARNING: This will overwrite the current database and screenshots."
read -r -p "Continue? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

# Restore database
echo "Restoring database..."
export PGPASSWORD
pg_restore -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" \
  --clean --if-exists --no-owner \
  -d "$DB_NAME" \
  "${BACKUP_PATH}/database.dump"
echo "  -> Database restored"

# Restore screenshots
if [[ -f "${BACKUP_PATH}/screenshots.tar.gz" ]]; then
  echo "Restoring screenshots..."
  rm -rf "$SCREENSHOT_DIR"
  tar -xzf "${BACKUP_PATH}/screenshots.tar.gz" -C "$(dirname "$SCREENSHOT_DIR")"
  echo "  -> Screenshots restored"
fi

echo "=== Restore complete ==="
