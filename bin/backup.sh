#!/bin/bash
# BlackBox Automated Vault & Database Backup Script
# Run manually or via cron to create timestamped backups of qdb and encrypted vault files.

set -e

# Default paths derived from BLACKBOX_HOME if set, otherwise relative to script directory
ROOT_DIR="${BLACKBOX_HOME:-$(cd "$(dirname "$0")/.." && pwd)}"
DB_DIR="${BLACKBOX_DB_DIR:-$ROOT_DIR/kx/db/qdb}"
VAULT_DIR="${BLACKBOX_VAULT_DIR:-$ROOT_DIR/kx/db/vault}"
BACKUP_PARENT="${BLACKBOX_BACKUP_DIR:-$ROOT_DIR/backups}"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_TARGET="$BACKUP_PARENT/blackbox_backup_$TIMESTAMP"

echo "=== BlackBox Backup Utility ==="
echo "Source DB: $DB_DIR"
echo "Source Vault: $VAULT_DIR"
echo "Backup Destination: $BACKUP_TARGET"

mkdir -p "$BACKUP_TARGET"

if [ -d "$DB_DIR" ]; then
    echo "Copying database tables..."
    cp -r "$DB_DIR" "$BACKUP_TARGET/qdb"
else
    echo "Warning: Database directory $DB_DIR not found."
fi

if [ -d "$VAULT_DIR" ]; then
    echo "Copying encrypted vault blobs..."
    cp -r "$VAULT_DIR" "$BACKUP_TARGET/vault"
else
    echo "Warning: Vault directory $VAULT_DIR not found."
fi

echo "Creating compressed tarball archive..."
tar -czf "$BACKUP_TARGET.tar.gz" -C "$BACKUP_PARENT" "blackbox_backup_$TIMESTAMP"
rm -rf "$BACKUP_TARGET"

echo "Success! Backup saved to: $BACKUP_TARGET.tar.gz"

# Retention: an unattended backup script that never deletes anything just becomes the next
# full-disk incident (see the disk-space enforcement work elsewhere in this app) - keep the
# newest N and prune the rest. Override with BLACKBOX_BACKUP_KEEP; 0 disables pruning.
KEEP="${BLACKBOX_BACKUP_KEEP:-14}"
if [ "$KEEP" -gt 0 ]; then
    OLD=$(ls -1t "$BACKUP_PARENT"/blackbox_backup_*.tar.gz 2>/dev/null | tail -n +"$((KEEP + 1))")
    if [ -n "$OLD" ]; then
        echo "Pruning old backups beyond the newest $KEEP:"
        echo "$OLD" | while IFS= read -r f; do echo "  removing $f"; rm -f "$f"; done
    fi
fi
