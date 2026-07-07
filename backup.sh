#!/bin/bash
BACKUP_DIR=/opt/dustforge/backups
DB=/opt/dustforge/data/dustforge.db
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# SQLite safe backup
sqlite3 "$DB" ".backup $BACKUP_DIR/dustforge_$TIMESTAMP.db"

# Also backup .env (contains IDENTITY_MASTER_KEY)
cp /opt/dustforge/.env "$BACKUP_DIR/env_$TIMESTAMP.bak"

# Keep only last 14 days of backups
find "$BACKUP_DIR" -name "dustforge_*.db" -mtime +14 -delete
find "$BACKUP_DIR" -name "env_*.bak" -mtime +14 -delete

echo "[$(date)] Backup complete: dustforge_$TIMESTAMP.db"
