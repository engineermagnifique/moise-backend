
# scripts/restore
#!/bin/bash

# BusiMap Backend Restore Script
# This script restores the database and media files from backup

set -e  # Exit on any error

echo "🔄 Starting BusiMap Backend Restore..."

# Check if backup file is provided
if [ -z "$1" ]; then
    echo "❌ Error: Please provide backup date/identifier"
    echo "Usage: $0 <backup_date> [compose_file]"
    echo "Example: $0 20231201_143000"
    echo ""
    echo "Available backups:"
    ls -1 docker/backups/ | grep -E "(database_backup_|media_backup_)" | sort
    exit 1
fi

BACKUP_DATE=$1
BACKUP_DIR="docker/backups"
COMPOSE_FILE=${2:-docker-compose.yml}

# Load environment variables
if [ -f .env ]; then
    source .env
fi

DB_BACKUP_FILE="$BACKUP_DIR/database_backup_$BACKUP_DATE.sql.gz"
MEDIA_BACKUP_FILE="$BACKUP_DIR/media_backup_$BACKUP_DATE.tar.gz"

# Check if backup files exist
if [ ! -f "$DB_BACKUP_FILE" ]; then
    echo "❌ Error: Database backup file not found: $DB_BACKUP_FILE"
    exit 1
fi

echo "📋 Restore Configuration:"
echo "   Backup Date: $BACKUP_DATE"
echo "   Database Backup: $DB_BACKUP_FILE"
echo "   Media Backup: $MEDIA_BACKUP_FILE"
echo "   Compose File: $COMPOSE_FILE"
echo ""

# Confirmation prompt
read -p "⚠️  This will overwrite existing data. Are you sure? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Restore cancelled"
    exit 1
fi

# Stop application services (keep database running)
echo "🛑 Stopping application services..."
docker-compose -f $COMPOSE_FILE stop web celery_worker celery_beat

# Wait a moment for connections to close
sleep 5

echo "🗄️ Restoring database..."

# Drop existing database connections
docker-compose -f $COMPOSE_FILE exec postgres psql -U ${DATABASE_USER:-bizmap_user} -d postgres -c "
SELECT pg_terminate_backend(pg_stat_activity.pid)
FROM pg_stat_activity
WHERE pg_stat_activity.datname = '${DATABASE_NAME:-bizmap_db}'
  AND pid <> pg_backend_pid();"

# Drop and recreate database
docker-compose -f $COMPOSE_FILE exec postgres psql -U ${DATABASE_USER:-bizmap_user} -d postgres -c "DROP DATABASE IF EXISTS ${DATABASE_NAME:-bizmap_db};"
docker-compose -f $COMPOSE_FILE exec postgres psql -U ${DATABASE_USER:-bizmap_user} -d postgres -c "CREATE DATABASE ${DATABASE_NAME:-bizmap_db};"

# Restore database
gunzip -c $DB_BACKUP_FILE | docker-compose -f $COMPOSE_FILE exec -T postgres psql -U ${DATABASE_USER:-bizmap_user} -d ${DATABASE_NAME:-bizmap_db}

if [ $? -eq 0 ]; then
    echo "✅ Database restored successfully"
else
    echo "❌ Database restore failed!"
    exit 1
fi

# Restore media files if backup exists
if [ -f "$MEDIA_BACKUP_FILE" ]; then
    echo "📁 Restoring media files..."
    
    # Get media volume name
    MEDIA_VOLUME=$(docker volume ls -q | grep media | head -n1)
    
    if [ -n "$MEDIA_VOLUME" ]; then
        # Clear existing media files
        docker run --rm -v $MEDIA_VOLUME:/media alpine sh -c "rm -rf /media/*"
        
        # Restore media files
        docker run --rm -v $MEDIA_VOLUME:/media -v $(pwd)/$BACKUP_DIR:/backup alpine tar -xzf /backup/media_backup_$BACKUP_DATE.tar.gz -C /media
        
        if [ $? -eq 0 ]; then
            echo "✅ Media files restored successfully"
        else
            echo "⚠️ Media files restore failed"
        fi
    else
        echo "⚠️ No media volume found, skipping media restore"
    fi
else
    echo "ℹ️ No media backup found for $BACKUP_DATE, skipping media restore"
fi

# Start application services
echo "🚀 Starting application services..."
docker-compose -f $COMPOSE_FILE up -d

# Wait for application to be ready
echo "⏳ Waiting for application to start..."
sleep 20

# Health check
echo "🔍 Performing health check..."
max_attempts=10
attempt=1

while [ $attempt -le $max_attempts ]; do
    if curl -f http://localhost:8000/api/health/ >/dev/null 2>&1; then
        echo "✅ Application is healthy!"
        break
    fi
    
    if [ $attempt -eq $max_attempts ]; then
        echo "❌ Health check failed after $max_attempts attempts"
        docker-compose -f $COMPOSE_FILE logs web
        exit 1
    fi
    
    echo "⏳ Attempt $attempt/$max_attempts - waiting for application..."
    sleep 5
    ((attempt++))
done

# Create restore log
RESTORE_LOG="$BACKUP_DIR/restore_log_$(date +%Y%m%d_%H%M%S).json"
cat > $RESTORE_LOG << EOF
{
  "restore_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "backup_date": "$BACKUP_DATE",
  "database_backup": "$DB_BACKUP_FILE",
  "media_backup": "$MEDIA_BACKUP_FILE",
  "compose_file": "$COMPOSE_FILE",
  "status": "success"
}
EOF

echo "📋 Restore log created: $RESTORE_LOG"

echo "🎉 Restore completed successfully!"
echo "🌐 Application is available at: http://localhost:8000"




