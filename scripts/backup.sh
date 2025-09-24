
#scripts/backup
#!/bin/bash

# BusiMap Backend Backup Script
# This script creates backups of the database and media files

set -e  # Exit on any error

echo "💾 Starting BusiMap Backend Backup..."

# Configuration
BACKUP_DIR="docker/backups"
DATE=$(date +%Y%m%d_%H%M%S)
COMPOSE_FILE="docker-compose.yml"

# Check if running in production
if [ -f "docker-compose.prod.yml" ] && docker-compose -f docker-compose.prod.yml ps | grep -q "Up"; then
    COMPOSE_FILE="docker-compose.prod.yml"
    echo "📋 Using production compose file"
fi

# Load environment variables
if [ -f .env ]; then
    source .env
fi

# Create backup directory
mkdir -p $BACKUP_DIR

echo "🗄️ Backing up PostgreSQL database..."

# Database backup
DB_BACKUP_FILE="$BACKUP_DIR/database_backup_$DATE.sql"
docker-compose -f $COMPOSE_FILE exec -T postgres pg_dump -U ${DATABASE_USER:-bizmap_user} ${DATABASE_NAME:-bizmap_db} > $DB_BACKUP_FILE

if [ $? -eq 0 ]; then
    echo "✅ Database backup created: $DB_BACKUP_FILE"
    
    # Compress the backup
    gzip $DB_BACKUP_FILE
    echo "🗜️ Database backup compressed: $DB_BACKUP_FILE.gz"
else
    echo "❌ Database backup failed!"
    exit 1
fi

echo "📁 Backing up media files..."

# Media files backup
MEDIA_BACKUP_FILE="$BACKUP_DIR/media_backup_$DATE.tar.gz"
if docker volume ls | grep -q media; then
    docker run --rm -v $(docker volume ls -q | grep media):/media -v $(pwd)/$BACKUP_DIR:/backup alpine tar -czf /backup/media_backup_$DATE.tar.gz -C /media .
    if [ $? -eq 0 ]; then
        echo "✅ Media files backup created: $MEDIA_BACKUP_FILE"
    else
        echo "⚠️ Media files backup failed or no media files found"
    fi
else
    echo "ℹ️ No media volume found, skipping media backup"
fi

echo "🧹 Cleaning up old backups (keeping last 7 days)..."

# Clean up old backups (keep last 7 days)
find $BACKUP_DIR -name "database_backup_*.sql.gz" -mtime +7 -delete
find $BACKUP_DIR -name "media_backup_*.tar.gz" -mtime +7 -delete

# Create backup manifest
echo "📋 Creating backup manifest..."
MANIFEST_FILE="$BACKUP_DIR/backup_manifest_$DATE.json"
cat > $MANIFEST_FILE << EOF
{
  "backup_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "database_backup": "database_backup_$DATE.sql.gz",
  "media_backup": "media_backup_$DATE.tar.gz",
  "database_size": "$(stat -f%z $BACKUP_DIR/database_backup_$DATE.sql.gz 2>/dev/null || stat -c%s $BACKUP_DIR/database_backup_$DATE.sql.gz 2>/dev/null || echo 'unknown')",
  "media_size": "$(stat -f%z $MEDIA_BACKUP_FILE 2>/dev/null || stat -c%s $MEDIA_BACKUP_FILE 2>/dev/null || echo 'unknown')",
  "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
  "environment": "${ENVIRONMENT:-development}"
}
EOF

echo "✅ Backup manifest created: $MANIFEST_FILE"

# List current backups
echo "📊 Current backups:"
ls -lh $BACKUP_DIR/

echo "🎉 Backup completed successfully!"
echo "💾 Backup location: $BACKUP_DIR"
echo ""
echo "🔄 To restore from backup:"
echo "   Database: gunzip -c $BACKUP_DIR/database_backup_$DATE.sql.gz | docker-compose -f $COMPOSE_FILE exec -T postgres psql -U \${DATABASE_USER} \${DATABASE_NAME}"
echo "   Media: docker run --rm -v \$(docker volume ls -q | grep media):/media -v \$(pwd)/$BACKUP_DIR:/backup alpine tar -xzf /backup/media_backup_$DATE.tar.gz -C /media"




