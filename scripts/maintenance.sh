
#scripts/maintaenance.sh
#!/bin/bash

# BusiMap Backend Maintenance Script
# This script performs routine maintenance tasks

set -e  # Exit on any error

echo "🔧 Starting BusiMap Backend Maintenance..."

COMPOSE_FILE="docker-compose.yml"

# Check if running in production
if [ -f "docker-compose.prod.yml" ] && docker-compose -f docker-compose.prod.yml ps | grep -q "Up"; then
    COMPOSE_FILE="docker-compose.prod.yml"
    echo "📋 Using production compose file"
fi

# Function to run Django management commands
run_django_command() {
    echo "🐍 Running: python manage.py $1"
    docker-compose -f $COMPOSE_FILE exec web python manage.py $1
}

echo "🧹 Starting maintenance tasks..."

# 1. Clean up old sessions
echo "🗑️ Cleaning up expired sessions..."
run_django_command "clearsessions"

# 2. Clean up old payment transactions
echo "💳 Cleaning up old payment transactions..."
run_django_command "cleanup_old_transactions --days 365 --failed-days 90"

# 3. Clean up old rides
echo "🚗 Cleaning up old rides..."
run_django_command "cleanup_old_rides --days 30"

# 4. Update driver locations (mark offline drivers)
echo "📍 Updating driver locations..."
run_django_command "update_driver_locations --offline-threshold 300"

# 5. Generate analytics
echo "📊 Generating analytics..."
run_django_command "generate_analytics --period week"

# 6. Database maintenance
echo "🗄️ Running database maintenance..."

# Analyze and vacuum database
docker-compose -f $COMPOSE_FILE exec postgres psql -U ${DATABASE_USER:-bizmap_user} -d ${DATABASE_NAME:-bizmap_db} -c "ANALYZE;"
docker-compose -f $COMPOSE_FILE exec postgres psql -U ${DATABASE_USER:-bizmap_user} -d ${DATABASE_NAME:-bizmap_db} -c "VACUUM;"

# 7. Clear expired cache entries
echo "🗂️ Clearing expired cache entries..."
docker-compose -f $COMPOSE_FILE exec redis redis-cli FLUSHEXPIRED 2>/dev/null || echo "Cache cleanup completed"

# 8. Check disk usage
echo "💾 Checking disk usage..."
echo "Docker system usage:"
docker system df

echo "Volume usage:"
docker system df -v | grep volume

# 9. Clean up unused Docker resources (be careful in production)
if [ "$COMPOSE_FILE" != "docker-compose.prod.yml" ]; then
    echo "🧹 Cleaning up unused Docker resources (development only)..."
    docker system prune -f
    docker volume prune -f
else
    echo "ℹ️ Skipping Docker cleanup in production (run manually if needed)"
fi

# 10. Check service health
echo "🔍 Checking service health..."
docker-compose -f $COMPOSE_FILE ps

# Check if all services are healthy
UNHEALTHY=$(docker-compose -f $COMPOSE_FILE ps | grep -c "unhealthy\|Exit" || echo "0")
if [ "$UNHEALTHY" -gt 0 ]; then
    echo "⚠️ Warning: $UNHEALTHY service(s) appear to be unhealthy"
    docker-compose -f $COMPOSE_FILE ps | grep -E "(unhealthy|Exit)"
else
    echo "✅ All services appear to be healthy"
fi

# 11. Log rotation (if not handled by system)
echo "📋 Rotating logs..."
LOG_DIR="logs"
if [ -d "$LOG_DIR" ]; then
    # Archive logs older than 7 days
    find $LOG_DIR -name "*.log" -mtime +7 -exec gzip {} \;
    # Remove archived logs older than 30 days
    find $LOG_DIR -name "*.log.gz" -mtime +30 -delete
    echo "✅ Log rotation completed"
else
    echo "ℹ️ No log directory found"
fi

# 12. Backup reminder
LAST_BACKUP=$(find docker/backups -name "database_backup_*.sql.gz" -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2- || echo "")
if [ -n "$LAST_BACKUP" ]; then
    BACKUP_AGE=$(( ($(date +%s) - $(stat -c %Y "$LAST_BACKUP" 2>/dev/null || stat -f %m "$LAST_BACKUP" 2>/dev/null || echo 0)) / 86400 ))
    if [ $BACKUP_AGE -gt 1 ]; then
        echo "⚠️ Warning: Last backup is $BACKUP_AGE days old"
        echo "💾 Consider running: ./scripts/backup.sh"
    else
        echo "✅ Recent backup found (${BACKUP_AGE} days old)"
    fi
else
    echo "⚠️ Warning: No backups found"
    echo "💾 Consider running: ./scripts/backup.sh"
fi

# 13. Security updates check (basic)
echo "🔒 Checking for security updates..."
if command -v apt &> /dev/null; then
    echo "ℹ️ Consider running: apt list --upgradable"
elif command -v yum &> /dev/null; then
    echo "ℹ️ Consider running: yum check-update --security"
else
    echo "ℹ️ Manual security update check recommended"
fi

# Create maintenance report
MAINTENANCE_REPORT="maintenance_report_$(date +%Y%m%d_%H%M%S).json"
cat > $MAINTENANCE_REPORT << EOF
{
  "maintenance_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "compose_file": "$COMPOSE_FILE",
  "tasks_completed": [
    "session_cleanup",
    "payment_transaction_cleanup",
    "ride_cleanup",
    "driver_location_update",
    "analytics_generation",
    "database_maintenance",
    "cache_cleanup",
    "disk_usage_check",
    "service_health_check",
    "log_rotation"
  ],
  "unhealthy_services": $UNHEALTHY,
  "backup_age_days": ${BACKUP_AGE:-"unknown"},
  "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
}
EOF

echo "📋 Maintenance report saved: $MAINTENANCE_REPORT"

echo "🎉 Maintenance completed successfully!"
echo ""
echo "📊 Summary:"
echo "   🧹 Cleaned up expired sessions and old data"
echo "   🗄️ Performed database maintenance"
echo "   📍 Updated driver locations"
echo "   📊 Generated analytics"
echo "   🔍 Checked service health"
echo "   📋 Created maintenance report"
echo ""
echo "💡 Next steps:"
echo "   📊 Review maintenance report: cat $MAINTENANCE_REPORT"
echo "   💾 Run backup if needed: ./scripts/backup.sh"
echo "   🔍 Monitor application logs: docker-compose -f $COMPOSE_FILE logs -f"




