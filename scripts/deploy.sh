
#scripts/deploy.sh
#!/bin/bash

# BusiMap Backend Deployment Script
# This script handles the deployment of the BusiMap backend application

set -e  # Exit on any error

echo "🚀 Starting BusiMap Backend Deployment..."

# Configuration
ENVIRONMENT=${1:-development}
DOCKER_COMPOSE_FILE="docker-compose.yml"

if [ "$ENVIRONMENT" = "production" ]; then
    DOCKER_COMPOSE_FILE="docker-compose.prod.yml"
fi

echo "📦 Environment: $ENVIRONMENT"
echo "📋 Using compose file: $DOCKER_COMPOSE_FILE"

# Check if .env file exists
if [ ! -f .env ]; then
    echo "❌ Error: .env file not found!"
    echo "📝 Please copy env.example to .env and configure your environment variables."
    exit 1
fi

# Load environment variables
source .env

# Validate required environment variables
required_vars=("SECRET_KEY" "DATABASE_PASSWORD" "REDIS_PASSWORD")
for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        echo "❌ Error: $var is not set in .env file"
        exit 1
    fi
done

echo "✅ Environment variables validated"

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p logs
mkdir -p docker/ssl
mkdir -p docker/backups

# Stop existing containers
echo "🛑 Stopping existing containers..."
docker-compose -f $DOCKER_COMPOSE_FILE down --remove-orphans

# Pull latest images
echo "📥 Pulling latest images..."
docker-compose -f $DOCKER_COMPOSE_FILE pull

# Build application image
echo "🔨 Building application image..."
docker-compose -f $DOCKER_COMPOSE_FILE build --no-cache web

# Start database and cache services first
echo "🗄️ Starting database and cache services..."
docker-compose -f $DOCKER_COMPOSE_FILE up -d postgres redis elasticsearch

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 30

# Check service health
echo "🔍 Checking service health..."
docker-compose -f $DOCKER_COMPOSE_FILE exec postgres pg_isready -U ${DATABASE_USER:-bizmap_user}
docker-compose -f $DOCKER_COMPOSE_FILE exec redis redis-cli ping

# Run database migrations
echo "🗃️ Running database migrations..."
docker-compose -f $DOCKER_COMPOSE_FILE run --rm web python manage.py migrate

# Create superuser if it doesn't exist (only in development)
if [ "$ENVIRONMENT" = "development" ]; then
    echo "👤 Creating superuser (development only)..."
    docker-compose -f $DOCKER_COMPOSE_FILE run --rm web python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(email='admin@busimap.rw').exists():
    User.objects.create_superuser('admin@busimap.rw', 'admin123', first_name='Admin', last_name='User')
    print('Superuser created: admin@busimap.rw / admin123')
else:
    print('Superuser already exists')
"
fi

# Load initial data
echo "📊 Loading initial data..."
docker-compose -f $DOCKER_COMPOSE_FILE run --rm web python manage.py setup_payment_methods

# Collect static files
echo "📦 Collecting static files..."
docker-compose -f $DOCKER_COMPOSE_FILE run --rm web python manage.py collectstatic --noinput

# Start all services
echo "🚀 Starting all services..."
docker-compose -f $DOCKER_COMPOSE_FILE up -d

# Wait for application to be ready
echo "⏳ Waiting for application to start..."
sleep 20

# Health check
echo "🔍 Performing health check..."
max_attempts=30
attempt=1

while [ $attempt -le $max_attempts ]; do
    if curl -f http://localhost:8000/api/health/ >/dev/null 2>&1; then
        echo "✅ Application is healthy!"
        break
    fi
    
    if [ $attempt -eq $max_attempts ]; then
        echo "❌ Health check failed after $max_attempts attempts"
        echo "📋 Container logs:"
        docker-compose -f $DOCKER_COMPOSE_FILE logs web
        exit 1
    fi
    
    echo "⏳ Attempt $attempt/$max_attempts - waiting for application..."
    sleep 5
    ((attempt++))
done

# Display service status
echo "📊 Service Status:"
docker-compose -f $DOCKER_COMPOSE_FILE ps

# Display useful information
echo ""
echo "🎉 Deployment completed successfully!"
echo ""
echo "📋 Service URLs:"
echo "   🌐 API: http://localhost:8000"
echo "   📚 API Docs: http://localhost:8000/api/docs/"
echo "   🔧 Admin: http://localhost:8000/admin/"
if [ "$ENVIRONMENT" = "development" ]; then
    echo "   👤 Admin Login: admin@busimap.rw / admin123"
fi
echo ""
echo "🔧 Management Commands:"
echo "   📊 View logs: docker-compose -f $DOCKER_COMPOSE_FILE logs -f"
echo "   🛑 Stop services: docker-compose -f $DOCKER_COMPOSE_FILE down"
echo "   🔄 Restart: docker-compose -f $DOCKER_COMPOSE_FILE restart"
echo "   📝 Django shell: docker-compose -f $DOCKER_COMPOSE_FILE exec web python manage.py shell"
echo ""

# Save deployment info
echo "{
  \"deployment_time\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
  \"environment\": \"$ENVIRONMENT\",
  \"compose_file\": \"$DOCKER_COMPOSE_FILE\",
  \"git_commit\": \"$(git rev-parse HEAD 2>/dev/null || echo 'unknown')\",
  \"git_branch\": \"$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')\"
}" > deployment-info.json

echo "💾 Deployment info saved to deployment-info.json"
echo "✨ BusiMap Backend is now running!"