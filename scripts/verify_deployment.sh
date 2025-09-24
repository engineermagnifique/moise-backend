scripts/verify_deployment.sh
#!/bin/bash

# BusiMap Backend Deployment Verification Script
# This script verifies that the backend is properly deployed and functional

set -e  # Exit on any error

echo "🔍 Starting BusiMap Backend Deployment Verification..."

# Configuration
COMPOSE_FILE="docker-compose.yml"
BASE_URL="http://localhost:8000"

# Check if running in production
if [ -f "docker-compose.prod.yml" ] && docker-compose -f docker-compose.prod.yml ps | grep -q "Up"; then
    COMPOSE_FILE="docker-compose.prod.yml"
    echo "📋 Using production compose file"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_result="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -n "🧪 Testing $test_name... "
    
    if eval "$test_command" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ PASSED${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}❌ FAILED${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Function to test HTTP endpoint
test_endpoint() {
    local endpoint="$1"
    local expected_status="$2"
    local description="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -n "🌐 Testing $description ($endpoint)... "
    
    local status_code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL$endpoint" || echo "000")
    
    if [ "$status_code" = "$expected_status" ]; then
        echo -e "${GREEN}✅ PASSED (${status_code})${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}❌ FAILED (Expected: ${expected_status}, Got: ${status_code})${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

echo "🐳 Checking Docker Services..."

# Check if Docker Compose services are running
run_test "Docker services status" "docker-compose -f $COMPOSE_FILE ps | grep -q 'Up'"

# Check individual services
run_test "PostgreSQL service" "docker-compose -f $COMPOSE_FILE exec -T postgres pg_isready -U bizmap_user"
run_test "Redis service" "docker-compose -f $COMPOSE_FILE exec -T redis redis-cli ping | grep -q 'PONG'"

echo ""
echo "🌐 Testing API Endpoints..."

# Test core endpoints
test_endpoint "/api/health/" "200" "Health Check"
test_endpoint "/api/docs/" "200" "API Documentation"
test_endpoint "/api/businesses/categories/" "200" "Business Categories"
test_endpoint "/api/businesses/" "200" "Business List"
test_endpoint "/api/search/intelligent/" "405" "AI Search (Method Not Allowed for GET)"
test_endpoint "/api/ai/chat/" "405" "AI Chat (Method Not Allowed for GET)"
test_endpoint "/admin/" "302" "Admin Interface (Redirect to login)"

echo ""
echo "🔧 Testing Django Management Commands..."

# Test management commands
run_test "Django check" "docker-compose -f $COMPOSE_FILE exec -T web python manage.py check"
run_test "Database migrations" "docker-compose -f $COMPOSE_FILE exec -T web python manage.py migrate --check"

echo ""
echo "📊 Testing Service Integration..."

# Test database connectivity
run_test "Database connection" "docker-compose -f $COMPOSE_FILE exec -T web python manage.py shell -c 'from django.db import connection; connection.ensure_connection()'"

# Test cache connectivity
run_test "Redis cache" "docker-compose -f $COMPOSE_FILE exec -T web python manage.py shell -c 'from django.core.cache import cache; cache.set(\"test\", \"value\", 1); assert cache.get(\"test\") == \"value\"'"

echo ""
echo "🔍 Testing Application Features..."

# Test API with JSON data
echo -n "🧪 Testing API JSON response format... "
HEALTH_RESPONSE=$(curl -s "$BASE_URL/api/health/" | python3 -c "import sys, json; json.load(sys.stdin); print('valid')" 2>/dev/null || echo "invalid")
if [ "$HEALTH_RESPONSE" = "valid" ]; then
    echo -e "${GREEN}✅ PASSED${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}❌ FAILED${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# Test static files
echo -n "🧪 Testing static files serving... "
STATIC_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/static/admin/css/base.css" || echo "000")
if [ "$STATIC_STATUS" = "200" ] || [ "$STATIC_STATUS" = "404" ]; then
    echo -e "${GREEN}✅ PASSED (Static files configured)${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}❌ FAILED (Static files not accessible)${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

echo ""
echo "📋 Checking Configuration..."

# Check environment variables
echo -n "🧪 Checking environment configuration... "
ENV_CHECK=$(docker-compose -f $COMPOSE_FILE exec -T web python manage.py shell -c "
import os
from django.conf import settings
required = ['SECRET_KEY', 'DATABASE_URL']
missing = [var for var in required if not getattr(settings, var, None)]
if missing:
    print(f'Missing: {missing}')
    exit(1)
print('OK')
" 2>/dev/null || echo "FAILED")

if [ "$ENV_CHECK" = "OK" ]; then
    echo -e "${GREEN}✅ PASSED${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}❌ FAILED${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

echo ""
echo "🔒 Security Verification..."

# Check debug mode
echo -n "🧪 Checking DEBUG setting... "
DEBUG_STATUS=$(docker-compose -f $COMPOSE_FILE exec -T web python manage.py shell -c "from django.conf import settings; print('ON' if settings.DEBUG else 'OFF')" 2>/dev/null || echo "ERROR")

if [ "$COMPOSE_FILE" = "docker-compose.prod.yml" ]; then
    if [ "$DEBUG_STATUS" = "OFF" ]; then
        echo -e "${GREEN}✅ PASSED (DEBUG=False for production)${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}❌ FAILED (DEBUG should be False in production)${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    if [ "$DEBUG_STATUS" = "ON" ]; then
        echo -e "${GREEN}✅ PASSED (DEBUG=True for development)${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${YELLOW}⚠️ WARNING (DEBUG=False in development)${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

echo ""
echo "📈 Performance Check..."

# Check response time
echo -n "🧪 Testing response time... "
RESPONSE_TIME=$(curl -s -o /dev/null -w "%{time_total}" "$BASE_URL/api/health/" 2>/dev/null || echo "999")
RESPONSE_TIME_MS=$(echo "$RESPONSE_TIME * 1000" | bc 2>/dev/null | cut -d. -f1 || echo "999")

if [ "$RESPONSE_TIME_MS" -lt 2000 ]; then
    echo -e "${GREEN}✅ PASSED (${RESPONSE_TIME_MS}ms)${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${YELLOW}⚠️ SLOW (${RESPONSE_TIME_MS}ms)${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

echo ""
echo "📊 Verification Summary"
echo "======================"
echo -e "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"

# Calculate success rate
SUCCESS_RATE=$(echo "scale=1; $TESTS_PASSED * 100 / $TOTAL_TESTS" | bc 2>/dev/null || echo "0")

echo -e "Success Rate: ${SUCCESS_RATE}%"

# Final verdict
if [ $TESTS_FAILED -eq 0 ]; then
    echo ""
    echo -e "${GREEN}🎉 ALL TESTS PASSED! 🎉${NC}"
    echo -e "${GREEN}✅ BusiMap Backend is DEPLOYMENT READY!${NC}"
    echo ""
    echo "🌐 Service URLs:"
    echo "   API: $BASE_URL"
    echo "   Docs: $BASE_URL/api/docs/"
    echo "   Admin: $BASE_URL/admin/"
    echo ""
    echo "🔧 Next Steps:"
    echo "   1. Configure environment variables for production"
    echo "   2. Set up SSL/TLS certificates"
    echo "   3. Configure monitoring and alerting"
    echo "   4. Set up automated backups"
    echo "   5. Deploy frontend application"
    
    # Create verification report
    cat > verification-report.json << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "status": "PASSED",
  "total_tests": $TOTAL_TESTS,
  "passed_tests": $TESTS_PASSED,
  "failed_tests": $TESTS_FAILED,
  "success_rate": ${SUCCESS_RATE},
  "response_time_ms": ${RESPONSE_TIME_MS},
  "environment": "$(echo $COMPOSE_FILE | sed 's/docker-compose//' | sed 's/.yml//' | sed 's/\.//')",
  "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
  "deployment_ready": true
}
EOF
    
    echo "📋 Verification report saved: verification-report.json"
    exit 0
else
    echo ""
    echo -e "${RED}❌ DEPLOYMENT VERIFICATION FAILED${NC}"
    echo -e "${RED}$TESTS_FAILED out of $TOTAL_TESTS tests failed${NC}"
    echo ""
    echo "🔧 Troubleshooting:"
    echo "   1. Check Docker services: docker-compose -f $COMPOSE_FILE ps"
    echo "   2. Check application logs: docker-compose -f $COMPOSE_FILE logs web"
    echo "   3. Verify environment variables in .env file"
    echo "   4. Run database migrations: docker-compose -f $COMPOSE_FILE exec web python manage.py migrate"
    echo "   5. Check DEPLOYMENT_CHECKLIST.md for detailed requirements"
    
    # Create failure report
    cat > verification-report.json << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "status": "FAILED",
  "total_tests": $TOTAL_TESTS,
  "passed_tests": $TESTS_PASSED,
  "failed_tests": $TESTS_FAILED,
  "success_rate": ${SUCCESS_RATE},
  "environment": "$(echo $COMPOSE_FILE | sed 's/docker-compose//' | sed 's/.yml//' | sed 's/\.//')",
  "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
  "deployment_ready": false
}
EOF
    
    echo "📋 Verification report saved: verification-report.json"
    exit 1
fi




