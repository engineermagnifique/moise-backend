# apps/common/views.py
import logging
from django.http import JsonResponse
from django.db import connection
from django.core.cache import cache
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.conf import settings
import redis
import requests

logger = logging.getLogger(__name__)

@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    Health check endpoint to verify system status
    """
    health_status = {
        'status': 'healthy',
        'timestamp': timezone.now().isoformat(),
        'version': getattr(settings, 'API_VERSION', '1.0'),
        'services': {}
    }
    
    overall_healthy = True
    
    # Check database connection
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            health_status['services']['database'] = {
                'status': 'healthy',
                'response_time_ms': 0  # Could add timing if needed
            }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        health_status['services']['database'] = {
            'status': 'unhealthy',
            'error': str(e)
        }
        overall_healthy = False
    
    # Check Redis connection
    try:
        cache_key = 'health_check_test'
        cache.set(cache_key, 'test', timeout=10)
        cache_value = cache.get(cache_key)
        
        if cache_value == 'test':
            health_status['services']['redis'] = {
                'status': 'healthy'
            }
        else:
            raise Exception("Cache value mismatch")
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        health_status['services']['redis'] = {
            'status': 'unhealthy',
            'error': str(e)
        }
        overall_healthy = False
    
    # Check Elasticsearch connection (if configured)
    elasticsearch_url = getattr(settings, 'ELASTICSEARCH_URL', None)
    if elasticsearch_url:
        try:
            response = requests.get(f"{elasticsearch_url}/_cluster/health", timeout=5)
            if response.status_code == 200:
                health_status['services']['elasticsearch'] = {
                    'status': 'healthy'
                }
            else:
                raise Exception(f"HTTP {response.status_code}")
        except Exception as e:
            logger.error(f"Elasticsearch health check failed: {e}")
            health_status['services']['elasticsearch'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            overall_healthy = False
    
    # Set overall status
    if not overall_healthy:
        health_status['status'] = 'unhealthy'
        return JsonResponse(health_status, status=status.HTTP_503_SERVICE_UNAVAILABLE)
    
    return JsonResponse(health_status, status=status.HTTP_200_OK)




