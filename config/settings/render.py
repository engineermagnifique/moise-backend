# config/settings/render.py
from .base import *
import os
import dj_database_url

# Security settings for Render
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

# Database configuration for Render
DATABASES = {
    'default': dj_database_url.config(
        default=os.environ.get('DATABASE_URL'),
        conn_max_age=600,
        ssl_require=True
    )
}

# Allowed hosts for Render
RENDER_EXTERNAL_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME')
if RENDER_EXTERNAL_HOSTNAME:
    ALLOWED_HOSTS.append(RENDER_EXTERNAL_HOSTNAME)

# Security settings
if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

# Redis configuration for Render
redis_url = os.environ.get('REDIS_URL')
if redis_url:
    CACHES['default']['LOCATION'] = redis_url
    CELERY_BROKER_URL = redis_url
    CELERY_RESULT_BACKEND = redis_url
    CHANNEL_LAYERS['default']['CONFIG']['hosts'] = [redis_url]

# Elasticsearch - disable or use cloud service in production
ELASTICSEARCH_DSL = {
    'default': {
        'hosts': [os.environ.get('ELASTICSEARCH_URL', '')],
        'timeout': 30,
    },
}

# Disable debug toolbar
if 'debug_toolbar' in INSTALLED_APPS:
    INSTALLED_APPS.remove('debug_toolbar')
if 'debug_toolbar.middleware.DebugToolbarMiddleware' in MIDDLEWARE:
    MIDDLEWARE.remove('debug_toolbar.middleware.DebugToolbarMiddleware')

# CORS settings for Render
CORS_ALLOWED_ORIGINS = [
    "https://bizmap-rwanda.onrender.com",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# Static files
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATIC_URL = '/static/'

# Ensure staticfiles directory exists
os.makedirs(STATIC_ROOT, exist_ok=True)