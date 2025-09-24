# config/settings/base.py
import os
import environ
from pathlib import Path

# Build paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Environment variables
env = environ.Env(
    DEBUG=(bool, True),  # Default to True for development
    SECRET_KEY=(str, 'dev-secret-key-change-in-production'),
    ALLOWED_HOSTS=(list, ['localhost', '127.0.0.1', '0.0.0.0']),
)

# Read .env file if it exists
env_file = os.path.join(BASE_DIR, '.env')
if os.path.exists(env_file):
    environ.Env.read_env(env_file)

# Security
SECRET_KEY = env('SECRET_KEY')
DEBUG = env('DEBUG')
ALLOWED_HOSTS = env('ALLOWED_HOSTS')

# Application definition
DJANGO_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    #'django.contrib.gis',
]

THIRD_PARTY_APPS = [
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'drf_spectacular',
    'django_elasticsearch_dsl',
    'channels',
    'django_filters',
]

LOCAL_APPS = [
    'apps.authentication',
    'apps.businesses',
    'apps.ai_engine',
    'apps.locations',
    'apps.search',
    'apps.analytics',
    'apps.payments',
    'apps.transportation',
    'apps.common',
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.locale.LocaleMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'
ASGI_APPLICATION = 'config.asgi.application'

STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"


# Database
DATABASES = {
    'default': env.db('DATABASE_URL', default='postgresql://postgres:simplepass@localhost:5432/busimap_rwanda')
}

# Cache
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('REDIS_URL'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Custom User Model
AUTH_USER_MODEL = 'authentication.User'

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Africa/Kigali'
USE_I18N = True
USE_TZ = True

# Supported languages
LANGUAGES = [
    ('en', 'English'),
    ('rw', 'Kinyarwanda'),
    ('fr', 'Français'),
]

LOCALE_PATHS = [
    BASE_DIR / 'locale',
]

# Static files and media
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'static'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# REST Framework configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.MultiPartParser',
        'rest_framework.parsers.FileUploadParser',
    ],
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_PAGINATION_CLASS': 'apps.common.pagination.CustomPageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'EXCEPTION_HANDLER': 'apps.common.exceptions.custom_exception_handler',
}

# JWT Configuration
from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=24),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=30),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
}

# CORS Configuration
CORS_ALLOW_ALL_ORIGINS = DEBUG
CORS_ALLOWED_ORIGINS = env.list('CORS_ALLOWED_ORIGINS', default=[])
CORS_ALLOW_CREDENTIALS = True

# DRF Spectacular (API Documentation)
SPECTACULAR_SETTINGS = {
    'TITLE': 'BusiMap Rwanda API',
    'DESCRIPTION': 'AI-Powered Business Discovery Platform for Rwanda',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'COMPONENT_SPLIT_REQUEST': True,
    'TAGS': [
        {'name': 'Authentication', 'description': 'User authentication endpoints'},
        {'name': 'Businesses', 'description': 'Business management endpoints'},
        {'name': 'AI & Intelligence', 'description': 'AI-powered features'},
        {'name': 'Search', 'description': 'Intelligent search endpoints'},
        {'name': 'Locations', 'description': 'Location and mapping services'},
        {'name': 'Analytics', 'description': 'Business analytics and insights'},
        {'name': 'Payments', 'description': 'Payment processing'},
        {'name': 'Transportation', 'description': 'Transport and mobility services'},
    ],
    'EXTERNAL_DOCS': {
        'description': 'BusiMap Rwanda Documentation',
        'url': 'https://docs.busimap.rw',
    },
    'CONTACT': {
        'name': 'BusiMap Rwanda Support',
        'email': 'support@busimap.rw',
    },
}

# Elasticsearch Configuration
ELASTICSEARCH_DSL = {
    'default': {
        'hosts': env('ELASTICSEARCH_URL', default='http://localhost:9200')
    },
}

# Celery Configuration
CELERY_BROKER_URL = env('REDIS_URL')
CELERY_RESULT_BACKEND = env('REDIS_URL')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE


# Email Configuration 
EMAIL_BACKEND = env('EMAIL_BACKEND', default='django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = env('EMAIL_HOST', default='')
EMAIL_PORT = env.int('EMAIL_PORT', default=587)
EMAIL_USE_TLS = env.bool('EMAIL_USE_TLS', default=True)
EMAIL_HOST_USER = env('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL', default='noreply@localhost')

# Frontend URL - CRITICAL!
FRONTEND_URL = env('FRONTEND_URL', default='http://localhost:3000')

# SMS Configuration
TWILIO_ACCOUNT_SID = env('TWILIO_ACCOUNT_SID', default='')
TWILIO_AUTH_TOKEN = env('TWILIO_AUTH_TOKEN', default='')
TWILIO_PHONE_NUMBER = env('TWILIO_PHONE_NUMBER', default='')

# Channels Configuration (WebSocket)
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [env('REDIS_URL')],
        },
    },
}

 # Ensure logs directory exists
log_dir = BASE_DIR / 'logs'
log_dir.mkdir(exist_ok=True)

# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'django.log',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': env('LOG_LEVEL', default='INFO'),
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': env('LOG_LEVEL', default='INFO'),
            'propagate': False,
        },
        'apps': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}

# BusiMap Rwanda Specific Settings
BUSIMAP_SETTINGS = {
    'SUPPORTED_LANGUAGES': ['en', 'rw', 'fr'],
    'DEFAULT_LANGUAGE': 'en',
    'RWANDA_PROVINCES': ['Kigali', 'Eastern', 'Western', 'Northern', 'Southern'],
    'MAX_SEARCH_RADIUS_KM': 50,
    'DEFAULT_SEARCH_RADIUS_KM': 5,
    'AI_CONVERSATION_TIMEOUT_MINUTES': 30,
    'MAX_CONVERSATION_HISTORY': 20,
    'BUSINESS_VERIFICATION_REQUIRED': True,
    'ENABLE_REAL_TIME_CHAT': True,
    'ENABLE_VOICE_FEATURES': True,
    'MAX_IMAGE_UPLOAD_SIZE_MB': 10,
    'SUPPORTED_PAYMENT_METHODS': ['mtn_momo', 'airtel_money', 'tigo_cash'],
}

# Mobile Money Configuration
MOBILE_MONEY_SETTINGS = {
    'MTN_MOMO': {
        'API_KEY': env('MTN_MOMO_API_KEY', default=''),
        'API_SECRET': env('MTN_MOMO_API_SECRET', default=''),
        'CALLBACK_URL': env('MTN_MOMO_CALLBACK_URL', default=''),
    },
    'AIRTEL_MONEY': {
        'API_KEY': env('AIRTEL_MONEY_API_KEY', default=''),
        'API_SECRET': env('AIRTEL_MONEY_API_SECRET', default=''),
        'CALLBACK_URL': env('AIRTEL_MONEY_CALLBACK_URL', default=''),
    },
}
