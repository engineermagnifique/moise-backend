# config/celery.py
import os
from celery import Celery
from django.conf import settings

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')

app = Celery('busimap_rwanda')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

# Celery beat schedule for periodic tasks
app.conf.beat_schedule = {
    'update-business-analytics': {
        'task': 'apps.analytics.tasks.update_business_analytics',
        'schedule': 3600.0,  # Run every hour
    },
    'update-search-trends': {
        'task': 'apps.search.tasks.update_search_trends',
        'schedule': 86400.0,  # Run daily
    },
    'clean-expired-sessions': {
        'task': 'apps.ai_engine.tasks.clean_expired_conversations',
        'schedule': 21600.0,  # Run every 6 hours
    },
}

app.conf.timezone = 'Africa/Kigali'

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')