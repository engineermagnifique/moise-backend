
# config/urls.py
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
    SpectacularRedocView,
)
from apps.common.views import health_check

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Health Check
    path('api/health/', health_check, name='health-check'),
    
    # API Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    
    # API Endpoints
    path('api/auth/', include('apps.authentication.urls')),
    path('api/businesses/', include('apps.businesses.urls')),
    path('api/ai/', include('apps.ai_engine.urls')),
    path('api/search/', include('apps.search.urls')),
    path('api/location/', include('apps.locations.urls')),
    path('api/analytics/', include('apps.analytics.urls')),
    path('api/payments/', include('apps.payments.urls')),
    path('api/transport/', include('apps.transportation.urls')),
]

# Static and media files
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    
    # Debug toolbar
    if 'debug_toolbar' in settings.INSTALLED_APPS:
        import debug_toolbar
        urlpatterns = [path('__debug__/', include(debug_toolbar.urls))] + urlpatterns
