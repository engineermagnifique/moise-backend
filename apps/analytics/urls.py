# apps/analytics/urls.py
from django.urls import path
from . import views

app_name = 'analytics'

urlpatterns = [
    # Business Performance
    path('business-performance/', views.BusinessPerformanceView.as_view(), name='business-performance'),
    path('business-insights/', views.BusinessInsightsView.as_view(), name='business-insights'),
    
    # Market Intelligence
    path('market-intelligence/', views.MarketIntelligenceView.as_view(), name='market-intelligence'),
    path('market-trends/', views.MarketTrendsView.as_view(), name='market-trends'),
    
    # Search Analytics
    path('search-analytics/', views.SearchAnalyticsView.as_view(), name='search-analytics'),
    
    # User Behavior
    path('user-behavior/', views.UserBehaviorAnalyticsView.as_view(), name='user-behavior'),
]

