# apps/search/urls.py
from django.urls import path, include
from . import views

app_name = "search"

urlpatterns = [
    # Intelligent search
    path(
        "intelligent/", views.IntelligentSearchView.as_view(), name="intelligent-search"
    ),
    # Quick search for autocomplete
    path("quick-search/", views.QuickSearchView.as_view(), name="quick-search"),
    # Advanced search
    path(
        "advanced-search/", views.AdvancedSearchView.as_view(), name="advanced-search"
    ),
    # Search suggestions
    path(
        "suggestions/",
        views.AISearchSuggestionsView.as_view(),
        name="search-suggestions",
    ),
    # Autocomplete
    path(
        "autocomplete/",
        views.SearchAutocompleteView.as_view(),
        name="search-autocomplete",
    ),
    # Category search
    path(
        "categories/<str:category>/",
        views.SearchByCategoryView.as_view(),
        name="search-by-category",
    ),
    # Location-based search
    path("nearby/", views.NearbyBusinessSearchView.as_view(), name="nearby-search"),
    # Trending searches
    path("trending/", views.TrendingSearchesView.as_view(), name="trending-searches"),
    # Search analytics
    path("stats/", views.SearchStatsView.as_view(), name="search-stats"),
    # Save searches
    path("saved/", views.SavedSearchView.as_view(), name="saved-searches"),
    path(
        "saved/<uuid:search_id>/",
        views.SavedSearchDetailView.as_view(),
        name="saved-search-detail",
    ),
    # Additional frontend expected endpoints
    path("history/", views.SearchHistoryView.as_view(), name="search-history"),
    path("save-search/", views.SaveSearchView.as_view(), name="save-search"),
    path("radius-search/", views.RadiusSearchView.as_view(), name="radius-search"),
    path("filters/", views.SearchFiltersView.as_view(), name="search-filters"),
]
