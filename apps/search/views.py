# apps/search/views.py
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, extend_schema_view
from django.db.models import Q, Count, Avg
from django.utils import timezone
from datetime import timedelta

from .models import SearchQuery, PopularSearch
from .serializers import (
    SearchQuerySerializer, PopularSearchSerializer,
    IntelligentSearchSerializer, QuickSearchSerializer,
    AdvancedSearchSerializer, SearchSuggestionSerializer
)
from .services.intelligent_search import IntelligentSearchService
from .services.search_analytics import SearchAnalyticsService
from apps.businesses.models import Business, BusinessCategory

@extend_schema_view(
    post=extend_schema(
        summary="Intelligent Search",
        description="AI-powered intelligent search with context understanding",
        tags=["Search"]
    )
)
class IntelligentSearchView(generics.GenericAPIView):
    """Intelligent search endpoint"""
    
    serializer_class = IntelligentSearchSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """Perform intelligent search"""
        try:
            query = request.data.get('query', '')
            language = request.data.get('language', 'en')
            location = request.data.get('location')
            filters = request.data.get('filters', {})
            sort_by = request.data.get('sort_by', 'relevance')
            page = request.data.get('page', 1)
            
            # Log search query
            search_query = SearchQuery.objects.create(
                user=request.user if request.user.is_authenticated else None,
                query_text=query,
                original_language=language,
                user_location=location,
                search_filters=filters,
                search_type='intelligent'
            )
            
            # Perform intelligent search
            search_service = IntelligentSearchService()
            results = search_service.search(
                query=query,
                language=language,
                location=location,
                filters=filters,
                sort_by=sort_by,
                page=page
            )
            
            # Update search query with results
            search_query.results_count = len(results.get('results', []))
            search_query.save()
            
            return Response({
                'success': True,
                'data': results
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'search_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    post=extend_schema(
        summary="Quick Search",
        description="Fast search for autocomplete and suggestions",
        tags=["Search"]
    )
)
class QuickSearchView(generics.GenericAPIView):
    """Quick search endpoint"""
    
    serializer_class = QuickSearchSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """Perform quick search"""
        try:
            query = request.data.get('query', '')
            limit = request.data.get('limit', 10)
            
            # Simple quick search implementation
            businesses = Business.objects.filter(
                Q(business_name__icontains=query) |
                Q(description__icontains=query) |
                Q(category__name__icontains=query),
                is_active=True
            )[:limit]
            
            results = []
            for business in businesses:
                results.append({
                    'business_id': str(business.business_id),
                    'business_name': business.business_name,
                    'category': business.category.name if business.category else '',
                    'address': business.address,
                    'rating': business.average_rating
                })
            
            return Response({
                'success': True,
                'data': {
                    'results': results,
                    'query': query,
                    'total_found': len(results)
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'quick_search_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    post=extend_schema(
        summary="Advanced Search",
        description="Advanced search with multiple filters and criteria",
        tags=["Search"]
    )
)
class AdvancedSearchView(generics.GenericAPIView):
    """Advanced search endpoint"""
    
    serializer_class = AdvancedSearchSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """Perform advanced search"""
        try:
            query = request.data.get('query', '')
            category = request.data.get('category')
            location = request.data.get('location')
            price_range = request.data.get('price_range')
            rating_min = request.data.get('rating_min')
            amenities = request.data.get('amenities', [])
            distance_km = request.data.get('distance_km', 10)
            sort_by = request.data.get('sort_by', 'relevance')
            page = request.data.get('page', 1)
            
            # Build query
            q_objects = Q(is_active=True)
            
            if query:
                q_objects &= (
                    Q(business_name__icontains=query) |
                    Q(description__icontains=query) |
                    Q(category__name__icontains=query)
                )
            
            if category:
                q_objects &= Q(category__name__icontains=category)
            
            if price_range:
                q_objects &= Q(price_range=price_range)
            
            if rating_min:
                q_objects &= Q(reviews__rating_score__gte=rating_min)
            
            # Apply location filter if provided
            if location and location.get('latitude') and location.get('longitude'):
                # Simple distance filtering (in production, use PostGIS)
                pass
            
            # Apply amenities filter
            if amenities:
                for amenity in amenities:
                    q_objects &= Q(amenities__contains=[amenity])
            
            # Execute query
            businesses = Business.objects.filter(q_objects).distinct()
            
            # Apply sorting
            if sort_by == 'rating':
                businesses = businesses.annotate(avg_rating=Avg('reviews__rating_score')).order_by('-avg_rating')
            elif sort_by == 'name':
                businesses = businesses.order_by('business_name')
            elif sort_by == 'created':
                businesses = businesses.order_by('-created_at')
            else:  # relevance
                businesses = businesses.order_by('-view_count')
            
            # Pagination
            page_size = 20
            start = (page - 1) * page_size
            end = start + page_size
            paginated_businesses = businesses[start:end]
            
            # Format results
            results = []
            for business in paginated_businesses:
                results.append({
                    'business_id': str(business.business_id),
                    'business_name': business.business_name,
                    'description': business.description,
                    'category': business.category.name if business.category else '',
                    'address': business.address,
                    'province': business.province,
                    'district': business.district,
                    'phone_number': business.phone_number,
                    'price_range': business.price_range,
                    'rating': business.average_rating,
                    'total_reviews': business.total_reviews,
                    'verification_status': business.verification_status,
                    'latitude': float(business.latitude) if business.latitude else None,
                    'longitude': float(business.longitude) if business.longitude else None
                })
            
            return Response({
                'success': True,
                'data': {
                    'results': results,
                    'total_found': businesses.count(),
                    'page': page,
                    'page_size': page_size,
                    'has_next': end < businesses.count(),
                    'has_previous': page > 1
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'advanced_search_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    get=extend_schema(
        summary="Search Suggestions",
        description="Get search suggestions based on partial query",
        tags=["Search"]
    )
)
class AISearchSuggestionsView(generics.GenericAPIView):
    """AI search suggestions endpoint"""
    
    serializer_class = SearchSuggestionSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        """Get search suggestions"""
        try:
            query = request.query_params.get('query', '')
            language = request.query_params.get('language', 'en')
            
            # Get popular searches that match the query
            popular_searches = PopularSearch.objects.filter(
                search_term__icontains=query,
                language=language
            ).order_by('-search_count')[:10]
            
            suggestions = [search.search_term for search in popular_searches]
            
            # Add category suggestions
            categories = BusinessCategory.objects.filter(
                name__icontains=query,
                is_active=True
            )[:5]
            
            category_suggestions = [f"{cat.name} businesses" for cat in categories]
            suggestions.extend(category_suggestions)
            
            return Response({
                'success': True,
                'data': {
                    'suggestions': suggestions[:10],
                    'query': query,
                    'language': language
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'suggestion_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    get=extend_schema(
        summary="Search Autocomplete",
        description="Get autocomplete suggestions",
        tags=["Search"]
    )
)
class SearchAutocompleteView(generics.GenericAPIView):
    """Search autocomplete endpoint"""
    
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        """Get autocomplete suggestions"""
        try:
            query = request.query_params.get('query', '')
            limit = int(request.query_params.get('limit', 5))
            
            if len(query) < 2:
                return Response({
                    'success': True,
                    'data': {'suggestions': []}
                })
            
            # Get business name suggestions
            businesses = Business.objects.filter(
                business_name__icontains=query,
                is_active=True
            ).values_list('business_name', flat=True)[:limit]
            
            # Get category suggestions
            categories = BusinessCategory.objects.filter(
                name__icontains=query,
                is_active=True
            ).values_list('name', flat=True)[:limit//2]
            
            suggestions = list(businesses) + list(categories)
            
            return Response({
                'success': True,
                'data': {
                    'suggestions': suggestions[:limit],
                    'query': query
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'autocomplete_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    get=extend_schema(
        summary="Search by Category",
        description="Search businesses by category",
        tags=["Search"]
    )
)
class SearchByCategoryView(generics.GenericAPIView):
    """Search by category endpoint"""
    
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        """Search businesses by category"""
        try:
            category = kwargs.get('category', '')
            location = request.query_params.get('location')
            sort_by = request.query_params.get('sort_by', 'name')
            page = int(request.query_params.get('page', 1))
            
            # Find businesses in the category
            businesses = Business.objects.filter(
                Q(category__name__icontains=category) |
                Q(subcategories__name__icontains=category),
                is_active=True
            ).distinct()
            
            # Apply sorting
            if sort_by == 'rating':
                businesses = businesses.annotate(avg_rating=Avg('reviews__rating_score')).order_by('-avg_rating')
            elif sort_by == 'created':
                businesses = businesses.order_by('-created_at')
            else:
                businesses = businesses.order_by('business_name')
            
            # Pagination
            page_size = 20
            start = (page - 1) * page_size
            end = start + page_size
            paginated_businesses = businesses[start:end]
            
            # Format results
            results = []
            for business in paginated_businesses:
                results.append({
                    'business_id': str(business.business_id),
                    'business_name': business.business_name,
                    'description': business.description,
                    'address': business.address,
                    'rating': business.average_rating,
                    'total_reviews': business.total_reviews,
                    'price_range': business.price_range
                })
            
            return Response({
                'success': True,
                'data': {
                    'results': results,
                    'category': category,
                    'total_found': businesses.count(),
                    'page': page,
                    'has_next': end < businesses.count()
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'category_search_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    post=extend_schema(
        summary="Nearby Business Search",
        description="Search for businesses near a location",
        tags=["Search"]
    )
)
class NearbyBusinessSearchView(generics.GenericAPIView):
    """Nearby business search endpoint"""
    
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """Search nearby businesses"""
        try:
            latitude = request.data.get('latitude')
            longitude = request.data.get('longitude')
            query = request.data.get('query', '')
            radius_km = request.data.get('radius_km', 5)
            category = request.data.get('category')
            page = request.data.get('page', 1)
            
            if not latitude or not longitude:
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Latitude and longitude are required',
                        'code': 'missing_coordinates'
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Simple nearby search (in production, use PostGIS)
            businesses = Business.objects.filter(
                is_active=True,
                latitude__isnull=False,
                longitude__isnull=False
            )
            
            if query:
                businesses = businesses.filter(
                    Q(business_name__icontains=query) |
                    Q(description__icontains=query)
                )
            
            if category:
                businesses = businesses.filter(
                    Q(category__name__icontains=category) |
                    Q(subcategories__name__icontains=category)
                )
            
            # Filter by distance (simplified)
            nearby_businesses = []
            for business in businesses:
                # Calculate distance (simplified)
                lat_diff = abs(float(business.latitude) - float(latitude))
                lon_diff = abs(float(business.longitude) - float(longitude))
                distance = (lat_diff + lon_diff) * 111  # Rough km conversion
                
                if distance <= radius_km:
                    business.distance = distance
                    nearby_businesses.append(business)
            
            # Sort by distance
            nearby_businesses.sort(key=lambda x: x.distance)
            
            # Pagination
            page_size = 20
            start = (page - 1) * page_size
            end = start + page_size
            paginated_businesses = nearby_businesses[start:end]
            
            # Format results
            results = []
            for business in paginated_businesses:
                results.append({
                    'business_id': str(business.business_id),
                    'business_name': business.business_name,
                    'description': business.description,
                    'address': business.address,
                    'latitude': float(business.latitude),
                    'longitude': float(business.longitude),
                    'distance_km': round(business.distance, 2),
                    'rating': business.average_rating,
                    'price_range': business.price_range
                })
            
            return Response({
                'success': True,
                'data': {
                    'results': results,
                    'total_found': len(nearby_businesses),
                    'center': {'latitude': latitude, 'longitude': longitude},
                    'radius_km': radius_km,
                    'page': page
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'nearby_search_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    get=extend_schema(
        summary="Trending Searches",
        description="Get trending search terms",
        tags=["Search"]
    )
)
class TrendingSearchesView(generics.GenericAPIView):
    """Trending searches endpoint"""
    
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        """Get trending searches"""
        try:
            time_period = request.query_params.get('time_period', 'week')
            language = request.query_params.get('language', 'en')
            
            # Get trending searches
            if time_period == 'week':
                since = timezone.now() - timedelta(days=7)
            elif time_period == 'month':
                since = timezone.now() - timedelta(days=30)
            else:
                since = timezone.now() - timedelta(days=7)
            
            trending = PopularSearch.objects.filter(
                language=language,
                last_searched__gte=since
            ).order_by('-trend_score')[:20]
            
            results = []
            for search in trending:
                results.append({
                    'search_term': search.search_term,
                    'search_count': search.search_count,
                    'trend_score': search.trend_score,
                    'category': search.category
                })
            
            return Response({
                'success': True,
                'data': {
                    'trending_searches': results,
                    'time_period': time_period,
                    'language': language
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'trending_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    get=extend_schema(
        summary="Search Statistics",
        description="Get search analytics and statistics",
        tags=["Search"]
    )
)
class SearchStatsView(generics.GenericAPIView):
    """Search statistics endpoint"""
    
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """Get search statistics"""
        try:
            # Get user's search history
            user_searches = SearchQuery.objects.filter(user=request.user)
            
            # Calculate stats
            total_searches = user_searches.count()
            unique_queries = user_searches.values('query_text').distinct().count()
            avg_results = user_searches.aggregate(avg_results=Avg('results_count'))['avg_results'] or 0
            
            # Most searched terms
            popular_terms = user_searches.values('query_text').annotate(
                count=Count('query_text')
            ).order_by('-count')[:5]
            
            return Response({
                'success': True,
                'data': {
                    'total_searches': total_searches,
                    'unique_queries': unique_queries,
                    'average_results': round(avg_results, 2),
                    'most_searched_terms': [
                        {'term': item['query_text'], 'count': item['count']}
                        for item in popular_terms
                    ]
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'stats_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    get=extend_schema(
        summary="Saved Searches",
        description="Get user's saved searches",
        tags=["Search"]
    ),
    post=extend_schema(
        summary="Save Search",
        description="Save a search query",
        tags=["Search"]
    )
)
class SavedSearchView(generics.ListCreateAPIView):
    """Saved searches endpoint"""
    
    serializer_class = SearchQuerySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return SearchQuery.objects.filter(user=self.request.user).order_by('-created_at')

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

@extend_schema_view(
    get=extend_schema(
        summary="Get Saved Search",
        description="Get details of a saved search",
        tags=["Search"]
    ),
    delete=extend_schema(
        summary="Delete Saved Search",
        description="Delete a saved search",
        tags=["Search"]
    )
)
class SavedSearchDetailView(generics.RetrieveDestroyAPIView):
    """Saved search detail endpoint"""
    
    serializer_class = SearchQuerySerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'query_id'

    def get_queryset(self):
        return SearchQuery.objects.filter(user=self.request.user)


@extend_schema_view(
    get=extend_schema(
        summary="Search History",
        description="Get user's search history",
        tags=["Search"]
    )
)
class SearchHistoryView(generics.GenericAPIView):
    """Search history endpoint"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            # Get user's recent searches
            searches = SearchQuery.objects.filter(
                user=request.user
            ).order_by('-created_at')[:20]
            
            history = []
            for search in searches:
                history.append({
                    'query': search.query_text,
                    'timestamp': search.created_at.isoformat(),
                    'results_count': search.results_count
                })
            
            return Response({
                'success': True,
                'data': {
                    'history': history
                }
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.exception("Error in SearchHistoryView")
            return Response({
                'success': False,
                'error': {'message': str(e), 'code': 'search_history_error'}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    post=extend_schema(
        summary="Save Search",
        description="Save a search for later",
        tags=["Search"]
    )
)
class SaveSearchView(generics.GenericAPIView):
    """Save search endpoint"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            query = request.data.get('query', '')
            filters = request.data.get('filters', {})
            
            # Create saved search
            search_query = SearchQuery.objects.create(
                user=request.user,
                query_text=query,
                search_filters=filters,
                search_type='saved'
            )
            
            return Response({
                'success': True,
                'data': {
                    'search_id': str(search_query.query_id),
                    'message': 'Search saved successfully'
                }
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.exception("Error in SaveSearchView")
            return Response({
                'success': False,
                'error': {'message': str(e), 'code': 'save_search_error'}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    post=extend_schema(
        summary="Radius Search",
        description="Search businesses within a specific radius",
        tags=["Search"]
    )
)
class RadiusSearchView(generics.GenericAPIView):
    """Radius search endpoint"""
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            latitude = request.data.get('latitude')
            longitude = request.data.get('longitude')
            radius = request.data.get('radius', 5)  # Default 5km
            query = request.data.get('query', '')
            
            if not latitude or not longitude:
                return Response({
                    'success': False,
                    'error': {'message': 'Latitude and longitude required', 'code': 'missing_location'}
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # TODO: Implement radius search with geospatial queries
            # For now, return mock results
            results = []
            
            return Response({
                'success': True,
                'data': {
                    'results': results,
                    'search_params': {
                        'latitude': latitude,
                        'longitude': longitude,
                        'radius_km': radius,
                        'query': query
                    }
                }
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.exception("Error in RadiusSearchView")
            return Response({
                'success': False,
                'error': {'message': str(e), 'code': 'radius_search_error'}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    get=extend_schema(
        summary="Search Filters",
        description="Get available search filters",
        tags=["Search"]
    )
)
class SearchFiltersView(generics.GenericAPIView):
    """Search filters endpoint"""
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            filters = {
                'categories': [
                    {'id': 1, 'name': 'Restaurant'},
                    {'id': 2, 'name': 'Hotel'},
                    {'id': 3, 'name': 'Shopping'},
                    {'id': 4, 'name': 'Services'},
                    {'id': 5, 'name': 'Healthcare'}
                ],
                'provinces': [
                    'Kigali',
                    'Eastern Province',
                    'Western Province',
                    'Northern Province',
                    'Southern Province'
                ],
                'price_ranges': [
                    {'value': 'low', 'label': 'Budget-friendly'},
                    {'value': 'medium', 'label': 'Mid-range'},
                    {'value': 'high', 'label': 'Premium'}
                ],
                'verification_status': [
                    {'value': 'verified', 'label': 'Verified businesses only'},
                    {'value': 'all', 'label': 'All businesses'}
                ]
            }
            
            return Response({
                'success': True,
                'data': filters
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.exception("Error in SearchFiltersView")
            return Response({
                'success': False,
                'error': {'message': str(e), 'code': 'search_filters_error'}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
