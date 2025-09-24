# apps/businesses/views.py
from rest_framework import generics, status, filters, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from django.db.models import Q, Avg, Count, F
from django.shortcuts import get_object_or_404
from geopy.distance import geodesic

from .models import Business, BusinessCategory, Review
from .serializers import (
    BusinessListSerializer, BusinessDetailSerializer, BusinessCreateSerializer,
    BusinessCategorySerializer, ReviewSerializer, ReviewCreateSerializer
)
from .filters import BusinessFilter
from apps.common.permissions import IsOwnerOrReadOnly

@extend_schema_view(
    get=extend_schema(
        summary="List Business Categories",
        description="Get all business categories with multilingual names",
        tags=["Businesses"]
    )
)
class BusinessCategoryListView(generics.ListAPIView):
    """List all business categories"""
    
    queryset = BusinessCategory.objects.filter(is_active=True)
    serializer_class = BusinessCategorySerializer
    permission_classes = [permissions.AllowAny]

@extend_schema_view(
    get=extend_schema(
        summary="List Businesses",
        description="Get paginated list of businesses with filtering and search",
        tags=["Businesses"],
        parameters=[
            OpenApiParameter(name='search', description='Search in business name and description'),
            OpenApiParameter(name='business_category', description='Filter by category ID'),
            OpenApiParameter(name='province', description='Filter by province'),
            OpenApiParameter(name='district', description='Filter by district'),
            OpenApiParameter(name='price_range', description='Filter by price range'),
            OpenApiParameter(name='verification_status', description='Filter by verification status'),
            OpenApiParameter(name='ordering', description='Order by: name, rating, created_at')
        ]
    )
)
class BusinessListView(generics.ListAPIView):
    """List businesses with advanced filtering"""
    
    serializer_class = BusinessListSerializer
    permission_classes = [permissions.AllowAny]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = BusinessFilter
    search_fields = ['business_name', 'description', 'address']
    ordering_fields = ['business_name', 'created_at', 'view_count']
    ordering = ['-created_at']

    def get_queryset(self):
        queryset = Business.objects.filter(is_active=True).select_related('category').prefetch_related('images')
        
        # Add rating annotation
        queryset = queryset.annotate(
            avg_rating=Avg('reviews__rating_score'),
            review_count=Count('reviews')
        )
        
        return queryset

@extend_schema_view(
    get=extend_schema(
        summary="Get Nearby Businesses",
        description="Get businesses near a specific location",
        tags=["Businesses"],
        parameters=[
            OpenApiParameter(name='latitude', description='User latitude', required=True, type=float),
            OpenApiParameter(name='longitude', description='User longitude', required=True, type=float),
            OpenApiParameter(name='radius', description='Search radius in kilometers (default: 5)', type=float),
            OpenApiParameter(name='search', description='Search query'),
            OpenApiParameter(name='ordering', description='Order by: distance, rating, name')
        ]
    )
)
class NearbyBusinessesView(generics.ListAPIView):
    """Get businesses near user location"""
    
    serializer_class = BusinessListSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        latitude = self.request.query_params.get('latitude')
        longitude = self.request.query_params.get('longitude')
        radius = float(self.request.query_params.get('radius', 5))  # Default 5km
        search = self.request.query_params.get('search', '')
        
        if not latitude or not longitude:
            return Business.objects.none()
        
        try:
            user_lat = float(latitude)
            user_lon = float(longitude)
        except (ValueError, TypeError):
            return Business.objects.none()
        
        # Base queryset
        queryset = Business.objects.filter(
            is_active=True,
            latitude__isnull=False,
            longitude__isnull=False
        ).select_related('category').prefetch_related('images')
        
        # Add search filter
        if search:
            queryset = queryset.filter(
                Q(business_name__icontains=search) |
                Q(description__icontains=search) |
                Q(category__name__icontains=search)
            )
        
        # Calculate distances and filter by radius
        nearby_businesses = []
        for business in queryset:
            distance = geodesic(
                (user_lat, user_lon),
                (float(business.latitude), float(business.longitude))
            ).kilometers
            
            if distance <= radius:
                business.distance = distance
                nearby_businesses.append(business)
        
        # Sort by distance or other criteria
        ordering = self.request.query_params.get('ordering', 'distance')
        if ordering == 'distance':
            nearby_businesses.sort(key=lambda x: x.distance)
        elif ordering == 'rating':
            nearby_businesses.sort(key=lambda x: x.average_rating, reverse=True)
        elif ordering == 'name':
            nearby_businesses.sort(key=lambda x: x.business_name)
        
        return nearby_businesses

    def list(self, request, *args, **kwargs):
        """Override list to add distance information"""
        queryset = self.get_queryset()
        
        # Paginate results
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            # Add distance to each result
            for i, business in enumerate(page):
                if hasattr(business, 'distance'):
                    serializer.data[i]['distance_km'] = round(business.distance, 2)
            
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        # Add distance to each result
        for i, business in enumerate(queryset):
            if hasattr(business, 'distance'):
                serializer.data[i]['distance_km'] = round(business.distance, 2)
        
        return Response(serializer.data)

@extend_schema_view(
    get=extend_schema(
        summary="Get Business Details",
        description="Get detailed information about a specific business",
        tags=["Businesses"]
    )
)
class BusinessDetailView(generics.RetrieveAPIView):
    """Get detailed business information"""
    
    queryset = Business.objects.filter(is_active=True)
    serializer_class = BusinessDetailSerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = 'business_id'

    def retrieve(self, request, *args, **kwargs):
        """Override to increment view count"""
        instance = self.get_object()
        
        # Increment view count
        instance.increment_view_count()
        
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

@extend_schema_view(
    post=extend_schema(
        summary="Create New Business",
        description="Create a new business listing (requires authentication)",
        tags=["Businesses"]
    )
)
class BusinessCreateView(generics.CreateAPIView):
    """Create new business"""
    
    serializer_class = BusinessCreateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        # Set user type to business owner
        user = self.request.user
        if user.user_type != 'business_owner':
            user.user_type = 'business_owner'
            user.save()
        
        serializer.save(owner=user)

@extend_schema_view(
    put=extend_schema(
        summary="Update Business",
        description="Update business information (owner only)",
        tags=["Businesses"]
    ),
    patch=extend_schema(
        summary="Partial Update Business",
        description="Partially update business information (owner only)",
        tags=["Businesses"]
    )
)
class BusinessUpdateView(generics.RetrieveUpdateAPIView):
    """Update business information"""
    
    queryset = Business.objects.all()
    serializer_class = BusinessCreateSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]
    lookup_field = 'business_id'

    def get_queryset(self):
        # Only allow owners to update their businesses
        return Business.objects.filter(owner=self.request.user)

@extend_schema_view(
    get=extend_schema(
        summary="Get Business Reviews",
        description="Get all reviews for a specific business",
        tags=["Businesses"]
    ),
    post=extend_schema(
        summary="Create Business Review",
        description="Create a review for a business (requires authentication)",
        tags=["Businesses"]
    )
)
class BusinessReviewView(generics.ListCreateAPIView):
    """List and create business reviews"""
    
    serializer_class = ReviewSerializer
    queryset = Review.objects.none()  # Added to fix the warning
    
    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        if self.request.method == 'POST':
            permission_classes = [permissions.IsAuthenticated]
        else:
            permission_classes = [permissions.AllowAny]
        return [permission() for permission in permission_classes]

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return ReviewCreateSerializer
        return ReviewSerializer

    def get_queryset(self):
        business_id = self.kwargs['business_id']
        return Review.objects.filter(
            business__business_id=business_id
        ).order_by('-created_at')

    def get_serializer_context(self):
        context = super().get_serializer_context()
        business_id = self.kwargs['business_id']
        business = get_object_or_404(Business, business_id=business_id)
        context['business'] = business
        return context

    def create(self, request, *args, **kwargs):
        business_id = kwargs['business_id']
        business = get_object_or_404(Business, business_id=business_id)
        
        # Check if user already reviewed this business
        if Review.objects.filter(business=business, reviewer=request.user).exists():
            return Response(
                {'error': 'You have already reviewed this business'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        return super().create(request, *args, **kwargs)