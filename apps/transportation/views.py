# apps/transportation/views.py
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, extend_schema_view
from django.utils import timezone
from django.db import models  # Add this import for models.Q

from .models import Ride, Driver, FareCalculation, VehicleType  # Add VehicleType import
from .serializers import (
    RideSerializer, DriverSerializer, FareCalculationSerializer,
    RideCreateSerializer, DriverLocationSerializer, VehicleTypeSerializer
)
from .services.fare_calculator import FareCalculatorService
from .services.ride_matching_service import RideMatchingService
from .services.analytics_service import AnalyticsService  # Add AnalyticsService import

@extend_schema_view(
    get=extend_schema(
        summary="List Rides",
        description="Get user's rides or available rides",
        tags=["Transportation"]
    )
)
class RideListView(generics.ListAPIView):
    """List rides"""
    
    serializer_class = RideSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        ride_type = self.request.query_params.get('type', 'all')
        
        if ride_type == 'my_rides':
            return Ride.objects.filter(passenger=user).order_by('-created_at')
        elif ride_type == 'available':
            return Ride.objects.filter(status='pending').order_by('-created_at')
        else:
            return Ride.objects.filter(passenger=user).order_by('-created_at')

@extend_schema_view(
    post=extend_schema(
        summary="Create Ride",
        description="Create a new ride request",
        tags=["Transportation"]
    )
)
class RideCreateView(generics.CreateAPIView):
    """Create ride request"""
    
    serializer_class = RideCreateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        # Calculate fare before saving
        pickup_lat = serializer.validated_data.get('pickup_latitude')
        pickup_lon = serializer.validated_data.get('pickup_longitude')
        dropoff_lat = serializer.validated_data.get('dropoff_latitude')
        dropoff_lon = serializer.validated_data.get('dropoff_longitude')
        vehicle_type = serializer.validated_data.get('vehicle_type')
        
        # Calculate fare
        fare_service = FareCalculatorService()
        fare_data = fare_service.calculate_fare(
            pickup_lat=float(pickup_lat),
            pickup_lon=float(pickup_lon),
            dropoff_lat=float(dropoff_lat),
            dropoff_lon=float(dropoff_lon),
            vehicle_type=vehicle_type.name if hasattr(vehicle_type, 'name') else 'car'
        )
        
        # Save ride with estimated fare
        serializer.save(
            passenger=self.request.user,
            estimated_fare=fare_data['total_fare'],
            distance_km=fare_data['distance_km'],
            duration_minutes=fare_data['duration_minutes']
        )

@extend_schema_view(
    get=extend_schema(
        summary="Get Ride Details",
        description="Get details of a specific ride",
        tags=["Transportation"]
    )
)
class RideDetailView(generics.RetrieveAPIView):
    """Get ride details"""
    
    serializer_class = RideSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'ride_id'

    def get_queryset(self):
        user = self.request.user
        return Ride.objects.filter(
            models.Q(passenger=user) | models.Q(driver=user)
        )

@extend_schema_view(
    post=extend_schema(
        summary="Accept Ride",
        description="Accept a ride request",
        tags=["Transportation"]
    )
)
class RideAcceptView(generics.GenericAPIView):
    """Accept ride request"""
    
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """Accept ride"""
        try:
            ride_id = kwargs['ride_id']
            
            try:
                ride = Ride.objects.get(ride_id=ride_id, status='pending')
            except Ride.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Ride not found or not available',
                        'code': 'ride_not_found'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Check if user is a driver
            if not hasattr(request.user, 'driver_profile'):
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Only drivers can accept rides',
                        'code': 'not_driver'
                    }
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Check if driver has the correct vehicle type
            driver_profile = request.user.driver_profile
            if driver_profile.vehicle_type != ride.vehicle_type:
                return Response({
                    'success': False,
                    'error': {
                        'message': f'Driver vehicle type ({driver_profile.vehicle_type.name}) does not match ride requirement ({ride.vehicle_type.name})',
                        'code': 'vehicle_type_mismatch'
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Accept ride
            ride.driver = request.user
            ride.status = 'accepted'
            ride.accepted_at = timezone.now()
            ride.save()
            
            # Mark driver as unavailable
            driver_profile.is_available = False
            driver_profile.save()
            
            return Response({
                'success': True,
                'data': {
                    'ride_id': str(ride.ride_id),
                    'status': ride.status,
                    'driver': request.user.get_full_name(),
                    'message': 'Ride accepted successfully'
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'accept_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    post=extend_schema(
        summary="Complete Ride",
        description="Mark ride as completed",
        tags=["Transportation"]
    )
)
class RideCompleteView(generics.GenericAPIView):
    """Complete ride"""
    
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """Complete ride"""
        try:
            ride_id = kwargs['ride_id']
            final_fare = request.data.get('final_fare')
            
            try:
                ride = Ride.objects.get(
                    ride_id=ride_id,
                    driver=request.user,
                    status='accepted'
                )
            except Ride.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Ride not found or not accepted by you',
                        'code': 'ride_not_found'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Complete ride
            ride.status = 'completed'
            ride.completed_at = timezone.now()
            if final_fare:
                ride.actual_fare = final_fare
            else:
                # Use estimated fare if final fare not provided
                ride.actual_fare = ride.estimated_fare
            ride.save()
            
            # Update driver profile
            driver_profile = request.user.driver_profile
            driver_profile.is_available = True
            driver_profile.total_rides += 1
            driver_profile.total_earnings += ride.actual_fare or 0
            driver_profile.save()
            
            return Response({
                'success': True,
                'data': {
                    'ride_id': str(ride.ride_id),
                    'status': ride.status,
                    'final_fare': ride.actual_fare,
                    'message': 'Ride completed successfully'
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'complete_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    post=extend_schema(
        summary="Calculate Fare",
        description="Calculate ride fare based on distance and other factors",
        tags=["Transportation"]
    )
)
class FareCalculationView(generics.GenericAPIView):
    """Calculate ride fare"""
    
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """Calculate fare"""
        try:
            pickup_lat = request.data.get('pickup_latitude')
            pickup_lon = request.data.get('pickup_longitude')
            dropoff_lat = request.data.get('dropoff_latitude')
            dropoff_lon = request.data.get('dropoff_longitude')
            vehicle_type_name = request.data.get('vehicle_type', 'car')
            
            if not all([pickup_lat, pickup_lon, dropoff_lat, dropoff_lon]):
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Pickup and dropoff coordinates are required',
                        'code': 'missing_coordinates'
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Calculate fare
            fare_service = FareCalculatorService()
            fare_data = fare_service.calculate_fare(
                pickup_lat=float(pickup_lat),
                pickup_lon=float(pickup_lon),
                dropoff_lat=float(dropoff_lat),
                dropoff_lon=float(dropoff_lon),
                vehicle_type=vehicle_type_name
            )
            
            return Response({
                'success': True,
                'data': fare_data
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'fare_calculation_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    get=extend_schema(
        summary="List Vehicle Types",
        description="Get available vehicle types",
        tags=["Transportation"]
    )
)
class VehicleTypeListView(generics.ListAPIView):
    """List available vehicle types"""
    
    serializer_class = VehicleTypeSerializer
    permission_classes = [permissions.AllowAny]
    queryset = VehicleType.objects.filter(is_active=True)

@extend_schema_view(
    get=extend_schema(
        summary="List Drivers",
        description="Get available drivers",
        tags=["Transportation"]
    )
)
class DriverListView(generics.ListAPIView):
    """List available drivers"""
    
    serializer_class = DriverSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        return Driver.objects.filter(is_available=True, is_online=True)

@extend_schema_view(
    get=extend_schema(
        summary="Get Driver Details",
        description="Get details of a specific driver",
        tags=["Transportation"]
    )
)
class DriverDetailView(generics.RetrieveAPIView):
    """Get driver details"""
    
    queryset = Driver.objects.all()
    serializer_class = DriverSerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = 'driver_id'

@extend_schema_view(
    get=extend_schema(
        summary="Get Driver Location",
        description="Get current location of a driver",
        tags=["Transportation"]
    ),
    post=extend_schema(
        summary="Update Driver Location",
        description="Update driver's current location",
        tags=["Transportation"]
    )
)
class DriverLocationView(generics.GenericAPIView):
    """Driver location management"""
    
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """Get driver location"""
        try:
            driver_id = kwargs['driver_id']
            
            try:
                driver = Driver.objects.get(driver_id=driver_id)
            except Driver.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Driver not found',
                        'code': 'driver_not_found'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            
            if not driver.current_latitude or not driver.current_longitude:
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Driver location not available',
                        'code': 'location_unavailable'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            
            return Response({
                'success': True,
                'data': {
                    'driver_id': str(driver.driver_id),
                    'latitude': float(driver.current_latitude),
                    'longitude': float(driver.current_longitude),
                    'last_updated': driver.location_updated_at.isoformat() if driver.location_updated_at else None,
                    'is_online': driver.is_online
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'location_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request, *args, **kwargs):
        """Update driver location"""
        try:
            driver_id = kwargs['driver_id']
            latitude = request.data.get('latitude')
            longitude = request.data.get('longitude')
            
            if not latitude or not longitude:
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Latitude and longitude are required',
                        'code': 'missing_coordinates'
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                driver = Driver.objects.get(driver_id=driver_id, user=request.user)
            except Driver.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Driver not found or not authorized',
                        'code': 'driver_not_found'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Update location
            driver.current_latitude = latitude
            driver.current_longitude = longitude
            driver.location_updated_at = timezone.now()
            driver.save()
            
            return Response({
                'success': True,
                'data': {
                    'driver_id': str(driver.driver_id),
                    'latitude': float(driver.current_latitude),
                    'longitude': float(driver.current_longitude),
                    'updated_at': driver.location_updated_at.isoformat()
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'update_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    get=extend_schema(
        summary="Transportation Analytics",
        description="Get transportation analytics and insights",
        tags=["Transportation"]
    )
)
class TransportationAnalyticsView(generics.GenericAPIView):
    """Transportation analytics"""
    
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """Get transportation analytics"""
        try:
            analytics_service = AnalyticsService()
            period = request.query_params.get('period', 'week')
            analytics_type = request.query_params.get('type', 'user')
            
            if analytics_type == 'user':
                # User analytics
                user_rides = Ride.objects.filter(passenger=request.user)
                
                total_rides = user_rides.count()
                completed_rides = user_rides.filter(status='completed').count()
                total_fare_paid = sum(ride.actual_fare or 0 for ride in user_rides.filter(status='completed'))
                
                # Get recent rides
                recent_rides = user_rides.order_by('-created_at')[:5]
                
                analytics_data = {
                    'total_rides': total_rides,
                    'completed_rides': completed_rides,
                    'cancelled_rides': user_rides.filter(status='cancelled').count(),
                    'total_fare_paid': float(total_fare_paid),
                    'average_fare': float(total_fare_paid / completed_rides) if completed_rides > 0 else 0,
                    'recent_rides': [
                        {
                            'ride_id': str(ride.ride_id),
                            'status': ride.status,
                            'fare': float(ride.actual_fare or 0),
                            'vehicle_type': ride.vehicle_type.name,
                            'created_at': ride.created_at.isoformat()
                        }
                        for ride in recent_rides
                    ]
                }
            elif analytics_type == 'driver' and hasattr(request.user, 'driver_profile'):
                # Driver analytics
                driver_analytics = analytics_service.get_driver_analytics(
                    str(request.user.driver_profile.driver_id), period
                )
                analytics_data = driver_analytics
            else:
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Invalid analytics type or user is not a driver',
                        'code': 'invalid_analytics_type'
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({
                'success': True,
                'data': analytics_data
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'analytics_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    post=extend_schema(
        summary="Cancel Ride",
        description="Cancel a ride request",
        tags=["Transportation"]
    )
)
class RideCancelView(generics.GenericAPIView):
    """Cancel ride"""
    
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """Cancel ride"""
        try:
            ride_id = kwargs['ride_id']
            reason = request.data.get('reason', '')
            
            try:
                ride = Ride.objects.get(
                    ride_id=ride_id,
                    passenger=request.user,
                    status__in=['pending', 'accepted']
                )
            except Ride.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Ride not found or cannot be cancelled',
                        'code': 'ride_not_found'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Cancel ride
            ride.status = 'cancelled'
            ride.cancelled_at = timezone.now()
            ride.save()
            
            # If ride was accepted, make driver available again
            if ride.driver:
                try:
                    driver_profile = ride.driver.driver_profile
                    driver_profile.is_available = True
                    driver_profile.save()
                except Driver.DoesNotExist:
                    pass
            
            return Response({
                'success': True,
                'data': {
                    'ride_id': str(ride.ride_id),
                    'status': ride.status,
                    'message': 'Ride cancelled successfully'
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'cancel_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)