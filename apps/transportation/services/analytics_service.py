# apps/transportation/services/analytics_service.py
from typing import Dict, Any, List
from django.db.models import Count, Avg, Sum
from django.utils import timezone
from datetime import timedelta
from apps.transportation.models import Ride, Driver, VehicleType
from apps.authentication.models import User

class AnalyticsService:
    """Service for transportation analytics and reporting"""
    
    def get_driver_analytics(self, driver_id: str, period: str = 'week') -> Dict[str, Any]:
        """Get analytics for a specific driver"""
        
        try:
            driver = Driver.objects.get(driver_id=driver_id)
            
            # Calculate date range
            end_date = timezone.now()
            if period == 'day':
                start_date = end_date - timedelta(days=1)
            elif period == 'week':
                start_date = end_date - timedelta(weeks=1)
            elif period == 'month':
                start_date = end_date - timedelta(days=30)
            else:
                start_date = end_date - timedelta(weeks=1)
            
            # Get rides in period
            rides = Ride.objects.filter(
                driver=driver.user,
                created_at__gte=start_date,
                created_at__lte=end_date
            )
            
            # Calculate metrics
            total_rides = rides.count()
            completed_rides = rides.filter(status='completed').count()
            cancelled_rides = rides.filter(status='cancelled').count()
            
            # Calculate earnings
            total_earnings = rides.filter(
                status='completed',
                actual_fare__isnull=False
            ).aggregate(Sum('actual_fare'))['actual_fare__sum'] or 0
            
            # Calculate average rating from reviews
            avg_rating = 0.0
            completed_rides_with_reviews = rides.filter(
                status='completed',
                review__isnull=False
            )
            if completed_rides_with_reviews.exists():
                avg_rating = completed_rides_with_reviews.aggregate(
                    Avg('review__overall_rating')
                )['review__overall_rating__avg'] or 0.0
            
            # Calculate average fare
            avg_fare = rides.filter(
                status='completed',
                actual_fare__isnull=False
            ).aggregate(Avg('actual_fare'))['actual_fare__avg'] or 0
            
            # Calculate completion rate
            completion_rate = (completed_rides / total_rides * 100) if total_rides > 0 else 0
            
            return {
                'driver_id': str(driver.driver_id),
                'driver_name': driver.user.get_full_name(),
                'period': period,
                'total_rides': total_rides,
                'completed_rides': completed_rides,
                'cancelled_rides': cancelled_rides,
                'completion_rate': round(completion_rate, 2),
                'total_earnings': float(total_earnings),
                'average_rating': round(avg_rating, 2),
                'average_fare': float(avg_fare),
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            }
            
        except Driver.DoesNotExist:
            return {
                'error': 'Driver not found'
            }
        except Exception as e:
            return {
                'error': str(e)
            }
    
    def get_passenger_analytics(self, user_id: str, period: str = 'week') -> Dict[str, Any]:
        """Get analytics for a specific passenger"""
        
        try:
            user = User.objects.get(id=user_id)
            
            # Calculate date range
            end_date = timezone.now()
            if period == 'day':
                start_date = end_date - timedelta(days=1)
            elif period == 'week':
                start_date = end_date - timedelta(weeks=1)
            elif period == 'month':
                start_date = end_date - timedelta(days=30)
            else:
                start_date = end_date - timedelta(weeks=1)
            
            # Get rides in period
            rides = Ride.objects.filter(
                passenger=user,
                created_at__gte=start_date,
                created_at__lte=end_date
            )
            
            # Calculate metrics
            total_rides = rides.count()
            completed_rides = rides.filter(status='completed').count()
            cancelled_rides = rides.filter(status='cancelled').count()
            
            # Calculate total spent
            total_spent = rides.filter(
                status='completed',
                actual_fare__isnull=False
            ).aggregate(Sum('actual_fare'))['actual_fare__sum'] or 0
            
            # Calculate average fare
            avg_fare = rides.filter(
                status='completed',
                actual_fare__isnull=False
            ).aggregate(Avg('actual_fare'))['actual_fare__avg'] or 0
            
            # Calculate completion rate
            completion_rate = (completed_rides / total_rides * 100) if total_rides > 0 else 0
            
            # Get favorite vehicle type
            favorite_vehicle_type = rides.filter(
                status='completed'
            ).values('vehicle_type__name').annotate(
                count=Count('vehicle_type')
            ).order_by('-count').first()
            
            return {
                'user_id': str(user.id),
                'user_name': user.get_full_name(),
                'period': period,
                'total_rides': total_rides,
                'completed_rides': completed_rides,
                'cancelled_rides': cancelled_rides,
                'completion_rate': round(completion_rate, 2),
                'total_spent': float(total_spent),
                'average_fare': float(avg_fare),
                'favorite_vehicle_type': favorite_vehicle_type['vehicle_type__name'] if favorite_vehicle_type else None,
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            }
            
        except User.DoesNotExist:
            return {
                'error': 'User not found'
            }
        except Exception as e:
            return {
                'error': str(e)
            }
    
    def get_system_analytics(self, period: str = 'week') -> Dict[str, Any]:
        """Get overall system analytics"""
        
        try:
            # Calculate date range
            end_date = timezone.now()
            if period == 'day':
                start_date = end_date - timedelta(days=1)
            elif period == 'week':
                start_date = end_date - timedelta(weeks=1)
            elif period == 'month':
                start_date = end_date - timedelta(days=30)
            else:
                start_date = end_date - timedelta(weeks=1)
            
            # Get rides in period
            rides = Ride.objects.filter(
                created_at__gte=start_date,
                created_at__lte=end_date
            )
            
            # Calculate metrics
            total_rides = rides.count()
            completed_rides = rides.filter(status='completed').count()
            cancelled_rides = rides.filter(status='cancelled').count()
            
            # Calculate total revenue
            total_revenue = rides.filter(
                status='completed',
                actual_fare__isnull=False
            ).aggregate(Sum('actual_fare'))['actual_fare__sum'] or 0
            
            # Calculate average fare
            avg_fare = rides.filter(
                status='completed',
                actual_fare__isnull=False
            ).aggregate(Avg('actual_fare'))['actual_fare__avg'] or 0
            
            # Calculate completion rate
            completion_rate = (completed_rides / total_rides * 100) if total_rides > 0 else 0
            
            # Get active drivers
            active_drivers = Driver.objects.filter(
                is_online=True,
                is_available=True
            ).count()
            
            # Get total drivers
            total_drivers = Driver.objects.count()
            
            # Get total vehicle types
            total_vehicle_types = VehicleType.objects.filter(is_active=True).count()
            
            # Get vehicle type distribution
            vehicle_type_distribution = rides.filter(
                status='completed'
            ).values('vehicle_type__name').annotate(
                count=Count('vehicle_type')
            ).order_by('-count')
            
            return {
                'period': period,
                'total_rides': total_rides,
                'completed_rides': completed_rides,
                'cancelled_rides': cancelled_rides,
                'completion_rate': round(completion_rate, 2),
                'total_revenue': float(total_revenue),
                'average_fare': float(avg_fare),
                'active_drivers': active_drivers,
                'total_drivers': total_drivers,
                'total_vehicle_types': total_vehicle_types,
                'vehicle_type_distribution': list(vehicle_type_distribution),
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            }
            
        except Exception as e:
            return {
                'error': str(e)
            }
    
    def get_ride_trends(self, period: str = 'week') -> Dict[str, Any]:
        """Get ride trends over time"""
        
        try:
            # Calculate date range
            end_date = timezone.now()
            if period == 'day':
                start_date = end_date - timedelta(days=1)
                group_by = 'hour'
            elif period == 'week':
                start_date = end_date - timedelta(weeks=1)
                group_by = 'day'
            elif period == 'month':
                start_date = end_date - timedelta(days=30)
                group_by = 'day'
            else:
                start_date = end_date - timedelta(weeks=1)
                group_by = 'day'
            
            # Get rides in period
            rides = Ride.objects.filter(
                created_at__gte=start_date,
                created_at__lte=end_date
            )
            
            # Group by time period
            if group_by == 'hour':
                trends = rides.extra(
                    select={'period': "DATE_TRUNC('hour', created_at)"}
                ).values('period').annotate(
                    count=Count('ride_id')
                ).order_by('period')
            else:  # day
                trends = rides.extra(
                    select={'period': "DATE_TRUNC('day', created_at)"}
                ).values('period').annotate(
                    count=Count('ride_id')
                ).order_by('period')
            
            # Format trends data
            trends_data = []
            for trend in trends:
                trends_data.append({
                    'period': trend['period'].isoformat(),
                    'count': trend['count']
                })
            
            return {
                'period': period,
                'group_by': group_by,
                'trends': trends_data,
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            }
            
        except Exception as e:
            return {
                'error': str(e)
            }

    def get_vehicle_type_analytics(self) -> Dict[str, Any]:
        """Get analytics for vehicle types"""
        
        try:
            vehicle_types = VehicleType.objects.filter(is_active=True)
            
            analytics = []
            for vehicle_type in vehicle_types:
                # Get rides for this vehicle type
                rides = Ride.objects.filter(vehicle_type=vehicle_type)
                completed_rides = rides.filter(status='completed')
                
                # Calculate metrics
                total_rides = rides.count()
                completed_count = completed_rides.count()
                total_revenue = completed_rides.aggregate(
                    Sum('actual_fare')
                )['actual_fare__sum'] or 0
                
                # Calculate average fare
                avg_fare = completed_rides.aggregate(
                    Avg('actual_fare')
                )['actual_fare__avg'] or 0
                
                analytics.append({
                    'vehicle_type_id': str(vehicle_type.vehicle_type_id),
                    'name': vehicle_type.name,
                    'description': vehicle_type.description,
                    'base_fare': float(vehicle_type.base_fare),
                    'per_km_rate': float(vehicle_type.per_km_rate),
                    'per_minute_rate': float(vehicle_type.per_minute_rate),
                    'minimum_fare': float(vehicle_type.minimum_fare),
                    'capacity': vehicle_type.capacity,
                    'total_rides': total_rides,
                    'completed_rides': completed_count,
                    'total_revenue': float(total_revenue),
                    'average_fare': float(avg_fare),
                    'utilization_rate': (completed_count / total_rides * 100) if total_rides > 0 else 0
                })
            
            return {
                'vehicle_types': analytics,
                'total_vehicle_types': len(analytics)
            }
            
        except Exception as e:
            return {
                'error': str(e)
            }


