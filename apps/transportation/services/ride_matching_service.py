# apps/transportation/services/ride_matching_service.py
from typing import Dict, Any, List
from django.db.models import Q
from apps.transportation.models import Ride, Driver
from .fare_calculator import FareCalculatorService

class RideMatchingService:
    """Service for matching rides with drivers"""
    
    def __init__(self):
        self.fare_calculator = FareCalculatorService()
    
    def find_matching_drivers(self, ride: Ride, max_distance_km: float = 5.0) -> List[Dict[str, Any]]:
        """Find drivers that can fulfill a ride request"""
        
        # Get available drivers
        available_drivers = Driver.objects.filter(
            is_online=True,
            is_available=True,
            is_verified=True,
            vehicle_type=ride.vehicle_type
        )
        
        matching_drivers = []
        
        for driver in available_drivers:
            # Check if driver has location data
            if not driver.current_latitude or not driver.current_longitude:
                continue
            
            # Calculate distance from driver to pickup point
            distance = self._calculate_distance(
                driver.current_latitude, driver.current_longitude,
                ride.pickup_latitude, ride.pickup_longitude
            )
            
            # Check if driver is within range
            if distance <= max_distance_km:
                # Calculate ETA (simplified)
                eta_minutes = self._calculate_eta(distance)
                
                # Calculate fare for this driver
                fare_data = self.fare_calculator.calculate_fare(
                    ride.pickup_latitude, ride.pickup_longitude,
                    ride.dropoff_latitude, ride.dropoff_longitude,
                    ride.vehicle_type
                )
                
                matching_drivers.append({
                    'driver_id': str(driver.driver_id),
                    'driver_name': driver.user.get_full_name(),
                    'vehicle_type': driver.vehicle_type,
                    'vehicle_model': driver.vehicle_model,
                    'vehicle_plate': driver.vehicle_plate,
                    'distance_km': round(distance, 2),
                    'eta_minutes': eta_minutes,
                    'rating': float(driver.average_rating),
                    'total_rides': driver.total_rides,
                    'estimated_fare': fare_data['total_fare'],
                    'currency': fare_data['currency']
                })
        
        # Sort by distance and rating
        matching_drivers.sort(key=lambda x: (x['distance_km'], -x['rating']))
        
        return matching_drivers[:10]  # Return top 10 matches
    
    def assign_driver(self, ride: Ride, driver_id: str) -> Dict[str, Any]:
        """Assign a specific driver to a ride"""
        
        try:
            driver = Driver.objects.get(
                driver_id=driver_id,
                is_online=True,
                is_available=True,
                is_verified=True,
                vehicle_type=ride.vehicle_type
            )
            
            # Check if driver is still available
            if not driver.is_available:
                return {
                    'success': False,
                    'error': 'Driver is no longer available'
                }
            
            # Assign driver to ride
            ride.driver = driver.user
            ride.status = 'accepted'
            ride.accepted_at = timezone.now()
            ride.save()
            
            # Mark driver as unavailable
            driver.is_available = False
            driver.save()
            
            return {
                'success': True,
                'data': {
                    'ride_id': str(ride.ride_id),
                    'driver_id': str(driver.driver_id),
                    'driver_name': driver.user.get_full_name(),
                    'status': ride.status,
                    'message': 'Driver assigned successfully'
                }
            }
            
        except Driver.DoesNotExist:
            return {
                'success': False,
                'error': 'Driver not found or not available'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two points in kilometers"""
        
        from math import radians, cos, sin, asin, sqrt
        
        # Convert to radians
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        
        # Haversine formula
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * asin(sqrt(a))
        r = 6371  # Earth's radius in kilometers
        
        return c * r
    
    def _calculate_eta(self, distance_km: float) -> int:
        """Calculate estimated time of arrival in minutes"""
        
        # Simplified ETA calculation
        # Assume average speed of 25 km/h in city traffic
        eta_hours = distance_km / 25
        eta_minutes = int(eta_hours * 60)
        
        # Minimum 2 minutes, maximum 30 minutes
        return max(2, min(eta_minutes, 30))
    
    def get_ride_suggestions(self, user_lat: float, user_lon: float, 
                           vehicle_type: str = 'car') -> List[Dict[str, Any]]:
        """Get ride suggestions based on user location"""
        
        # Get nearby available rides
        nearby_rides = Ride.objects.filter(
            status='pending',
            vehicle_type=vehicle_type
        ).exclude(
            passenger__isnull=True
        )
        
        suggestions = []
        
        for ride in nearby_rides:
            # Calculate distance from user to pickup point
            distance = self._calculate_distance(
                user_lat, user_lon,
                ride.pickup_latitude, ride.pickup_longitude
            )
            
            # Only suggest rides within 2km
            if distance <= 2.0:
                suggestions.append({
                    'ride_id': str(ride.ride_id),
                    'pickup_address': ride.pickup_address,
                    'dropoff_address': ride.dropoff_address,
                    'vehicle_type': ride.vehicle_type,
                    'distance_km': round(distance, 2),
                    'estimated_fare': float(ride.estimated_fare or 0),
                    'passenger_count': ride.passenger_count,
                    'requested_at': ride.requested_at.isoformat()
                })
        
        # Sort by distance
        suggestions.sort(key=lambda x: x['distance_km'])
        
        return suggestions[:5]  # Return top 5 suggestions