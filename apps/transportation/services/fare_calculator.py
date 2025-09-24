# apps/transportation/services/fare_calculator.py
from typing import Dict, Any
from math import radians, cos, sin, asin, sqrt
from decimal import Decimal

class FareCalculatorService:
    """Service for calculating ride fares"""
    
    def __init__(self):
        # Base fare rates (in RWF)
        self.base_rates = {
            'motorcycle': {
                'base_fare': 500,
                'per_km': 200,
                'per_minute': 50,
                'minimum_fare': 1000
            },
            'car': {
                'base_fare': 1000,
                'per_km': 400,
                'per_minute': 100,
                'minimum_fare': 2000
            },
            'van': {
                'base_fare': 1500,
                'per_km': 600,
                'per_minute': 150,
                'minimum_fare': 3000
            },
            'bus': {
                'base_fare': 2000,
                'per_km': 800,
                'per_minute': 200,
                'minimum_fare': 4000
            }
        }
    
    def calculate_fare(self, pickup_lat: float, pickup_lon: float, 
                      dropoff_lat: float, dropoff_lon: float, 
                      vehicle_type: str = 'car') -> Dict[str, Any]:
        """Calculate fare for a ride"""
        
        # Calculate distance
        distance_km = self._calculate_distance(
            pickup_lat, pickup_lon, dropoff_lat, dropoff_lon
        )
        
        # Calculate duration (simplified - in production, use routing service)
        duration_minutes = self._estimate_duration(distance_km)
        
        # Get rates for vehicle type
        rates = self.base_rates.get(vehicle_type, self.base_rates['car'])
        
        # Calculate fare components
        base_fare = Decimal(str(rates['base_fare']))
        distance_fare = Decimal(str(rates['per_km'])) * Decimal(str(distance_km))
        time_fare = Decimal(str(rates['per_minute'])) * Decimal(str(duration_minutes))
        
        # Calculate total fare
        total_fare = base_fare + distance_fare + time_fare
        
        # Apply minimum fare
        minimum_fare = Decimal(str(rates['minimum_fare']))
        if total_fare < minimum_fare:
            total_fare = minimum_fare
        
        # Apply surge pricing (simplified)
        surge_multiplier = self._calculate_surge_multiplier(pickup_lat, pickup_lon)
        total_fare = total_fare * Decimal(str(surge_multiplier))
        
        return {
            'distance_km': round(distance_km, 2),
            'duration_minutes': duration_minutes,
            'base_fare': float(base_fare),
            'distance_fare': float(distance_fare),
            'time_fare': float(time_fare),
            'surge_multiplier': surge_multiplier,
            'total_fare': float(total_fare),
            'currency': 'RWF',
            'vehicle_type': vehicle_type,
            'breakdown': {
                'base_fare': float(base_fare),
                'distance_fare': float(distance_fare),
                'time_fare': float(time_fare),
                'surge_charge': float(total_fare - (base_fare + distance_fare + time_fare))
            }
        }
    
    def _calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two points in kilometers"""
        
        # Convert to radians
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        
        # Haversine formula
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * asin(sqrt(a))
        r = 6371  # Earth's radius in kilometers
        
        return c * r
    
    def _estimate_duration(self, distance_km: float) -> int:
        """Estimate ride duration in minutes"""
        
        # Simplified duration calculation
        # Assume average speed of 30 km/h in city
        duration_hours = distance_km / 30
        duration_minutes = int(duration_hours * 60)
        
        # Minimum 5 minutes, maximum 120 minutes
        return max(5, min(duration_minutes, 120))
    
    def _calculate_surge_multiplier(self, lat: float, lon: float) -> float:
        """Calculate surge pricing multiplier"""
        
        # Simplified surge calculation
        # In production, this would consider:
        # - Time of day
        # - Weather conditions
        # - Demand patterns
        # - Special events
        
        # For now, return 1.0 (no surge)
        return 1.0
    
    def get_fare_estimate(self, pickup_lat: float, pickup_lon: float,
                         dropoff_lat: float, dropoff_lon: float,
                         vehicle_types: list = None) -> Dict[str, Any]:
        """Get fare estimates for multiple vehicle types"""
        
        if vehicle_types is None:
            vehicle_types = ['motorcycle', 'car', 'van', 'bus']
        
        estimates = {}
        
        for vehicle_type in vehicle_types:
            if vehicle_type in self.base_rates:
                fare_data = self.calculate_fare(
                    pickup_lat, pickup_lon, dropoff_lat, dropoff_lon, vehicle_type
                )
                estimates[vehicle_type] = {
                    'total_fare': fare_data['total_fare'],
                    'currency': fare_data['currency'],
                    'distance_km': fare_data['distance_km'],
                    'duration_minutes': fare_data['duration_minutes']
                }
        
        return {
            'estimates': estimates,
            'pickup': {'latitude': pickup_lat, 'longitude': pickup_lon},
            'dropoff': {'latitude': dropoff_lat, 'longitude': dropoff_lon}
        }