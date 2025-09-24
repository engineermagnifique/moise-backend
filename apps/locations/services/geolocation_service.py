# apps/locations/services/geolocation_service.py
from typing import Dict, Any, Optional, Tuple
import requests
from django.conf import settings

class GeolocationService:
    """Service for geolocation operations"""
    
    def __init__(self):
        self.google_api_key = getattr(settings, 'GOOGLE_MAPS_API_KEY', '')
        self.nominatim_base_url = 'https://nominatim.openstreetmap.org'
    
    def geocode(self, address: str) -> Dict[str, Any]:
        """Convert address to coordinates using OpenStreetMap Nominatim"""
        
        try:
            # Use OpenStreetMap Nominatim for geocoding
            params = {
                'q': address,
                'format': 'json',
                'limit': 1,
                'countrycodes': 'rw',  # Limit to Rwanda
                'addressdetails': 1
            }
            
            response = requests.get(
                f"{self.nominatim_base_url}/search",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data:
                    result = data[0]
                    return {
                        'latitude': float(result['lat']),
                        'longitude': float(result['lon']),
                        'formatted_address': result.get('display_name', ''),
                        'address_components': self._parse_address_components(result.get('address', {})),
                        'confidence': 0.8  # Placeholder confidence
                    }
                else:
                    return {
                        'error': 'No results found',
                        'latitude': None,
                        'longitude': None
                    }
            else:
                return {
                    'error': f'Geocoding service error: {response.status_code}',
                    'latitude': None,
                    'longitude': None
                }
                
        except Exception as e:
            return {
                'error': f'Geocoding failed: {str(e)}',
                'latitude': None,
                'longitude': None
            }
    
    def reverse_geocode(self, latitude: float, longitude: float) -> Dict[str, Any]:
        """Convert coordinates to address using OpenStreetMap Nominatim"""
        
        try:
            params = {
                'lat': latitude,
                'lon': longitude,
                'format': 'json',
                'addressdetails': 1,
                'zoom': 18  # High detail level
            }
            
            response = requests.get(
                f"{self.nominatim_base_url}/reverse",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data and 'address' in data:
                    return {
                        'formatted_address': data.get('display_name', ''),
                        'address_components': self._parse_address_components(data['address']),
                        'latitude': latitude,
                        'longitude': longitude
                    }
                else:
                    return {
                        'error': 'No address found for coordinates',
                        'formatted_address': None
                    }
            else:
                return {
                    'error': f'Reverse geocoding service error: {response.status_code}',
                    'formatted_address': None
                }
                
        except Exception as e:
            return {
                'error': f'Reverse geocoding failed: {str(e)}',
                'formatted_address': None
            }
    
    def _parse_address_components(self, address: Dict[str, Any]) -> Dict[str, Any]:
        """Parse address components from geocoding response"""
        
        components = {
            'country': address.get('country', ''),
            'country_code': address.get('country_code', ''),
            'state': address.get('state', ''),
            'province': address.get('state', ''),  # Rwanda uses state as province
            'city': address.get('city', '') or address.get('town', '') or address.get('village', ''),
            'district': address.get('county', ''),
            'sector': address.get('suburb', ''),
            'cell': address.get('neighbourhood', ''),
            'street': address.get('road', ''),
            'house_number': address.get('house_number', ''),
            'postcode': address.get('postcode', '')
        }
        
        return components
    
    def calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
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
    
    def is_in_rwanda(self, latitude: float, longitude: float) -> bool:
        """Check if coordinates are within Rwanda boundaries"""
        
        # Rwanda approximate boundaries
        rwanda_bounds = {
            'north': -1.0,
            'south': -2.8,
            'east': 30.9,
            'west': 28.9
        }
        
        return (
            rwanda_bounds['south'] <= latitude <= rwanda_bounds['north'] and
            rwanda_bounds['west'] <= longitude <= rwanda_bounds['east']
        )
    
    def get_nearby_locations(self, latitude: float, longitude: float, radius_km: float = 5) -> Dict[str, Any]:
        """Get nearby locations within radius"""
        
        try:
            params = {
                'lat': latitude,
                'lon': longitude,
                'radius': radius_km * 1000,  # Convert to meters
                'format': 'json',
                'addressdetails': 1
            }
            
            response = requests.get(
                f"{self.nominatim_base_url}/reverse",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'locations': data
                }
            else:
                return {
                    'success': False,
                    'error': f'Service error: {response.status_code}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to get nearby locations: {str(e)}'
            }
    
    def validate_coordinates(self, latitude: float, longitude: float) -> Dict[str, Any]:
        """Validate coordinates and check if they're in Rwanda"""
        
        is_valid = (
            -90 <= latitude <= 90 and
            -180 <= longitude <= 180
        )
        
        is_in_rwanda = self.is_in_rwanda(latitude, longitude) if is_valid else False
        
        return {
            'is_valid': is_valid,
            'is_in_rwanda': is_in_rwanda,
            'latitude': latitude,
            'longitude': longitude
        }