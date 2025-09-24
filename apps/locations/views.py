# apps/locations/views.py
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, extend_schema_view
from django.db.models import Q

from .models import RwandaProvince, RwandaDistrict, RwandaSector, RwandaCell
from .serializers import (
    ProvinceSerializer, DistrictSerializer, SectorSerializer, CellSerializer,
    GeocodeSerializer, ReverseGeocodeSerializer, LocationSearchSerializer
)
from .services.geolocation_service import GeolocationService

@extend_schema_view(
    get=extend_schema(
        summary="List Provinces",
        description="Get all Rwanda provinces",
        tags=["Locations"]
    )
)
class ProvinceListView(generics.ListAPIView):
    """List all provinces"""
    
    queryset = RwandaProvince.objects.all()
    serializer_class = ProvinceSerializer
    permission_classes = [permissions.AllowAny]

@extend_schema_view(
    get=extend_schema(
        summary="Get Province Details",
        description="Get detailed information about a specific province",
        tags=["Locations"]
    )
)
class ProvinceDetailView(generics.RetrieveAPIView):
    """Get province details"""
    
    queryset = RwandaProvince.objects.all()
    serializer_class = ProvinceSerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = 'province_id'

@extend_schema_view(
    get=extend_schema(
        summary="List Districts",
        description="Get all districts or districts in a specific province",
        tags=["Locations"]
    )
)
class DistrictListView(generics.ListAPIView):
    """List all districts"""
    
    queryset = RwandaDistrict.objects.all()
    serializer_class = DistrictSerializer
    permission_classes = [permissions.AllowAny]

@extend_schema_view(
    get=extend_schema(
        summary="Get District Details",
        description="Get detailed information about a specific district",
        tags=["Locations"]
    )
)
class DistrictDetailView(generics.RetrieveAPIView):
    """Get district details"""
    
    queryset = RwandaDistrict.objects.all()
    serializer_class = DistrictSerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = 'district_id'

@extend_schema_view(
    get=extend_schema(
        summary="Get Province Districts",
        description="Get all districts in a specific province",
        tags=["Locations"]
    )
)
class ProvinceDistrictsView(generics.ListAPIView):
    """Get districts in a province"""
    
    serializer_class = DistrictSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        province_id = self.kwargs['province_id']
        return RwandaDistrict.objects.filter(province_id=province_id)

@extend_schema_view(
    get=extend_schema(
        summary="List Sectors",
        description="Get all sectors or sectors in a specific district",
        tags=["Locations"]
    )
)
class SectorListView(generics.ListAPIView):
    """List all sectors"""
    
    queryset = RwandaSector.objects.all()
    serializer_class = SectorSerializer
    permission_classes = [permissions.AllowAny]

@extend_schema_view(
    get=extend_schema(
        summary="Get Sector Details",
        description="Get detailed information about a specific sector",
        tags=["Locations"]
    )
)
class SectorDetailView(generics.RetrieveAPIView):
    """Get sector details"""
    
    queryset = RwandaSector.objects.all()
    serializer_class = SectorSerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = 'sector_id'

@extend_schema_view(
    get=extend_schema(
        summary="Get District Sectors",
        description="Get all sectors in a specific district",
        tags=["Locations"]
    )
)
class DistrictSectorsView(generics.ListAPIView):
    """Get sectors in a district"""
    
    serializer_class = SectorSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        district_id = self.kwargs['district_id']
        return RwandaSector.objects.filter(district_id=district_id)

@extend_schema_view(
    get=extend_schema(
        summary="List Cells",
        description="Get all cells or cells in a specific sector",
        tags=["Locations"]
    )
)
class CellListView(generics.ListAPIView):
    """List all cells"""
    
    queryset = RwandaCell.objects.all()
    serializer_class = CellSerializer
    permission_classes = [permissions.AllowAny]

@extend_schema_view(
    get=extend_schema(
        summary="Get Cell Details",
        description="Get detailed information about a specific cell",
        tags=["Locations"]
    )
)
class CellDetailView(generics.RetrieveAPIView):
    """Get cell details"""
    
    queryset = RwandaCell.objects.all()
    serializer_class = CellSerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = 'cell_id'

@extend_schema_view(
    get=extend_schema(
        summary="Get Sector Cells",
        description="Get all cells in a specific sector",
        tags=["Locations"]
    )
)
class SectorCellsView(generics.ListAPIView):
    """Get cells in a sector"""
    
    serializer_class = CellSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        sector_id = self.kwargs['sector_id']
        return RwandaCell.objects.filter(sector_id=sector_id)

@extend_schema_view(
    post=extend_schema(
        summary="Geocode Address",
        description="Convert address to coordinates",
        tags=["Locations"]
    )
)
class GeocodeView(generics.GenericAPIView):
    """Geocode address to coordinates"""
    
    serializer_class = GeocodeSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """Geocode address"""
        try:
            address = request.data.get('address', '')
            
            geolocation_service = GeolocationService()
            result = geolocation_service.geocode(address)
            
            return Response({
                'success': True,
                'data': result
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'geocoding_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    post=extend_schema(
        summary="Reverse Geocode Coordinates",
        description="Convert coordinates to address",
        tags=["Locations"]
    )
)
class ReverseGeocodeView(generics.GenericAPIView):
    """Reverse geocode coordinates to address"""
    
    serializer_class = ReverseGeocodeSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """Reverse geocode coordinates"""
        try:
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
            
            geolocation_service = GeolocationService()
            result = geolocation_service.reverse_geocode(float(latitude), float(longitude))
            
            return Response({
                'success': True,
                'data': result
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'reverse_geocoding_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    get=extend_schema(
        summary="Search Locations",
        description="Search for locations by name",
        tags=["Locations"]
    )
)
class LocationSearchView(generics.GenericAPIView):
    """Search locations by name"""
    
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        """Search locations"""
        try:
            query = request.query_params.get('q', '')
            location_type = request.query_params.get('type', 'all')  # all, province, district, sector, cell
            
            if not query:
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Search query is required',
                        'code': 'missing_query'
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
            
            results = []
            
            # Search provinces
            if location_type in ['all', 'province']:
                provinces = RwandaProvince.objects.filter(
                    Q(name__icontains=query) |
                    Q(name_kinyarwanda__icontains=query) |
                    Q(name_french__icontains=query)
                )[:5]
                
                for province in provinces:
                    results.append({
                        'type': 'province',
                        'id': str(province.province_id),
                        'name': province.name,
                        'name_kinyarwanda': province.name_kinyarwanda,
                        'name_french': province.name_french,
                        'latitude': float(province.latitude),
                        'longitude': float(province.longitude)
                    })
            
            # Search districts
            if location_type in ['all', 'district']:
                districts = RwandaDistrict.objects.filter(
                    Q(name__icontains=query) |
                    Q(name_kinyarwanda__icontains=query) |
                    Q(name_french__icontains=query)
                )[:5]
                
                for district in districts:
                    results.append({
                        'type': 'district',
                        'id': str(district.district_id),
                        'name': district.name,
                        'name_kinyarwanda': district.name_kinyarwanda,
                        'name_french': district.name_french,
                        'province': district.province.name,
                        'latitude': float(district.latitude),
                        'longitude': float(district.longitude)
                    })
            
            # Search sectors
            if location_type in ['all', 'sector']:
                sectors = RwandaSector.objects.filter(
                    Q(name__icontains=query) |
                    Q(name_kinyarwanda__icontains=query) |
                    Q(name_french__icontains=query)
                )[:5]
                
                for sector in sectors:
                    results.append({
                        'type': 'sector',
                        'id': str(sector.sector_id),
                        'name': sector.name,
                        'name_kinyarwanda': sector.name_kinyarwanda,
                        'name_french': sector.name_french,
                        'district': sector.district.name,
                        'province': sector.district.province.name,
                        'latitude': float(sector.latitude) if sector.latitude else None,
                        'longitude': float(sector.longitude) if sector.longitude else None
                    })
            
            # Search cells
            if location_type in ['all', 'cell']:
                cells = RwandaCell.objects.filter(
                    Q(name__icontains=query) |
                    Q(name_kinyarwanda__icontains=query)
                )[:5]
                
                for cell in cells:
                    results.append({
                        'type': 'cell',
                        'id': str(cell.cell_id),
                        'name': cell.name,
                        'name_kinyarwanda': cell.name_kinyarwanda,
                        'sector': cell.sector.name,
                        'district': cell.sector.district.name,
                        'province': cell.sector.district.province.name,
                        'latitude': float(cell.latitude) if cell.latitude else None,
                        'longitude': float(cell.longitude) if cell.longitude else None
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
                    'code': 'search_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

