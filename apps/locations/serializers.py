# apps/locations/serializers.py
from rest_framework import serializers
from .models import RwandaProvince, RwandaDistrict, RwandaSector, RwandaCell

class ProvinceSerializer(serializers.ModelSerializer):
    """Province serializer"""
    
    class Meta:
        model = RwandaProvince
        fields = [
            'province_id', 'name', 'name_kinyarwanda', 'name_french',
            'latitude', 'longitude', 'area_km2', 'population',
            'boundaries', 'created_at'
        ]
        read_only_fields = ['province_id', 'created_at']

class DistrictSerializer(serializers.ModelSerializer):
    """District serializer"""
    
    province_name = serializers.CharField(source='province.name', read_only=True)
    
    class Meta:
        model = RwandaDistrict
        fields = [
            'district_id', 'province', 'province_name', 'name', 'name_kinyarwanda',
            'name_french', 'latitude', 'longitude', 'area_km2', 'population',
            'boundaries', 'created_at'
        ]
        read_only_fields = ['district_id', 'created_at']

class SectorSerializer(serializers.ModelSerializer):
    """Sector serializer"""
    
    district_name = serializers.CharField(source='district.name', read_only=True)
    province_name = serializers.CharField(source='district.province.name', read_only=True)
    
    class Meta:
        model = RwandaSector
        fields = [
            'sector_id', 'district', 'district_name', 'province_name', 'name',
            'name_kinyarwanda', 'name_french', 'latitude', 'longitude', 'created_at'
        ]
        read_only_fields = ['sector_id', 'created_at']

class CellSerializer(serializers.ModelSerializer):
    """Cell serializer"""
    
    sector_name = serializers.CharField(source='sector.name', read_only=True)
    district_name = serializers.CharField(source='sector.district.name', read_only=True)
    province_name = serializers.CharField(source='sector.district.province.name', read_only=True)
    
    class Meta:
        model = RwandaCell
        fields = [
            'cell_id', 'sector', 'sector_name', 'district_name', 'province_name',
            'name', 'name_kinyarwanda', 'latitude', 'longitude', 'created_at'
        ]
        read_only_fields = ['cell_id', 'created_at']

class GeocodeSerializer(serializers.Serializer):
    """Geocode serializer"""
    
    address = serializers.CharField()

class ReverseGeocodeSerializer(serializers.Serializer):
    """Reverse geocode serializer"""
    
    latitude = serializers.FloatField()
    longitude = serializers.FloatField()

class LocationSearchSerializer(serializers.Serializer):
    """Location search serializer"""
    
    q = serializers.CharField()
    type = serializers.ChoiceField(choices=['all', 'province', 'district', 'sector', 'cell'], default='all')

