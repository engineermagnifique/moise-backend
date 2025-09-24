# apps/locations/models.py
import uuid
from django.db import models

class RwandaProvince(models.Model):
    """Rwanda provinces with detailed information"""
    
    province_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    name_kinyarwanda = models.CharField(max_length=100)
    name_french = models.CharField(max_length=100)
    
    # Geographic data
    latitude = models.DecimalField(max_digits=10, decimal_places=8)
    longitude = models.DecimalField(max_digits=11, decimal_places=8)
    area_km2 = models.FloatField()
    population = models.IntegerField(null=True, blank=True)
    
    # Boundaries (GeoJSON format)
    boundaries = models.JSONField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'rwanda_provinces'

    def __str__(self):
        return self.name

class RwandaDistrict(models.Model):
    """Rwanda districts"""
    
    district_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    province = models.ForeignKey(RwandaProvince, on_delete=models.CASCADE, related_name='districts')
    
    name = models.CharField(max_length=100)
    name_kinyarwanda = models.CharField(max_length=100)
    name_french = models.CharField(max_length=100)
    
    # Geographic data
    latitude = models.DecimalField(max_digits=10, decimal_places=8)
    longitude = models.DecimalField(max_digits=11, decimal_places=8)
    area_km2 = models.FloatField()
    population = models.IntegerField(null=True, blank=True)
    
    # Boundaries
    boundaries = models.JSONField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'rwanda_districts'
        unique_together = ['province', 'name']

    def __str__(self):
        return f"{self.name}, {self.province.name}"

class RwandaSector(models.Model):
    """Rwanda sectors"""
    
    sector_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    district = models.ForeignKey(RwandaDistrict, on_delete=models.CASCADE, related_name='sectors')
    
    name = models.CharField(max_length=100)
    name_kinyarwanda = models.CharField(max_length=100)
    name_french = models.CharField(max_length=100, blank=True)
    
    # Geographic data
    latitude = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    longitude = models.DecimalField(max_digits=11, decimal_places=8, null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'rwanda_sectors'
        unique_together = ['district', 'name']

    def __str__(self):
        return f"{self.name}, {self.district.name}"

class RwandaCell(models.Model):
    """Rwanda cells"""
    
    cell_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sector = models.ForeignKey(RwandaSector, on_delete=models.CASCADE, related_name='cells')
    
    name = models.CharField(max_length=100)
    name_kinyarwanda = models.CharField(max_length=100)
    
    # Geographic data
    latitude = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    longitude = models.DecimalField(max_digits=11, decimal_places=8, null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'rwanda_cells'
        unique_together = ['sector', 'name']

    def __str__(self):
        return f"{self.name}, {self.sector.name}"