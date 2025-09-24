# apps/locations/urls.py
from django.urls import path
from . import views

app_name = 'locations'

urlpatterns = [
    # Provinces
    path('provinces/', views.ProvinceListView.as_view(), name='provinces'),
    path('provinces/<uuid:province_id>/', views.ProvinceDetailView.as_view(), name='province-detail'),
    
    # Districts
    path('districts/', views.DistrictListView.as_view(), name='districts'),
    path('districts/<uuid:district_id>/', views.DistrictDetailView.as_view(), name='district-detail'),
    path('provinces/<uuid:province_id>/districts/', views.ProvinceDistrictsView.as_view(), name='province-districts'),
    
    # Sectors
    path('sectors/', views.SectorListView.as_view(), name='sectors'),
    path('sectors/<uuid:sector_id>/', views.SectorDetailView.as_view(), name='sector-detail'),
    path('districts/<uuid:district_id>/sectors/', views.DistrictSectorsView.as_view(), name='district-sectors'),
    
    # Cells
    path('cells/', views.CellListView.as_view(), name='cells'),
    path('cells/<uuid:cell_id>/', views.CellDetailView.as_view(), name='cell-detail'),
    path('sectors/<uuid:sector_id>/cells/', views.SectorCellsView.as_view(), name='sector-cells'),
    
    # Location utilities
    path('geocode/', views.GeocodeView.as_view(), name='geocode'),
    path('reverse-geocode/', views.ReverseGeocodeView.as_view(), name='reverse-geocode'),
    path('search/', views.LocationSearchView.as_view(), name='location-search'),
]

