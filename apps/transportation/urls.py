# apps/transportation/urls.py
from django.urls import path
from . import views

app_name = 'transportation'

urlpatterns = [
    # Ride Services
    path('rides/', views.RideListView.as_view(), name='ride-list'),
    path('rides/create/', views.RideCreateView.as_view(), name='ride-create'),
    path('rides/<uuid:ride_id>/', views.RideDetailView.as_view(), name='ride-detail'),
    path('rides/<uuid:ride_id>/accept/', views.RideAcceptView.as_view(), name='ride-accept'),
    path('rides/<uuid:ride_id>/complete/', views.RideCompleteView.as_view(), name='ride-complete'),
    path('rides/<uuid:ride_id>/cancel/', views.RideCancelView.as_view(), name='ride-cancel'),
    
    # Fare Calculation
    path('fare/calculate/', views.FareCalculationView.as_view(), name='fare-calculate'),
    
    # Vehicle Types
    path('vehicle-types/', views.VehicleTypeListView.as_view(), name='vehicle-type-list'),
    
    # Driver Management
    path('drivers/', views.DriverListView.as_view(), name='driver-list'),
    path('drivers/<uuid:driver_id>/', views.DriverDetailView.as_view(), name='driver-detail'),
    path('drivers/<uuid:driver_id>/location/', views.DriverLocationView.as_view(), name='driver-location'),
    
    # Transportation Analytics
    path('analytics/', views.TransportationAnalyticsView.as_view(), name='transportation-analytics'),
]