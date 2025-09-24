
# apps/businesses/urls.py
from django.urls import path
from . import views

app_name = 'businesses'

urlpatterns = [
    # Categories
    path('categories/', views.BusinessCategoryListView.as_view(), name='categories'),
    
    # Business CRUD
    path('', views.BusinessListView.as_view(), name='business-list'),
    path('nearby/', views.NearbyBusinessesView.as_view(), name='nearby-businesses'),
    path('create/', views.BusinessCreateView.as_view(), name='business-create'),
    path('<uuid:business_id>/', views.BusinessDetailView.as_view(), name='business-detail'),
    path('<uuid:business_id>/update/', views.BusinessUpdateView.as_view(), name='business-update'),
    
    # Reviews
    path('<uuid:business_id>/reviews/', views.BusinessReviewView.as_view(), name='business-reviews'),
]