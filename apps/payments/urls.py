# apps/payments/urls.py
from django.urls import path
from . import views

app_name = 'payments'

urlpatterns = [
    # Mobile Money
    path('momo/initiate/', views.MTNMoMoInitiateView.as_view(), name='momo-initiate'),
    path('momo/callback/', views.MTNMoMoCallbackView.as_view(), name='momo-callback'),
    path('airtel/initiate/', views.AirtelMoneyInitiateView.as_view(), name='airtel-initiate'),
    path('airtel/callback/', views.AirtelMoneyCallbackView.as_view(), name='airtel-callback'),
    
    # Payment Management
    path('transactions/', views.TransactionListView.as_view(), name='transaction-list'),
    path('transactions/<uuid:transaction_id>/', views.TransactionDetailView.as_view(), name='transaction-detail'),
    path('transactions/<uuid:transaction_id>/status/', views.TransactionStatusView.as_view(), name='transaction-status'),
    
    # Payment Methods
    path('methods/', views.PaymentMethodListView.as_view(), name='payment-methods'),
    path('methods/<uuid:method_id>/', views.PaymentMethodDetailView.as_view(), name='payment-method-detail'),
]