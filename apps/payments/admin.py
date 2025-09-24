# apps/payments/admin.py
from django.contrib import admin
from .models import MobileMoneyProvider, PaymentMethod, PaymentTransaction, PaymentRefund

@admin.register(MobileMoneyProvider)
class MobileMoneyProviderAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'code']
    readonly_fields = ['provider_id', 'created_at', 'updated_at']

@admin.register(PaymentMethod)
class PaymentMethodAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'payment_type', 'provider', 'is_active']
    list_filter = ['payment_type', 'is_active', 'requires_external_integration']
    search_fields = ['name', 'code', 'provider']
    readonly_fields = ['method_id', 'created_at', 'updated_at']

@admin.register(PaymentTransaction)
class PaymentTransactionAdmin(admin.ModelAdmin):
    list_display = ['transaction_id', 'user', 'amount', 'currency', 'status', 'payment_method', 'created_at']
    list_filter = ['status', 'transaction_type', 'currency', 'created_at']
    search_fields = ['transaction_id', 'user__email', 'user__first_name', 'user__last_name', 'provider_transaction_id']
    readonly_fields = ['transaction_id', 'created_at', 'updated_at']
    raw_id_fields = ['user', 'business']

@admin.register(PaymentRefund)
class PaymentRefundAdmin(admin.ModelAdmin):
    list_display = ['refund_id', 'transaction', 'user', 'amount', 'status', 'requested_at']
    list_filter = ['status', 'requested_at']
    search_fields = ['refund_id', 'transaction__transaction_id', 'user__email']
    readonly_fields = ['refund_id', 'requested_at', 'created_at', 'updated_at']
    raw_id_fields = ['transaction', 'user']