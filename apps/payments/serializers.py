# apps/payments/serializers.py
from rest_framework import serializers
from .models import PaymentTransaction, PaymentMethod, PaymentRefund

class PaymentMethodSerializer(serializers.ModelSerializer):
    """Payment method serializer"""
    
    class Meta:
        model = PaymentMethod
        fields = [
            'method_id', 'name', 'payment_type', 'provider',
            'is_active', 'min_amount', 'max_amount', 'supported_currencies',
            'fixed_fee', 'percentage_fee', 'description', 'icon_url'
        ]
        read_only_fields = ['method_id']

class PaymentTransactionSerializer(serializers.ModelSerializer):
    """Payment transaction serializer"""
    
    class Meta:
        model = PaymentTransaction
        fields = [
            'transaction_id', 'user', 'amount', 'currency', 'payment_method',
            'status', 'external_reference', 'phone_number', 'account_number',
            'description', 'processing_fee', 'total_amount', 'initiated_at',
            'completed_at', 'expires_at', 'failure_reason', 'failure_code'
        ]
        read_only_fields = ['transaction_id', 'initiated_at', 'completed_at']

class PaymentRefundSerializer(serializers.ModelSerializer):
    """Payment refund serializer"""
    
    class Meta:
        model = PaymentRefund
        fields = [
            'refund_id', 'transaction', 'user', 'amount', 'reason',
            'status', 'external_reference', 'requested_at', 'processed_at',
            'failure_reason'
        ]
        read_only_fields = ['refund_id', 'requested_at', 'processed_at']