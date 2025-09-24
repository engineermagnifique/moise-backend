# apps/payments/models.py
import uuid
from django.db import models
from django.contrib.auth import get_user_model
from apps.common.models import TimestampedModel

User = get_user_model()

class MobileMoneyProvider(TimestampedModel):
    """Mobile Money providers like MTN, Airtel, etc."""
    
    provider_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=20, unique=True)  # MTN_MOMO, AIRTEL_MONEY
    
    # Configuration
    is_active = models.BooleanField(default=True)
    api_config = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'mobile_money_providers'
        verbose_name = 'Mobile Money Provider'
        verbose_name_plural = 'Mobile Money Providers'

    def __str__(self):
        return f"{self.name} ({self.code})"

class PaymentMethod(TimestampedModel):
    """Available payment methods"""
    
    PAYMENT_TYPES = [
        ('mobile_money', 'Mobile Money'),
        ('bank_transfer', 'Bank Transfer'),
        ('credit_card', 'Credit Card'),
        ('cash', 'Cash'),
    ]
    
    method_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=50, unique=True)  # mtn_momo, airtel_money, etc.
    payment_type = models.CharField(max_length=20, choices=PAYMENT_TYPES)
    provider = models.CharField(max_length=100)  # MTN, Airtel, Bank name, etc.
    
    # Mobile Money Provider relationship
    mobile_money_provider = models.ForeignKey(
        MobileMoneyProvider, 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True,
        related_name='payment_methods'
    )
    
    # Configuration
    is_active = models.BooleanField(default=True)
    requires_external_integration = models.BooleanField(default=False)
    min_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    max_amount = models.DecimalField(max_digits=10, decimal_places=2, default=1000000)
    supported_currencies = models.JSONField(default=list)
    
    # Fees
    fixed_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    percentage_fee = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    
    # Metadata
    description = models.TextField(blank=True)
    icon_url = models.URLField(blank=True)
    api_config = models.JSONField(default=dict)  # Store API configuration
    
    class Meta:
        db_table = 'payment_methods'
        verbose_name = 'Payment Method'
        verbose_name_plural = 'Payment Methods'

    def __str__(self):
        return f"{self.name} ({self.provider})"

class PaymentTransaction(TimestampedModel):
    """Payment transaction records"""
    
    TRANSACTION_STATUS = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('successful', 'Successful'),  # Added for compatibility
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
        ('refunded', 'Refunded'),
    ]
    
    TRANSACTION_TYPES = [
        ('general', 'General Payment'),
        ('business_listing', 'Business Listing'),
        ('premium_features', 'Premium Features'),
        ('advertisement', 'Advertisement'),
        ('service_booking', 'Service Booking'),
    ]
    
    transaction_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payment_transactions')
    
    # Business relationship (optional)
    business = models.ForeignKey(
        'businesses.Business', 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True,
        related_name='payment_transactions'
    )
    
    # Payment Method
    payment_method = models.ForeignKey(
        PaymentMethod, 
        on_delete=models.CASCADE,
        related_name='transactions'
    )
    
    # Transaction Details
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='RWF')
    status = models.CharField(max_length=20, choices=TRANSACTION_STATUS, default='pending')
    transaction_type = models.CharField(max_length=30, choices=TRANSACTION_TYPES, default='general')
    
    # External References
    external_reference = models.CharField(max_length=100, blank=True)
    provider_transaction_id = models.CharField(max_length=100, blank=True)
    related_object_id = models.CharField(max_length=100, blank=True)  # ID of related object (listing, ad, etc.)
    
    # Payer Information
    payer_phone_number = models.CharField(max_length=20, blank=True)
    payer_email = models.EmailField(blank=True)
    phone_number = models.CharField(max_length=20, blank=True)  # For compatibility
    account_number = models.CharField(max_length=50, blank=True)
    description = models.TextField(blank=True)
    
    # Fees and Amounts
    processing_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    # Timestamps
    initiated_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    # Failure Information
    failure_reason = models.TextField(blank=True)
    failure_code = models.CharField(max_length=50, blank=True)
    
    # Provider Response Data
    provider_response = models.JSONField(default=dict)
    
    # Metadata
    metadata = models.JSONField(default=dict)
    callback_data = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'payment_transactions'
        verbose_name = 'Payment Transaction'
        verbose_name_plural = 'Payment Transactions'
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['external_reference']),
            models.Index(fields=['created_at']),
            models.Index(fields=['provider_transaction_id']),
        ]

    def __str__(self):
        return f"Transaction {self.transaction_id} - {self.amount} {self.currency}"

    def save(self, *args, **kwargs):
        # Calculate total amount including fees
        if not self.total_amount:
            self.total_amount = self.amount + self.processing_fee
        
        # Copy phone number for compatibility
        if self.payer_phone_number and not self.phone_number:
            self.phone_number = self.payer_phone_number
            
        super().save(*args, **kwargs)

class PaymentRefund(TimestampedModel):
    """Payment refund records"""
    
    REFUND_STATUS = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    refund_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    transaction = models.ForeignKey(PaymentTransaction, on_delete=models.CASCADE, related_name='refunds')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    
    # Refund Details
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    reason = models.TextField()
    status = models.CharField(max_length=20, choices=REFUND_STATUS, default='pending')
    
    # External References
    external_reference = models.CharField(max_length=100, blank=True)
    provider_refund_id = models.CharField(max_length=100, blank=True)
    
    # Timestamps
    requested_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    
    # Failure Information
    failure_reason = models.TextField(blank=True)
    
    class Meta:
        db_table = 'payment_refunds'
        verbose_name = 'Payment Refund'
        verbose_name_plural = 'Payment Refunds'

    def __str__(self):
        return f"Refund {self.refund_id} - {self.amount} {self.transaction.currency}"