# apps/payments/views.py
import logging
from decimal import Decimal
from django.db import models
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from django.utils import timezone
from django.shortcuts import get_object_or_404

from .models import PaymentTransaction, PaymentMethod, PaymentRefund
from .serializers import PaymentTransactionSerializer, PaymentMethodSerializer, PaymentRefundSerializer
from .services.mobile_money_service import MobileMoneyService
from apps.common.exceptions import BusiMapException

logger = logging.getLogger(__name__)

@extend_schema_view(
    get=extend_schema(
        summary="List Transactions",
        description="Get user's payment transactions",
        tags=["Payments"]
    )
)
class TransactionListView(generics.ListAPIView):
    """List user transactions"""
    
    serializer_class = PaymentTransactionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return PaymentTransaction.objects.filter(user=self.request.user).order_by('-created_at')

@extend_schema_view(
    get=extend_schema(
        summary="Get Transaction Details",
        description="Get details of a specific transaction",
        tags=["Payments"]
    )
)
class TransactionDetailView(generics.RetrieveAPIView):
    """Get transaction details"""
    
    serializer_class = PaymentTransactionSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'transaction_id'

    def get_queryset(self):
        return PaymentTransaction.objects.filter(user=self.request.user)

@extend_schema_view(
    get=extend_schema(
        summary="Get Transaction Status",
        description="Get the current status of a transaction",
        tags=["Payments"]
    )
)
class TransactionStatusView(APIView):
    """Get transaction status"""
    
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, transaction_id):
        try:
            transaction = get_object_or_404(
                PaymentTransaction, 
                transaction_id=transaction_id, 
                user=request.user
            )
            
            data = {
                'transaction_id': str(transaction.transaction_id),
                'status': transaction.status,
                'amount': float(transaction.amount),
                'currency': transaction.currency,
                'payment_method': transaction.payment_method,
                'created_at': transaction.initiated_at.isoformat(),
                'completed_at': transaction.completed_at.isoformat() if transaction.completed_at else None,
                'failure_reason': transaction.failure_reason if transaction.failure_reason else None
            }
            
            return Response(data)
        except Exception as e:
            logger.error(f"Error getting transaction status: {e}")
            return Response(
                {'error': 'Failed to get transaction status'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@extend_schema_view(
    get=extend_schema(
        summary="List Payment Methods",
        description="Get available payment methods",
        tags=["Payments"]
    )
)
class PaymentMethodListView(generics.ListAPIView):
    """List available payment methods"""
    
    queryset = PaymentMethod.objects.filter(is_active=True)
    serializer_class = PaymentMethodSerializer
    permission_classes = [permissions.AllowAny]

@extend_schema_view(
    get=extend_schema(
        summary="Get Payment Method Details",
        description="Get details of a specific payment method",
        tags=["Payments"]
    )
)
class PaymentMethodDetailView(generics.RetrieveAPIView):
    """Get payment method details"""
    
    queryset = PaymentMethod.objects.filter(is_active=True)
    serializer_class = PaymentMethodSerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = 'method_id'

# Mobile Money Payment Views

@extend_schema_view(
    post=extend_schema(
        summary="Initiate MTN MoMo Payment",
        description="Initiate a payment using MTN Mobile Money",
        tags=["Mobile Money"],
        request={
            'application/json': {
                'type': 'object',
                'properties': {
                    'amount': {'type': 'number', 'description': 'Payment amount'},
                    'phone_number': {'type': 'string', 'description': 'Phone number for payment'},
                    'business_id': {'type': 'string', 'description': 'Optional business ID', 'nullable': True},
                    'transaction_type': {'type': 'string', 'description': 'Type of transaction', 'default': 'general'},
                    'description': {'type': 'string', 'description': 'Payment description', 'nullable': True}
                },
                'required': ['amount', 'phone_number']
            }
        }
    )
)
class MTNMoMoInitiateView(APIView):
    """Initiate MTN Mobile Money payment"""
    
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            # Get request data
            amount = request.data.get('amount')
            phone_number = request.data.get('phone_number')
            business_id = request.data.get('business_id')
            transaction_type = request.data.get('transaction_type', 'general')
            description = request.data.get('description', '')

            # Validate required fields
            if not amount or not phone_number:
                return Response(
                    {'error': 'Amount and phone_number are required'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Convert amount to Decimal
            try:
                amount = Decimal(str(amount))
            except (ValueError, TypeError):
                return Response(
                    {'error': 'Invalid amount format'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate amount
            if amount <= 0:
                return Response(
                    {'error': 'Amount must be greater than 0'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Initiate payment using service
            result = MobileMoneyService.initiate_payment(
                user=request.user,
                payment_method_code='mtn_momo',
                amount=amount,
                phone_number=phone_number,
                business_id=business_id,
                transaction_type=transaction_type
            )

            return Response(result, status=status.HTTP_201_CREATED)

        except BusiMapException as e:
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.exception(f"Error initiating MTN MoMo payment: {e}")
            return Response(
                {'error': 'Failed to initiate payment'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@extend_schema_view(
    post=extend_schema(
        summary="MTN MoMo Payment Callback",
        description="Handle callback from MTN Mobile Money",
        tags=["Mobile Money"]
    )
)
class MTNMoMoCallbackView(APIView):
    """Handle MTN Mobile Money payment callbacks"""
    
    permission_classes = [permissions.AllowAny]  # Callbacks don't have user authentication

    def post(self, request):
        try:
            # Log the callback data for debugging
            logger.info(f"MTN MoMo callback received: {request.data}")

            # Handle the callback using service
            result = MobileMoneyService.handle_payment_callback(
                provider_code='MTN_MOMO',
                callback_data=request.data
            )

            if result.get('success'):
                return Response({'status': 'success'}, status=status.HTTP_200_OK)
            else:
                return Response(
                    {'error': result.get('error', 'Callback processing failed')}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

        except Exception as e:
            logger.exception(f"Error processing MTN MoMo callback: {e}")
            return Response(
                {'error': 'Failed to process callback'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@extend_schema_view(
    post=extend_schema(
        summary="Initiate Airtel Money Payment",
        description="Initiate a payment using Airtel Money",
        tags=["Mobile Money"],
        request={
            'application/json': {
                'type': 'object',
                'properties': {
                    'amount': {'type': 'number', 'description': 'Payment amount'},
                    'phone_number': {'type': 'string', 'description': 'Phone number for payment'},
                    'business_id': {'type': 'string', 'description': 'Optional business ID', 'nullable': True},
                    'transaction_type': {'type': 'string', 'description': 'Type of transaction', 'default': 'general'},
                    'description': {'type': 'string', 'description': 'Payment description', 'nullable': True}
                },
                'required': ['amount', 'phone_number']
            }
        }
    )
)
class AirtelMoneyInitiateView(APIView):
    """Initiate Airtel Money payment"""
    
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            # Get request data
            amount = request.data.get('amount')
            phone_number = request.data.get('phone_number')
            business_id = request.data.get('business_id')
            transaction_type = request.data.get('transaction_type', 'general')
            description = request.data.get('description', '')

            # Validate required fields
            if not amount or not phone_number:
                return Response(
                    {'error': 'Amount and phone_number are required'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Convert amount to Decimal
            try:
                amount = Decimal(str(amount))
            except (ValueError, TypeError):
                return Response(
                    {'error': 'Invalid amount format'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate amount
            if amount <= 0:
                return Response(
                    {'error': 'Amount must be greater than 0'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Initiate payment using service
            result = MobileMoneyService.initiate_payment(
                user=request.user,
                payment_method_code='airtel_money',
                amount=amount,
                phone_number=phone_number,
                business_id=business_id,
                transaction_type=transaction_type
            )

            return Response(result, status=status.HTTP_201_CREATED)

        except BusiMapException as e:
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.exception(f"Error initiating Airtel Money payment: {e}")
            return Response(
                {'error': 'Failed to initiate payment'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@extend_schema_view(
    post=extend_schema(
        summary="Airtel Money Payment Callback",
        description="Handle callback from Airtel Money",
        tags=["Mobile Money"]
    )
)
class AirtelMoneyCallbackView(APIView):
    """Handle Airtel Money payment callbacks"""
    
    permission_classes = [permissions.AllowAny]  # Callbacks don't have user authentication

    def post(self, request):
        try:
            # Log the callback data for debugging
            logger.info(f"Airtel Money callback received: {request.data}")

            # Handle the callback using service
            result = MobileMoneyService.handle_payment_callback(
                provider_code='AIRTEL_MONEY',
                callback_data=request.data
            )

            if result.get('success'):
                return Response({'status': 'success'}, status=status.HTTP_200_OK)
            else:
                return Response(
                    {'error': result.get('error', 'Callback processing failed')}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

        except Exception as e:
            logger.exception(f"Error processing Airtel Money callback: {e}")
            return Response(
                {'error': 'Failed to process callback'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# Additional utility views

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_payment_summary(request):
    """Get payment summary for the authenticated user"""
    try:
        user = request.user
        
        # Get transaction counts by status
        transactions = PaymentTransaction.objects.filter(user=user)
        
        summary = {
            'total_transactions': transactions.count(),
            'successful_transactions': transactions.filter(status='completed').count(),
            'pending_transactions': transactions.filter(status='pending').count(),
            'failed_transactions': transactions.filter(status='failed').count(),
            'total_amount_spent': float(
                transactions.filter(status='completed').aggregate(
                    total=models.Sum('total_amount')
                )['total'] or 0
            )
        }
        
        return Response(summary)
        
    except Exception as e:
        logger.exception(f"Error getting payment summary: {e}")
        return Response(
            {'error': 'Failed to get payment summary'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def cancel_transaction(request, transaction_id):
    """Cancel a pending transaction"""
    try:
        transaction = get_object_or_404(
            PaymentTransaction,
            transaction_id=transaction_id,
            user=request.user,
            status='pending'
        )
        
        # Update transaction status
        transaction.status = 'cancelled'
        transaction.save()
        
        return Response({
            'message': 'Transaction cancelled successfully',
            'transaction_id': str(transaction.transaction_id)
        })
        
    except PaymentTransaction.DoesNotExist:
        return Response(
            {'error': 'Transaction not found or cannot be cancelled'}, 
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.exception(f"Error cancelling transaction: {e}")
        return Response(
            {'error': 'Failed to cancel transaction'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )