# apps/payments/services/mobile_money_service.py
import logging
import requests
import uuid
from typing import Dict, Any
from decimal import Decimal
from django.utils import timezone
from django.conf import settings
from apps.authentication.models import User
from apps.payments.models import PaymentMethod, PaymentTransaction, MobileMoneyProvider
from apps.common.exceptions import BusiMapException

logger = logging.getLogger(__name__)

class MobileMoneyService:
    """
    Service for handling mobile money payments (MTN MoMo, Airtel Money, etc.)
    """

    @staticmethod
    def initiate_payment(
        user: User,
        payment_method_code: str,
        amount: Decimal,
        phone_number: str,
        business_id: str = None,
        transaction_type: str = 'general',
        related_object_id: str = None
    ) -> Dict[str, Any]:
        """
        Initiates a mobile money payment transaction.
        """
        try:
            # Get payment method
            payment_method = PaymentMethod.objects.get(
                code=payment_method_code, 
                is_active=True,
                requires_external_integration=True,
                mobile_money_provider__isnull=False
            )

            # Get business if provided
            business = None
            if business_id:
                try:
                    from apps.businesses.models import Business
                    business = Business.objects.get(business_id=business_id)
                except Business.DoesNotExist:
                    raise BusiMapException(f"Business with ID {business_id} not found.")

            # Create payment transaction record
            transaction = PaymentTransaction.objects.create(
                user=user,
                business=business,
                payment_method=payment_method,
                amount=amount,
                currency='RWF',
                status='pending',
                transaction_type=transaction_type,
                related_object_id=related_object_id,
                payer_phone_number=phone_number,
                payer_email=user.email
            )

            # Call external payment API based on provider
            provider = payment_method.mobile_money_provider
            
            if provider.code == 'MTN_MOMO':
                result = MobileMoneyService._initiate_mtn_momo_payment(
                    transaction, phone_number, amount
                )
            elif provider.code == 'AIRTEL_MONEY':
                result = MobileMoneyService._initiate_airtel_money_payment(
                    transaction, phone_number, amount
                )
            else:
                raise BusiMapException(f"Unsupported mobile money provider: {provider.code}")

            # Update transaction with provider response
            transaction.provider_transaction_id = result.get('provider_transaction_id')
            transaction.provider_response = result.get('provider_response', {})
            
            if result.get('success'):
                transaction.status = 'pending'  # Keep as pending until callback confirmation
            else:
                transaction.status = 'failed'
            
            transaction.save()

            return {
                "transaction_id": str(transaction.transaction_id),
                "status": transaction.status,
                "amount": float(amount),
                "currency": transaction.currency,
                "payment_method": payment_method.name,
                "provider_transaction_id": transaction.provider_transaction_id,
                "message": result.get('message', 'Payment initiated successfully.'),
                "requires_user_action": result.get('requires_user_action', True)
            }

        except PaymentMethod.DoesNotExist:
            raise BusiMapException(f"Payment method '{payment_method_code}' not found or not active.")
        except Exception as e:
            logger.exception(f"Error initiating mobile money payment: {e}")
            raise BusiMapException(f"Failed to initiate payment: {e}")

    @staticmethod
    def _initiate_mtn_momo_payment(
        transaction: PaymentTransaction, 
        phone_number: str, 
        amount: Decimal
    ) -> Dict[str, Any]:
        """
        Initiates MTN Mobile Money payment.
        This is a placeholder implementation - in production, you'd integrate with MTN MoMo API.
        """
        try:
            # In a real implementation, this would call MTN MoMo API
            # For now, we'll simulate the API call
            
            momo_config = getattr(settings, 'MOBILE_MONEY_SETTINGS', {}).get('MTN_MOMO', {})
            api_user = momo_config.get('API_USER')
            api_key = momo_config.get('API_KEY')
            
            if not api_user or not api_key:
                logger.warning("MTN MoMo API credentials not configured. Using mock response.")
                # Mock successful response for development
                return {
                    "success": True,
                    "provider_transaction_id": f"mtn_mock_{uuid.uuid4().hex[:10]}",
                    "message": "Payment request sent to user's phone. Please complete on your device.",
                    "requires_user_action": True,
                    "provider_response": {
                        "status": "PENDING",
                        "reference": f"mtn_ref_{uuid.uuid4().hex[:8]}",
                        "mock": True
                    }
                }

            # Real MTN MoMo API integration would go here
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json',
                'X-Reference-Id': str(transaction.transaction_id),
                'X-Target-Environment': momo_config.get('ENVIRONMENT', 'sandbox')
            }

            payload = {
                'amount': str(amount),
                'currency': 'RWF',
                'externalId': str(transaction.transaction_id),
                'payer': {
                    'partyIdType': 'MSISDN',
                    'partyId': phone_number.replace('+', '')
                },
                'payerMessage': f'Payment for BusiMap transaction {transaction.transaction_id}',
                'payeeNote': f'BusiMap payment from {transaction.user.get_full_name()}'
            }

            # Make API call (this is a placeholder URL)
            api_url = momo_config.get('API_URL', 'https://sandbox.momodeveloper.mtn.com/collection/v1_0/requesttopay')
            
            response = requests.post(api_url, json=payload, headers=headers, timeout=30)
            
            if response.status_code == 202:  # MTN MoMo typically returns 202 for accepted requests
                return {
                    "success": True,
                    "provider_transaction_id": response.headers.get('X-Reference-Id', str(transaction.transaction_id)),
                    "message": "Payment request sent to user's phone. Please complete on your device.",
                    "requires_user_action": True,
                    "provider_response": {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "body": response.text
                    }
                }
            else:
                return {
                    "success": False,
                    "message": f"MTN MoMo API error: {response.status_code}",
                    "provider_response": {
                        "status_code": response.status_code,
                        "error": response.text
                    }
                }

        except requests.RequestException as e:
            logger.error(f"MTN MoMo API request failed: {e}")
            return {
                "success": False,
                "message": "Failed to connect to MTN MoMo service.",
                "provider_response": {"error": str(e)}
            }
        except Exception as e:
            logger.exception(f"Unexpected error in MTN MoMo payment: {e}")
            return {
                "success": False,
                "message": "An unexpected error occurred.",
                "provider_response": {"error": str(e)}
            }

    @staticmethod
    def _initiate_airtel_money_payment(
        transaction: PaymentTransaction, 
        phone_number: str, 
        amount: Decimal
    ) -> Dict[str, Any]:
        """
        Initiates Airtel Money payment.
        This is a placeholder implementation - in production, you'd integrate with Airtel Money API.
        """
        try:
            # Mock implementation for Airtel Money
            airtel_config = getattr(settings, 'MOBILE_MONEY_SETTINGS', {}).get('AIRTEL_MONEY', {})
            
            if not airtel_config.get('CLIENT_ID'):
                logger.warning("Airtel Money API credentials not configured. Using mock response.")
                # Mock successful response for development
                return {
                    "success": True,
                    "provider_transaction_id": f"airtel_mock_{uuid.uuid4().hex[:10]}",
                    "message": "Payment request sent to user's phone. Please complete on your device.",
                    "requires_user_action": True,
                    "provider_response": {
                        "status": "PENDING",
                        "reference": f"airtel_ref_{uuid.uuid4().hex[:8]}",
                        "mock": True
                    }
                }

            # Real Airtel Money API integration would go here
            # This is just a placeholder structure
            return {
                "success": True,
                "provider_transaction_id": f"airtel_placeholder_{uuid.uuid4().hex[:10]}",
                "message": "Airtel Money integration not fully implemented yet.",
                "requires_user_action": True,
                "provider_response": {
                    "status": "PLACEHOLDER",
                    "note": "This is a placeholder implementation."
                }
            }

        except Exception as e:
            logger.exception(f"Unexpected error in Airtel Money payment: {e}")
            return {
                "success": False,
                "message": "An unexpected error occurred.",
                "provider_response": {"error": str(e)}
            }

    @staticmethod
    def handle_payment_callback(
        provider_code: str,
        callback_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handles payment callback from mobile money providers.
        """
        try:
            # Extract transaction reference from callback
            transaction_id = callback_data.get('reference') or callback_data.get('transaction_id')
            
            if not transaction_id:
                raise BusiMapException("Transaction ID not found in callback data.")

            # Find transaction
            try:
                if provider_code.upper() == 'MTN_MOMO':
                    transaction = PaymentTransaction.objects.get(
                        transaction_id=transaction_id,
                        payment_method__mobile_money_provider__code='MTN_MOMO'
                    )
                elif provider_code.upper() == 'AIRTEL_MONEY':
                    transaction = PaymentTransaction.objects.get(
                        transaction_id=transaction_id,
                        payment_method__mobile_money_provider__code='AIRTEL_MONEY'
                    )
                else:
                    raise BusiMapException(f"Unsupported provider: {provider_code}")

            except PaymentTransaction.DoesNotExist:
                raise BusiMapException(f"Transaction {transaction_id} not found.")

            # Update transaction based on callback status
            callback_status = callback_data.get('status', '').upper()
            
            if callback_status in ['SUCCESSFUL', 'SUCCESS', 'COMPLETED']:
                transaction.status = 'successful'
                transaction.completed_at = timezone.now()
            elif callback_status in ['FAILED', 'FAILURE', 'REJECTED']:
                transaction.status = 'failed'
            elif callback_status in ['CANCELLED', 'CANCELED']:
                transaction.status = 'cancelled'
            else:
                # Keep as pending for unknown statuses
                pass

            # Update provider response with callback data
            transaction.provider_response.update({
                'callback_received_at': timezone.now().isoformat(),
                'callback_data': callback_data
            })
            
            transaction.save()

            logger.info(f"Payment callback processed for transaction {transaction_id}: {transaction.status}")

            return {
                "success": True,
                "transaction_id": str(transaction.transaction_id),
                "status": transaction.status,
                "message": "Callback processed successfully."
            }

        except Exception as e:
            logger.exception(f"Error processing payment callback: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    @staticmethod
    def get_transaction_status(transaction_id: str) -> Dict[str, Any]:
        """
        Retrieves the current status of a payment transaction.
        """
        try:
            transaction = PaymentTransaction.objects.get(transaction_id=transaction_id)
            
            return {
                "transaction_id": str(transaction.transaction_id),
                "status": transaction.status,
                "amount": float(transaction.amount),
                "currency": transaction.currency,
                "payment_method": transaction.payment_method.name,
                "provider_transaction_id": transaction.provider_transaction_id,
                "created_at": transaction.created_at.isoformat(),
                "completed_at": transaction.completed_at.isoformat() if transaction.completed_at else None,
                "user": transaction.user.get_full_name() if transaction.user else None,
                "business": transaction.business.business_name if transaction.business else None
            }

        except PaymentTransaction.DoesNotExist:
            raise BusiMapException(f"Transaction {transaction_id} not found.")
        except Exception as e:
            logger.exception(f"Error retrieving transaction status: {e}")
            raise BusiMapException(f"Failed to retrieve transaction status: {e}")