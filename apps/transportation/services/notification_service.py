# apps/transportation/services/notification_service.py
from typing import Dict, Any
from django.utils import timezone
from apps.transportation.models import Ride, Driver
from apps.authentication.models import User
from .ride_matching_service import RideMatchingService

class NotificationService:
    """Service for handling ride-related notifications"""
    
    def __init__(self):
        self.ride_matching_service = RideMatchingService()
    
    def send_ride_request_notification(self, ride: Ride) -> Dict[str, Any]:
        """Send notification to nearby drivers about a new ride request"""
        
        try:
            # Find matching drivers
            matching_drivers = self.ride_matching_service.find_matching_drivers(ride)
            
            if not matching_drivers:
                return {
                    'success': False,
                    'error': 'No available drivers found'
                }
            
            # Send notifications to top 5 drivers
            notifications_sent = 0
            for driver_data in matching_drivers[:5]:
                driver = Driver.objects.get(driver_id=driver_data['driver_id'])
                
                # Create notification
                notification = {
                    'type': 'ride_request',
                    'ride_id': str(ride.ride_id),
                    'pickup_address': ride.pickup_address,
                    'dropoff_address': ride.dropoff_address,
                    'vehicle_type': ride.vehicle_type,
                    'estimated_fare': driver_data['estimated_fare'],
                    'distance_km': driver_data['distance_km'],
                    'eta_minutes': driver_data['eta_minutes'],
                    'passenger_count': ride.passenger_count,
                    'requested_at': ride.requested_at.isoformat()
                }
                
                # Send notification (placeholder for actual notification service)
                self._send_notification(driver.user, notification)
                notifications_sent += 1
            
            return {
                'success': True,
                'data': {
                    'notifications_sent': notifications_sent,
                    'matching_drivers': len(matching_drivers)
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def send_ride_accepted_notification(self, ride: Ride) -> Dict[str, Any]:
        """Send notification to passenger that ride was accepted"""
        
        try:
            notification = {
                'type': 'ride_accepted',
                'ride_id': str(ride.ride_id),
                'driver_name': ride.driver.get_full_name(),
                'driver_phone': ride.driver.phone_number,
                'vehicle_type': ride.vehicle_type,
                'vehicle_model': ride.driver.driver_profile.vehicle_model,
                'vehicle_plate': ride.driver.driver_profile.vehicle_plate,
                'estimated_fare': float(ride.estimated_fare or 0),
                'eta_minutes': ride.eta_minutes,
                'accepted_at': ride.accepted_at.isoformat()
            }
            
            # Send notification to passenger
            self._send_notification(ride.passenger, notification)
            
            return {
                'success': True,
                'data': notification
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def send_ride_started_notification(self, ride: Ride) -> Dict[str, Any]:
        """Send notification that ride has started"""
        
        try:
            notification = {
                'type': 'ride_started',
                'ride_id': str(ride.ride_id),
                'driver_name': ride.driver.get_full_name(),
                'vehicle_type': ride.vehicle_type,
                'started_at': ride.started_at.isoformat()
            }
            
            # Send notification to passenger
            self._send_notification(ride.passenger, notification)
            
            return {
                'success': True,
                'data': notification
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def send_ride_completed_notification(self, ride: Ride) -> Dict[str, Any]:
        """Send notification that ride has been completed"""
        
        try:
            notification = {
                'type': 'ride_completed',
                'ride_id': str(ride.ride_id),
                'driver_name': ride.driver.get_full_name(),
                'vehicle_type': ride.vehicle_type,
                'final_fare': float(ride.final_fare or 0),
                'completed_at': ride.completed_at.isoformat()
            }
            
            # Send notification to passenger
            self._send_notification(ride.passenger, notification)
            
            return {
                'success': True,
                'data': notification
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def send_ride_cancelled_notification(self, ride: Ride, reason: str = None) -> Dict[str, Any]:
        """Send notification that ride was cancelled"""
        
        try:
            notification = {
                'type': 'ride_cancelled',
                'ride_id': str(ride.ride_id),
                'reason': reason or 'No reason provided',
                'cancelled_at': timezone.now().isoformat()
            }
            
            # Send notification to passenger
            self._send_notification(ride.passenger, notification)
            
            return {
                'success': True,
                'data': notification
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _send_notification(self, user: User, notification: Dict[str, Any]) -> None:
        """Send notification to user (placeholder for actual notification service)"""
        
        # In a real implementation, this would:
        # 1. Send push notification via FCM/APNS
        # 2. Send SMS if needed
        # 3. Send email if needed
        # 4. Store notification in database
        
        print(f"Sending notification to {user.email}: {notification}")
        
        # Store notification in database (placeholder)
        # Notification.objects.create(
        #     user=user,
        #     type=notification['type'],
        #     data=notification,
        #     sent_at=timezone.now()
        # )




