# apps/ai_engine/websockets/consumers.py
import json
import logging
import asyncio
from typing import Dict, Optional
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from asgiref.sync import sync_to_async
from django.utils import timezone
from django.db import models

from ..services.conversation_service import ConversationService
from ..models import ConversationSession

logger = logging.getLogger(__name__)
User = get_user_model()


class AIConversationConsumer(AsyncWebsocketConsumer):
    """Enhanced WebSocket consumer for real-time AI conversations"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_id = None
        self.user = None
        self.conversation_service = ConversationService()
        self.conversation_id = None
        self.processing_message = False

    async def connect(self):
        """Handle WebSocket connection with authentication"""

        try:
            # Get user ID from URL
            self.user_id = self.scope["url_route"]["kwargs"]["user_id"]

            # Authenticate user
            self.user = await self.get_user(self.user_id)
            if not self.user or not self.user.is_active:
                await self.close(code=4001)  # Unauthorized
                return

            # Join user's personal room
            self.room_name = f"ai_chat_{self.user_id}"
            self.room_group_name = f"ai_chat_{self.user_id}"

            await self.channel_layer.group_add(self.room_group_name, self.channel_name)

            await self.accept()

            # Send welcome message
            await self.send_message(
                {
                    "type": "system_message",
                    "message": self.get_welcome_message(),
                    "timestamp": self.get_current_timestamp(),
                    "connection_id": self.channel_name,
                }
            )

            logger.info(f"User {self.user_id} connected to AI chat")

        except Exception as e:
            logger.error(f"Error connecting user {self.user_id}: {e}")
            await self.close(code=4000)  # General error

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection"""

        try:
            if hasattr(self, "room_group_name"):
                await self.channel_layer.group_discard(
                    self.room_group_name, self.channel_name
                )

            # Update conversation status if active
            if self.conversation_id:
                await self.end_conversation_session()

            logger.info(
                f"User {self.user_id} disconnected from AI chat (code: {close_code})"
            )

        except Exception as e:
            logger.error(f"Error disconnecting user {self.user_id}: {e}")

    async def receive(self, text_data):
        """Handle incoming WebSocket messages"""

        if self.processing_message:
            await self.send_error(
                "Please wait for the previous message to be processed"
            )
            return

        try:
            data = json.loads(text_data)
            message_type = data.get("type", "user_message")

            # Route message based on type
            if message_type == "user_message":
                await self.handle_user_message(data)
            elif message_type == "voice_message":
                await self.handle_voice_message(data)
            elif message_type == "typing_indicator":
                await self.handle_typing_indicator(data)
            elif message_type == "location_update":
                await self.handle_location_update(data)
            elif message_type == "feedback":
                await self.handle_user_feedback(data)
            elif message_type == "conversation_end":
                await self.handle_conversation_end(data)
            else:
                await self.send_error(f"Unknown message type: {message_type}")

        except json.JSONDecodeError:
            await self.send_error("Invalid JSON format")
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            await self.send_error("Failed to process message")
        finally:
            self.processing_message = False

    async def handle_user_message(self, data: Dict):
        """Process user text message through AI with enhanced features"""

        self.processing_message = True

        message = data.get("message", "").strip()
        if not message:
            await self.send_error("Empty message")
            return

        if len(message) > 1000:  # Limit message length
            await self.send_error("Message too long (max 1000 characters)")
            return

        # Send typing indicator
        await self.send_typing_indicator(True, estimated_time=3)

        try:
            # Process message through AI service
            result = await self.process_ai_message(
                message=message,
                conversation_id=data.get("conversation_id"),
                user_location=data.get("user_location"),
                language=data.get("language", self.user.preferred_language),
                message_metadata=data.get("metadata", {}),
            )

            # Stop typing indicator
            await self.send_typing_indicator(False)

            # Send AI response
            await self.send_message(
                {
                    "type": "ai_response",
                    "message": result["response"],
                    "conversation_id": result["conversation_id"],
                    "suggested_businesses": result.get("suggested_businesses", []),
                    "follow_up_suggestions": result.get("follow_up_suggestions", []),
                    "language": result.get("language", "en"),
                    "intent": result.get("intent", "general"),
                    "confidence": result.get("confidence", 0.5),
                    "response_time_ms": result.get("response_time_ms", 0),
                    "timestamp": self.get_current_timestamp(),
                    "message_id": self.generate_message_id(),
                    "response_to": data.get("message_id"),
                    "context_used": result.get("context_used", {}),
                }
            )

            # Update conversation ID for future messages
            self.conversation_id = result["conversation_id"]

        except Exception as e:
            logger.error(f"Error processing AI message: {e}")
            await self.send_typing_indicator(False)

            # Send contextual error message
            error_message = self.get_error_message_by_language(
                self.user.preferred_language
            )
            await self.send_error(error_message)

    async def handle_voice_message(self, data: Dict):
        """Process voice message with speech-to-text conversion"""

        self.processing_message = True

        audio_data = data.get("audio_data")
        if not audio_data:
            await self.send_error("No audio data provided")
            return

        # Send processing status updates
        await self.send_message(
            {
                "type": "voice_processing",
                "status": "received",
                "progress": 0.1,
                "message": "Audio received, processing...",
            }
        )

        try:
            # Update processing status
            await self.send_message(
                {
                    "type": "voice_processing",
                    "status": "transcribing",
                    "progress": 0.4,
                    "message": "Converting speech to text...",
                }
            )

            # Process speech to text (mock implementation)
            transcribed_text = await self.process_speech_to_text(
                audio_data,
                data.get("audio_format", "webm"),
                data.get("language_hint", self.user.preferred_language),
            )

            if not transcribed_text:
                await self.send_error("Could not understand audio. Please try again.")
                return

            # Update processing status
            await self.send_message(
                {
                    "type": "voice_processing",
                    "status": "processing_ai",
                    "progress": 0.7,
                    "transcribed_text": transcribed_text,
                    "message": "Understanding your request...",
                }
            )

            # Process through AI like regular message
            result = await self.process_ai_message(
                message=transcribed_text,
                conversation_id=data.get("conversation_id"),
                user_location=data.get("user_location"),
                language=data.get("language", self.user.preferred_language),
                is_voice_input=True,
            )

            # Generate speech response if requested
            audio_response = None
            if data.get("generate_speech", False):
                await self.send_message(
                    {
                        "type": "voice_processing",
                        "status": "generating_speech",
                        "progress": 0.9,
                        "message": "Generating voice response...",
                    }
                )

                audio_response = await self.process_text_to_speech(
                    result["response"],
                    language=result.get("language", "en"),
                    voice_gender=data.get("voice_gender", "female"),
                )

            # Send complete voice response
            await self.send_message(
                {
                    "type": "ai_voice_response",
                    "message": result["response"],
                    "transcribed_text": transcribed_text,
                    "audio_response": audio_response,
                    "conversation_id": result["conversation_id"],
                    "suggested_businesses": result.get("suggested_businesses", []),
                    "follow_up_suggestions": result.get("follow_up_suggestions", []),
                    "language": result.get("language", "en"),
                    "intent": result.get("intent", "general"),
                    "confidence": result.get("confidence", 0.5),
                    "timestamp": self.get_current_timestamp(),
                    "voice_processing_complete": True,
                }
            )

        except Exception as e:
            logger.error(f"Error processing voice message: {e}")
            await self.send_error(
                "Failed to process voice message. Please try typing instead."
            )

    async def handle_typing_indicator(self, data: Dict):
        """Handle user typing indicators"""

        is_typing = data.get("is_typing", False)

        # Broadcast to other connections (for multi-device support)
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                "type": "user_typing_status",
                "is_typing": is_typing,
                "sender_channel": self.channel_name,
                "timestamp": self.get_current_timestamp(),
            },
        )

    async def handle_location_update(self, data: Dict):
        """Handle user location updates"""

        location = data.get("location")
        if not location or "latitude" not in location or "longitude" not in location:
            await self.send_error("Invalid location data")
            return

        try:
            # Validate coordinates
            lat = float(location["latitude"])
            lon = float(location["longitude"])

            if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
                await self.send_error("Invalid coordinate values")
                return

            # Update user location
            await self.update_user_location(location)

            await self.send_message(
                {
                    "type": "location_updated",
                    "message": "Location updated successfully",
                    "location": location,
                    "timestamp": self.get_current_timestamp(),
                }
            )

        except (ValueError, TypeError):
            await self.send_error("Invalid location format")

    async def handle_user_feedback(self, data: Dict):
        """Handle user feedback on AI responses"""

        try:
            feedback_type = data.get(
                "feedback_type"
            )  # 'helpful', 'not_helpful', 'rating'
            message_id = data.get("message_id")
            rating = data.get("rating")
            comment = data.get("comment", "")

            # Store feedback (would update message ratings)
            await self.store_user_feedback(message_id, feedback_type, rating, comment)

            # Thank user for feedback
            thank_you_message = self.get_thank_you_message(self.user.preferred_language)
            await self.send_message(
                {
                    "type": "feedback_received",
                    "message": thank_you_message,
                    "timestamp": self.get_current_timestamp(),
                }
            )

        except Exception as e:
            logger.error(f"Error handling user feedback: {e}")

    async def handle_conversation_end(self, data: Dict):
        """Handle explicit conversation end"""

        try:
            reason = data.get("reason", "user_ended")
            satisfaction = data.get("satisfaction_rating")

            if self.conversation_id:
                await self.end_conversation_session(reason, satisfaction)

            # Send goodbye message
            goodbye_message = self.get_goodbye_message(self.user.preferred_language)
            await self.send_message(
                {
                    "type": "conversation_ended",
                    "message": goodbye_message,
                    "reason": reason,
                    "timestamp": self.get_current_timestamp(),
                }
            )

        except Exception as e:
            logger.error(f"Error ending conversation: {e}")

    @database_sync_to_async
    def process_ai_message(
        self,
        message: str,
        conversation_id: Optional[str] = None,
        user_location: Optional[Dict] = None,
        language: str = "en",
        message_metadata: Dict = None,
        is_voice_input: bool = False,
    ) -> Dict:
        """Process message through AI service"""

        start_time = timezone.now()

        result = self.conversation_service.process_message(
            user=self.user,
            message=message,
            conversation_id=conversation_id,
            user_location=user_location,
        )

        # Add response time
        response_time = (timezone.now() - start_time).total_seconds() * 1000
        result["response_time_ms"] = int(response_time)
        result["is_voice_input"] = is_voice_input
        result["message_metadata"] = message_metadata or {}

        return result

    async def process_speech_to_text(
        self, audio_data: str, audio_format: str = "webm", language_hint: str = "en"
    ) -> Optional[str]:
        """Process speech to text (placeholder for actual implementation)"""

        # TODO: Integrate with actual speech-to-text service
        # This would use services like Google Speech-to-Text, Azure Speech Services, etc.

        await asyncio.sleep(1)  # Simulate processing time

        # Mock transcription based on language hint
        mock_transcriptions = {
            "rw": "Ndashaka kurya restaurant nziza hafi yanjye",
            "en": "I want to find a good restaurant near me",
            "fr": "Je veux trouver un bon restaurant près de moi",
        }

        return mock_transcriptions.get(language_hint, mock_transcriptions["en"])

    async def process_text_to_speech(
        self, text: str, language: str = "en", voice_gender: str = "female"
    ) -> Optional[Dict]:
        """Process text to speech (placeholder for actual implementation)"""

        # TODO: Integrate with actual text-to-speech service
        # This would use services like Google Text-to-Speech, Azure Cognitive Services, etc.

        await asyncio.sleep(1)  # Simulate processing time

        # Mock audio response
        return {
            "audio_url": None,  # Would contain actual audio URL
            "audio_data": None,  # Would contain base64 audio data
            "duration_seconds": len(text.split()) * 0.6,  # Rough estimate
            "voice_used": f"{language}-{voice_gender}-standard",
            "format": "mp3",
        }

    async def send_message(self, message: Dict):
        """Send message to WebSocket with error handling"""

        try:
            await self.send(text_data=json.dumps(message))
        except Exception as e:
            logger.error(f"Error sending WebSocket message: {e}")

    async def send_error(self, error_message: str, error_code: str = "general_error"):
        """Send error message to WebSocket"""

        await self.send_message(
            {
                "type": "error",
                "error": error_message,
                "error_code": error_code,
                "timestamp": self.get_current_timestamp(),
            }
        )

    async def send_typing_indicator(
        self, is_typing: bool, estimated_time: Optional[int] = None
    ):
        """Send typing indicator to user"""

        await self.send_message(
            {
                "type": "ai_typing_status",
                "is_typing": is_typing,
                "estimated_response_time": estimated_time,
                "timestamp": self.get_current_timestamp(),
            }
        )

    @database_sync_to_async
    def get_user(self, user_id: str):
        """Get user by ID"""

        try:
            return User.objects.get(id=user_id, is_active=True)
        except User.DoesNotExist:
            return None

    @database_sync_to_async
    def update_user_location(self, location: Dict):
        """Update user's current location"""

        try:
            self.user.current_latitude = location["latitude"]
            self.user.current_longitude = location["longitude"]
            self.user.save(update_fields=["current_latitude", "current_longitude"])
        except Exception as e:
            logger.error(f"Error updating user location: {e}")

    @database_sync_to_async
    def store_user_feedback(
        self, message_id: str, feedback_type: str, rating: Optional[int], comment: str
    ):
        """Store user feedback for AI improvement"""

        # TODO: Implement feedback storage
        logger.info(
            f"User feedback: {feedback_type}, rating: {rating}, comment: {comment}"
        )

    @database_sync_to_async
    def end_conversation_session(
        self, reason: str = "completed", satisfaction: Optional[int] = None
    ):
        """End conversation session"""

        try:
            if self.conversation_id:
                conversation = ConversationSession.objects.get(
                    session_id=self.conversation_id
                )
                conversation.conversation_state = "completed"
                conversation.ended_at = timezone.now()
                if satisfaction:
                    conversation.satisfaction_score = satisfaction
                conversation.save()
        except Exception as e:
            logger.error(f"Error ending conversation session: {e}")

    def get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        return timezone.now().isoformat()

    def generate_message_id(self) -> str:
        """Generate unique message ID"""
        import uuid

        return str(uuid.uuid4())

    def get_welcome_message(self) -> str:
        """Get welcome message in user's preferred language"""

        messages = {
            "rw": "Muraho neza! Ni gute nakugufasha uyu munsi?",
            "en": "Hello! How can I help you today?",
            "fr": "Bonjour! Comment puis-je vous aider aujourd'hui?",
        }
        return messages.get(self.user.preferred_language, messages["en"])

    def get_goodbye_message(self, language: str) -> str:
        """Get goodbye message in specified language"""

        messages = {
            "rw": "Murakoze kuba mwatubwiye! Muzagaruke mugihe cyose mushaka ubufasha.",
            "en": "Thank you for chatting with us! Come back anytime you need help.",
            "fr": "Merci d'avoir discuté avec nous! Revenez quand vous avez besoin d'aide.",
        }
        return messages.get(language, messages["en"])

    def get_thank_you_message(self, language: str) -> str:
        """Get thank you message for feedback"""

        messages = {
            "rw": "Murakoze kubwira ibitekerezo byanyu! Bidufasha kuzamura serivisi zacu.",
            "en": "Thank you for your feedback! It helps us improve our service.",
            "fr": "Merci pour vos commentaires! Cela nous aide à améliorer notre service.",
        }
        return messages.get(language, messages["en"])

    def get_error_message_by_language(self, language: str) -> str:
        """Get error message in user's language"""

        messages = {
            "rw": "Ihangane, habaye ikibazo gito. Ongera ugerageze!",
            "en": "Sorry, something went wrong. Please try again!",
            "fr": "Désolé, quelque chose s'est mal passé. Veuillez réessayer!",
        }
        return messages.get(language, messages["en"])

    # Channel layer message handlers
    async def user_typing_status(self, event):
        """Handle typing status from channel layer"""

        # Don't send back to the sender
        if event.get("sender_channel") == self.channel_name:
            return

        await self.send_message(
            {
                "type": "user_typing",
                "is_typing": event["is_typing"],
                "timestamp": event["timestamp"],
            }
        )

    async def ai_response_broadcast(self, event):
        """Handle AI response broadcast from channel layer"""

        await self.send_message(event["message"])
