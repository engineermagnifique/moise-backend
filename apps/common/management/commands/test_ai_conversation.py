# management/commands/test_ai_conversation.py
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from apps.ai_engine.services.conversation_service import ConversationService
import json

User = get_user_model()


class Command(BaseCommand):
    help = "Test AI conversation system with sample messages"

    def add_arguments(self, parser):
        parser.add_argument(
            "--user-email",
            type=str,
            default="customer@test.rw",
            help="Email of user to test with",
        )

    def handle(self, *args, **options):
        self.stdout.write("Testing AI conversation system...")

        try:
            # Get test user
            user = User.objects.get(email=options["user_email"])

            # Initialize conversation service
            conversation_service = ConversationService()

            # Test messages in different scenarios
            test_messages = [
                {
                    "message": "Ndashaka kurya ariko sinzi aho narira kuberako ndimushya hano ndi",
                    "language": "rw",
                    "location": {"latitude": -1.9441, "longitude": 30.0619},
                    "description": "Food search in Kinyarwanda",
                },
                {
                    "message": "My car broke down and I don't know where I am. I need help!",
                    "language": "en",
                    "location": {"latitude": -1.9506, "longitude": 30.0588},
                    "description": "Emergency assistance in English",
                },
                {
                    "message": "Je cherche un bon restaurant pour ma famille",
                    "language": "fr",
                    "location": {"latitude": -1.9441, "longitude": 30.0619},
                    "description": "Family restaurant search in French",
                },
                {
                    "message": "Ndashaka amavuriro akwegereye",
                    "language": "rw",
                    "location": {"latitude": -1.9500, "longitude": 30.0600},
                    "description": "Medical search in Kinyarwanda",
                },
                {
                    "message": "Where can I find ATM near me?",
                    "language": "en",
                    "location": {"latitude": -1.9525, "longitude": 30.0625},
                    "description": "ATM search in English",
                },
            ]

            for i, test in enumerate(test_messages, 1):
                self.stdout.write(f"\n--- Test {i}: {test['description']} ---")
                self.stdout.write(f"Input: {test['message']}")

                try:
                    # Process message
                    result = conversation_service.process_message(
                        user=user,
                        message=test["message"],
                        user_location=test["location"],
                    )

                    # Display result
                    self.stdout.write(
                        f"AI Response: {result.get('response', 'No response')}"
                    )
                    self.stdout.write(f"Intent: {result.get('intent', 'Unknown')}")
                    self.stdout.write(f"Language: {result.get('language', 'Unknown')}")
                    self.stdout.write(f"Confidence: {result.get('confidence', 0.0)}")

                    if result.get("suggested_businesses"):
                        self.stdout.write(
                            f"Suggested businesses: {len(result['suggested_businesses'])}"
                        )

                    if result.get("follow_ups"):
                        self.stdout.write("Follow-up suggestions:")
                        for follow_up in result["follow_ups"][:2]:
                            self.stdout.write(f"  - {follow_up}")

                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f"Error processing message: {e}")
                    )

            # Test conversation context
            self.stdout.write("\n--- Testing Conversation Context ---")

            conversation_id = None
            context_messages = [
                "Ndashaka kurya pizza",
                "Ese hari ubumenyangiye?",
                "Ni angahe?",
            ]

            for i, message in enumerate(context_messages, 1):
                self.stdout.write(f"\nContext Test {i}: {message}")

                try:
                    result = conversation_service.process_message(
                        user=user,
                        message=message,
                        conversation_id=conversation_id,
                        user_location={"latitude": -1.9441, "longitude": 30.0619},
                    )

                    conversation_id = result.get("conversation_id")
                    self.stdout.write(
                        f"AI Response: {result.get('response', 'No response')}"
                    )

                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"Error in context test: {e}"))

            self.stdout.write(
                self.style.SUCCESS("\nAI conversation testing completed!")
            )

        except User.DoesNotExist:
            self.stdout.write(
                self.style.ERROR(f'User {options["user_email"]} not found')
            )
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error during testing: {e}"))
