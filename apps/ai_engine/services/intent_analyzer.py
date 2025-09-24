# apps/ai_engine/services/intent_analyzer.py
import re
import logging
from typing import Dict, Any, List
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class IntentType(Enum):
    SEARCH_BUSINESS = "search_business"
    FOOD_SEARCH = "food_search"
    TRANSPORT_SEARCH = "transport_search"
    EMERGENCY_HELP = "emergency_help"
    GREETING = "greeting"
    GENERAL_INQUIRY = "general_inquiry"

@dataclass
class IntentPattern:
    keywords: List[str]
    patterns: List[str]
    confidence_boost: float = 0.0
    cultural_indicators: List[str] = None

class IntentAnalyzer:
    def __init__(self):
        self.intent_patterns = self._initialize_intent_patterns()
        self.cultural_contexts = self._initialize_cultural_contexts()
    
    def _initialize_intent_patterns(self):
        return {
            IntentType.SEARCH_BUSINESS: {
                'en': IntentPattern(
                    keywords=['find', 'search', 'look for', 'where is', 'near me'],
                    patterns=[r'(find|search|look for|where is|near me)'],
                    confidence_boost=0.2,
                    cultural_indicators=['please', 'could you', 'would you']
                ),
                'rw': IntentPattern(
                    keywords=['shakira', 'reka', 'nshakire', 'hari he', 'hafi yawe'],
                    patterns=[r'(shakira|reka|nshakire|hari he|hafi yawe)'],
                    confidence_boost=0.3,
                    cultural_indicators=['murakoze', 'nshobora', 'woshobora']
                )
            },
            IntentType.FOOD_SEARCH: {
                'en': IntentPattern(
                    keywords=['hungry', 'eat', 'food', 'restaurant', 'meal'],
                    patterns=[r'(hungry|eat|food|restaurant|meal)'],
                    confidence_boost=0.4,
                    cultural_indicators=['please', 'thank you']
                ),
                'rw': IntentPattern(
                    keywords=['inzara', 'kurya', 'ibiribwa', 'restoran', 'ifunguro'],
                    patterns=[r'(inzara|kurya|ibiribwa|restoran|ifunguro)'],
                    confidence_boost=0.5,
                    cultural_indicators=['murakoze', 'nshobora']
                )
            },
            IntentType.TRANSPORT_SEARCH: {
                'en': IntentPattern(
                    keywords=['transport', 'ride', 'taxi', 'moto', 'bus', 'travel', 'go to', 'buy', 'motorcycle', 'vehicle'],
                    patterns=[r'(transport|ride|taxi|moto|bus|travel|go to|buy|motorcycle|vehicle)'],
                    confidence_boost=0.3,
                    cultural_indicators=['please', 'could you', 'would you']
                ),
                'rw': IntentPattern(
                    keywords=['genda', 'moto', 'taxi', 'bus', 'guhaguruka', 'kugenda', 'gufata', 'gura', 'gucuruza'],
                    patterns=[r'(genda|moto|taxi|bus|guhaguruka|kugenda|gufata|gura|gucuruza)'],
                    confidence_boost=0.4,
                    cultural_indicators=['murakoze', 'nshobora', 'woshobora']
                )
            },
            IntentType.EMERGENCY_HELP: {
                'en': IntentPattern(
                    keywords=['help', 'emergency', 'broken', 'stuck', 'lost'],
                    patterns=[r'(help|emergency|broken|stuck|lost)'],
                    confidence_boost=0.6,
                    cultural_indicators=['please', 'urgent']
                ),
                'rw': IntentPattern(
                    keywords=['fasha', 'ikibazo', 'rapfuye', 'ntashoboye', 'wabuze'],
                    patterns=[r'(fasha|ikibazo|rapfuye|ntashoboye|wabuze)'],
                    confidence_boost=0.7,
                    cultural_indicators=['murakoze', 'nshobora']
                )
            }
        }
    
    def _initialize_cultural_contexts(self):
        return {
            'en': {
                'politeness_indicators': ['please', 'thank you', 'could you', 'would you'],
                'urgency_indicators': ['urgent', 'asap', 'immediately', 'right now'],
                'location_indicators': ['here', 'there', 'near me', 'around here']
            },
            'rw': {
                'politeness_indicators': ['murakoze', 'nshobora', 'woshobora', 'ndasaba'],
                'urgency_indicators': ['vuba', 'mu kanya', 'ubungubu', 'ubu'],
                'location_indicators': ['hano', 'hariya', 'hafi', 'mu kigali']
            }
        }
    
    def analyze_intent(self, message: str, language: str = 'en', context: Dict = None) -> Dict[str, Any]:
        if not message or not message.strip():
            return self._create_intent_result(IntentType.GENERAL_INQUIRY, 0.0, [], language)
        
        message_lower = message.lower().strip()
        context = context or {}
        cultural_context = self.cultural_contexts.get(language, self.cultural_contexts['en'])
        
        intent_scores = {}
        detected_entities = []
        
        for intent_type, patterns in self.intent_patterns.items():
            if language not in patterns:
                continue
                
            pattern_data = patterns[language]
            score = self._calculate_intent_score(message_lower, pattern_data, cultural_context, context)
            
            if score > 0:
                intent_scores[intent_type] = score
                entities = self._extract_entities_for_intent(message, intent_type, language, pattern_data)
                detected_entities.extend(entities)
        
        if intent_scores:
            best_intent = max(intent_scores, key=intent_scores.get)
            confidence = intent_scores[best_intent]
        else:
            best_intent = IntentType.GENERAL_INQUIRY
            confidence = 0.1
        
        cultural_analysis = self._analyze_cultural_appropriateness(message_lower, cultural_context)
        requires_clarification = self._requires_clarification(best_intent, confidence, detected_entities, context)
        
        return {
            'intent': best_intent.value,
            'confidence': min(confidence, 1.0),
            'entities': detected_entities,
            'cultural_analysis': cultural_analysis,
            'requires_clarification': requires_clarification,
            'language': language,
            'suggested_questions': self._generate_suggested_questions(best_intent, language, requires_clarification)
        }
    
    def _calculate_intent_score(self, message: str, pattern_data: IntentPattern, 
                              cultural_context: Dict, context: Dict) -> float:
        score = 0.0
        
        keyword_matches = sum(1 for keyword in pattern_data.keywords if keyword in message)
        if keyword_matches > 0:
            score += (keyword_matches / len(pattern_data.keywords)) * 0.4
        
        pattern_matches = 0
        for pattern in pattern_data.patterns:
            if re.search(pattern, message, re.IGNORECASE):
                pattern_matches += 1
        
        if pattern_matches > 0:
            score += (pattern_matches / len(pattern_data.patterns)) * 0.5
        
        if pattern_data.cultural_indicators:
            cultural_matches = sum(1 for indicator in pattern_data.cultural_indicators if indicator in message)
            if cultural_matches > 0:
                score += (cultural_matches / len(pattern_data.cultural_indicators)) * 0.2
        
        score += pattern_data.confidence_boost
        return min(score, 1.0)
    
    def _extract_entities_for_intent(self, message: str, intent_type: IntentType, 
                                   language: str, pattern_data: IntentPattern) -> List[Dict[str, Any]]:
        entities = []
        message_lower = message.lower()
        
        if intent_type in [IntentType.SEARCH_BUSINESS, IntentType.FOOD_SEARCH]:
            business_types = self._get_business_types(language)
            for entity_type, keywords in business_types.items():
                if any(keyword in message_lower for keyword in keywords):
                    entities.append({
                        'type': 'business_type',
                        'value': entity_type,
                        'confidence': 0.8,
                        'language': language
                    })
        
        return entities
    
    def _get_business_types(self, language: str) -> Dict[str, List[str]]:
        if language == 'rw':
            return {
                'restaurant': ['restoran', 'ibiribwa', 'kurya', 'ifunguro'],
                'hotel': ['hoteli', 'guhagarara', 'kurara'],
                'shop': ['ubucuruzi', 'gucururwa', 'isoko'],
                'garage': ['igaraje', 'gukora', 'makanika']
            }
        else:
            return {
                'restaurant': ['restaurant', 'food', 'eat', 'meal', 'dining'],
                'hotel': ['hotel', 'accommodation', 'stay', 'sleep'],
                'shop': ['shop', 'store', 'buy', 'shopping'],
                'garage': ['garage', 'repair', 'fix', 'mechanic']
            }
    
    def _analyze_cultural_appropriateness(self, message: str, cultural_context: Dict) -> Dict[str, Any]:
        politeness_score = sum(1 for indicator in cultural_context['politeness_indicators'] if indicator in message) / len(cultural_context['politeness_indicators'])
        urgency_score = sum(1 for indicator in cultural_context['urgency_indicators'] if indicator in message) / len(cultural_context['urgency_indicators'])
        location_mentioned = any(indicator in message for indicator in cultural_context['location_indicators'])
        
        return {
            'politeness_score': politeness_score,
            'urgency_score': urgency_score,
            'location_mentioned': location_mentioned,
            'is_culturally_appropriate': politeness_score > 0.1 or urgency_score > 0.1,
            'tone': 'urgent' if urgency_score > 0.3 else 'polite' if politeness_score > 0.3 else 'neutral'
        }
    
    def _requires_clarification(self, intent: IntentType, confidence: float, 
                              entities: List[Dict], context: Dict) -> bool:
        if confidence < 0.6:
            return True
        
        entity_requiring_intents = [IntentType.SEARCH_BUSINESS, IntentType.FOOD_SEARCH, IntentType.EMERGENCY_HELP]
        if intent in entity_requiring_intents and not entities:
            return True
        
        return False
    
    def _generate_suggested_questions(self, intent: IntentType, language: str, 
                                    requires_clarification: bool) -> List[str]:
        if not requires_clarification:
            return []
        
        if language == 'rw':
            questions = {
                IntentType.SEARCH_BUSINESS: ["Ushaka ikihe gucuruzi?", "Ushaka kugera he?"],
                IntentType.FOOD_SEARCH: ["Ushaka ibiribwa byahe?", "Ushaka kurya he?"],
                IntentType.EMERGENCY_HELP: ["Ufite ikihe kibazo?", "Uri he?"]
            }
        else:
            questions = {
                IntentType.SEARCH_BUSINESS: ["What type of business are you looking for?", "Where do you want to go?"],
                IntentType.FOOD_SEARCH: ["What type of food do you want?", "Where would you like to eat?"],
                IntentType.EMERGENCY_HELP: ["What kind of help do you need?", "Where are you located?"]
            }
        
        return questions.get(intent, [])
    
    def _create_intent_result(self, intent: IntentType, confidence: float, 
                            entities: List[Dict], language: str) -> Dict[str, Any]:
        return {
            'intent': intent.value,
            'confidence': confidence,
            'entities': entities,
            'cultural_analysis': {
                'is_culturally_appropriate': False,
                'politeness_score': 0.0,
                'urgency_score': 0.0,
                'location_mentioned': False,
                'tone': 'neutral'
            },
            'requires_clarification': confidence < 0.6,
            'language': language,
            'suggested_questions': []
        }