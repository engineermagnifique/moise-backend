# apps/ai_engine/services/language_service.py
import re
from typing import Dict, Any, Optional

class LanguageService:
    """Service for language detection and translation"""
    
    def __init__(self):
        # Language detection patterns
        self.language_patterns = {
            'en': [
                r'\b(the|and|or|but|in|on|at|to|for|of|with|by)\b',
                r'\b(is|are|was|were|be|been|being)\b',
                r'\b(restaurant|hotel|shop|store|service)\b',
                r'\b(hello|hi|hey|thank|you|help|please)\b'
            ],
            'rw': [
                r'\b(na|kandi|cyangwa|ariko|mu|ku|kuri|kubera|hamwe|na)\b',
                r'\b(ni|ari|wari|wari|kuba|waba|kuba)\b',
                r'\b(restoran|hoteli|ubucuruzi|serivisi)\b',
                r'\b(muraho|mwaramutse|mwirirwe|murakoze|nshobora|woshobora)\b',
                r'\b(ndashaka|nshaka|ndabaza|mfasha|fasha)\b',
                r'\b(ndi|uri|ari|turi|muri|bari)\b'
            ],
            'fr': [
                r'\b(le|la|les|et|ou|mais|dans|sur|à|pour|de|avec|par)\b',
                r'\b(est|sont|était|étaient|être|été|étant)\b',
                r'\b(restaurant|hôtel|magasin|service)\b'
            ]
        }
        
        # Translation dictionaries (simplified)
        self.translations = {
            'en': {
                'restaurant': 'restaurant',
                'hotel': 'hotel',
                'shop': 'shop',
                'store': 'store',
                'service': 'service'
            },
            'rw': {
                'restaurant': 'restoran',
                'hotel': 'hoteli',
                'shop': 'ubucuruzi',
                'store': 'ubucuruzi',
                'service': 'serivisi'
            },
            'fr': {
                'restaurant': 'restaurant',
                'hotel': 'hôtel',
                'shop': 'magasin',
                'store': 'magasin',
                'service': 'service'
            }
        }
    
    def detect_language(self, text: str) -> str:
        """Detect the language of input text"""
        
        if not text or not text.strip():
            return 'en'  # Default to English
        
        text_lower = text.lower()
        scores = {}
        
        # Calculate scores for each language
        for lang, patterns in self.language_patterns.items():
            score = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, text_lower, re.IGNORECASE))
                score += matches
            scores[lang] = score
        
        # Return language with highest score
        if scores:
            detected_lang = max(scores, key=scores.get)
            # Only return detected language if it has a score > 0, otherwise default to English
            return detected_lang if scores[detected_lang] > 0 else 'en'
        
        return 'en'
    
    def translate_text(self, text: str, target_language: str, source_language: Optional[str] = None) -> str:
        """Translate text to target language"""
        
        if not text or not text.strip():
            return text
        
        # Auto-detect source language if not provided
        if not source_language:
            source_language = self.detect_language(text)
        
        # If source and target are the same, return original text
        if source_language == target_language:
            return text
        
        # Simple word-by-word translation (in production, use proper translation API)
        words = text.split()
        translated_words = []
        
        for word in words:
            word_lower = word.lower()
            translated_word = word  # Default to original word
            
            # Check if word exists in translation dictionary
            if word_lower in self.translations.get(source_language, {}):
                translated_word = self.translations[source_language][word_lower]
            
            translated_words.append(translated_word)
        
        return ' '.join(translated_words)
    
    def get_supported_languages(self) -> Dict[str, str]:
        """Get list of supported languages"""
        
        return {
            'en': 'English',
            'rw': 'Kinyarwanda',
            'fr': 'Français'
        }
    
    def is_language_supported(self, language_code: str) -> bool:
        """Check if language is supported"""
        
        return language_code in self.get_supported_languages()
    
    def get_language_name(self, language_code: str) -> str:
        """Get language name from code"""
        
        languages = self.get_supported_languages()
        return languages.get(language_code, 'Unknown')
    
    def detect_and_translate(self, text: str, target_language: str) -> Dict[str, Any]:
        """Detect language and translate to target"""
        
        source_language = self.detect_language(text)
        translated_text = self.translate_text(text, target_language, source_language)
        
        return {
            'original_text': text,
            'translated_text': translated_text,
            'source_language': source_language,
            'target_language': target_language,
            'confidence': 0.8  # Placeholder confidence score
        }