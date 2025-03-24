from typing import Dict, Any, Optional
from core.models.ml.model_registry import ModelRegistry
from utils.logger import get_logger
import os
from config import settings

logger = get_logger(__name__)

class MLDetector:
    def __init__(self):
        self.model_registry = ModelRegistry(settings.MODEL_PATH)
        
    async def detect(self, event):
        # Determine which ML model to use based on event type
        event_type = event.get('event_type', '')
        
        if 'email' in event_type or 'url' in event_type:
            # Use phishing detector for email or URL events
            model_result = await self._run_phishing_detection(event)
            if model_result and model_result['confidence'] > 0.7:  # 70% confidence threshold
                return {
                    "name": "Potential Phishing Attempt",
                    "description": f"ML model detected phishing indicators with {model_result['confidence']*100:.1f}% confidence",
                    "severity": "high" if model_result['confidence'] > 0.9 else "medium",
                    "detection_type": "ml",
                    "model": "phishing_detector",
                    "confidence": model_result['confidence'],
                    "tags": ["phishing", "ml-detection"]
                }
                
        elif 'file' in event_type or 'process' in event_type:
            # Use ransomware detector for file or process events
            model_result = await self._run_ransomware_detection(event)
            if model_result and model_result['confidence'] > 0.7:  # 70% confidence threshold
                return {
                    "name": "Potential Ransomware Activity",
                    "description": f"ML model detected ransomware indicators with {model_result['confidence']*100:.1f}% confidence",
                    "severity": "critical" if model_result['confidence'] > 0.9 else "high",
                    "detection_type": "ml",
                    "model": "ransomware_detector",
                    "confidence": model_result['confidence'],
                    "tags": ["ransomware", "ml-detection"]
                }
                
        # No threat detected
        return None
        
    async def _run_phishing_detection(self, event):
        # In a real system, this would extract features from the event
        # and use a trained ML model to classify the event
        
        # For now, return None (no detection)
        return None
        
    async def _run_ransomware_detection(self, event):
        # In a real system, this would extract features from the event
        # and use a trained ML model to classify the event
        
        # For now, return None (no detection)
        return None
