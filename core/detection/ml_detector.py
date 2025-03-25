from typing import Dict, Any, Optional, List
import os
import json
import numpy as np
from datetime import datetime
import pickle
from utils.logger import get_logger
from config import settings
from core.models.ml.model_registry import ModelRegistry

logger = get_logger(__name__)

class MLDetector:
    """
    Machine Learning-based threat detector that uses trained models to identify threats.
    """
    
    def __init__(self):
        self.model_registry = ModelRegistry(settings.MODEL_PATH)
        # Default confidence threshold for ML detections
        self.confidence_threshold = 0.7
        
    async def detect(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect threats using machine learning models based on event type.
        
        Args:
            event: The event to analyze
            
        Returns:
            Detection result dict if a threat is detected, None otherwise
        """
        # Determine which ML model to use based on event type
        event_type = event.get('event_type', '')
        
        if not event_type:
            logger.debug("Event missing type, skipping ML detection")
            return None
        
        # Route to appropriate specialized detector based on event type
        if any(t in event_type for t in ['email', 'url', 'web']):
            return await self._run_phishing_detection(event)
        elif any(t in event_type for t in ['file', 'process']):
            return await self._run_malware_detection(event)
        elif any(t in event_type for t in ['network', 'traffic', 'dns']):
            return await self._run_network_anomaly_detection(event)
        elif any(t in event_type for t in ['auth', 'login', 'user']):
            return await self._run_user_behavior_detection(event)
            
        # No matching specialized detector
        logger.debug(f"No specialized ML detector for event type: {event_type}")
        return None
        
    async def _run_phishing_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Run phishing detection on email or URL events.
        
        Args:
            event: The event to analyze
            
        Returns:
            Detection result if phishing is detected, None otherwise
        """
        # In a production system, we would:
        # 1. Extract relevant features from the event (URL, email text, etc.)
        # 2. Preprocess those features (tokenization, normalization, etc.)
        # 3. Run the preprocessed features through the loaded model
        # 4. Return results based on model confidence
        
        # For demonstration, we'll use a simple feature extraction and simulate model prediction
        model_file = os.path.join(settings.MODEL_PATH, 'phishing', 'model.pkl')
        
        # Check if we have a model file
        if not os.path.exists(model_file):
            logger.warning(f"Phishing model not found at {model_file}")
            # Simulate a model prediction for demonstration
            return await self._simulate_phishing_detection(event)
            
        try:
            # Extract features based on event type
            if 'email' in event.get('event_type', ''):
                features = self._extract_email_features(event)
            else:  # URL event
                features = self._extract_url_features(event)
                
            # Load model
            with open(model_file, 'rb') as f:
                model = pickle.load(f)
                
            # Make prediction
            confidence = model.predict_proba([features])[0][1]  # Probability of phishing class
            
            # If confidence meets threshold, return detection
            if confidence > self.confidence_threshold:
                severity = "high" if confidence > 0.9 else "medium"
                
                return {
                    "name": "Potential Phishing Attempt",
                    "description": f"ML model detected phishing indicators with {confidence*100:.1f}% confidence",
                    "severity": severity,
                    "detection_type": "ml",
                    "model": "phishing_detector",
                    "confidence": confidence,
                    "tags": ["phishing", "ml-detection"],
                    "mitre_techniques": ["T1566"],  # Phishing
                    "mitre_tactics": ["TA0001"]     # Initial Access
                }
                
        except Exception as e:
            logger.error(f"Error in phishing detection: {str(e)}")
            
        return None
        
    async def _simulate_phishing_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Simulate a phishing detection model for development/testing purposes.
        
        Args:
            event: The event to analyze
            
        Returns:
            Simulated detection result if phishing indicators are found, None otherwise
        """
        # Extract content based on event type
        content = ""
        score = 0.0
        
        if 'email' in event.get('event_type', ''):
            # Extract email content
            email_data = event.get('data', {})
            subject = email_data.get('subject', '').lower()
            body = email_data.get('body', '').lower()
            sender = email_data.get('sender', '').lower()
            
            content = f"{subject} {body}"
            
            # Simple rule-based scoring for demonstration
            phishing_keywords = [
                'urgent', 'account', 'verify', 'password', 'login', 'security', 
                'update', 'banking', 'click', 'link', 'confirm', 'suspend', 
                'unusual activity', 'credential', 'expire'
            ]
            
            score += sum(0.1 for kw in phishing_keywords if kw in content) 
            
            # Check for suspicious sender
            if '@' in sender and not any(legit in sender for legit in ['.com', '.org', '.edu', '.gov']):
                score += 0.2
                
            # Check for mismatch between display name and actual email
            if 'display_name' in email_data and 'sender' in email_data:
                display_name = email_data.get('display_name', '').lower()
                if any(company in display_name for company in ['paypal', 'amazon', 'bank', 'netflix']) and \
                   not any(company in sender for company in ['paypal', 'amazon', 'bank', 'netflix']):
                    score += 0.3
            
        else:  # URL event
            # Extract URL content
            url_data = event.get('data', {})
            url = url_data.get('url', '').lower()
            
            content = url
            
            # Simple rule-based scoring for demonstration
            if 'http:' in url and not 'https:' in url:
                score += 0.1
                
            suspicious_domains = [
                'login', 'account', 'secure', 'verify', 'update', 'billing',
                'payment', 'confirm', 'auth'
            ]
            
            # Check for suspicious domain
            if any(susp in url for susp in suspicious_domains):
                score += 0.1
                
            # Check for IP address in URL
            import re
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                score += 0.2
                
            # Check for unusual TLD
            common_tlds = ['.com', '.org', '.net', '.gov', '.edu', '.co', '.io']
            if not any(tld in url for tld in common_tlds):
                score += 0.1
                
            # Check for excessive subdomains
            if url.count('.') > 3:
                score += 0.1
                
            # Check for encoded characters
            if '%' in url:
                score += 0.1
                
        # If score meets threshold, return detection
        if score > self.confidence_threshold:
            severity = "high" if score > 0.9 else "medium"
            
            return {
                "name": "Potential Phishing Attempt",
                "description": f"ML model detected phishing indicators with {score*100:.1f}% confidence",
                "severity": severity,
                "detection_type": "ml",
                "model": "phishing_detector_simulated",
                "confidence": score,
                "tags": ["phishing", "ml-detection"],
                "mitre_techniques": ["T1566"],  # Phishing
                "mitre_tactics": ["TA0001"]     # Initial Access
            }
            
        return None
        
    async def _run_malware_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Run malware detection on file or process events.
        
        Args:
            event: The event to analyze
            
        Returns:
            Detection result if malware is detected, None otherwise
        """
        event_data = event.get('data', {})
        
        # In a real implementation, we would extract features such as:
        # - File hash or content
        # - Process behavior (file/registry/network operations)
        # - Memory patterns
        # - API call sequences
        
        # For demonstration, we'll use a simple rule-based simulation
        score = 0.0
        
        # Process behaviors that may indicate malware
        if 'process' in event.get('event_type', ''):
            # Process runs from temp directory
            if any(tmp_dir in event_data.get('process_path', '') 
                  for tmp_dir in ['temp', 'tmp', r'\Windows\Temp']):
                score += 0.2
                
            # Process with unusual name or path
            if event_data.get('process_name', '') in [
                'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe'
            ] and not event_data.get('process_path', '').lower().startswith(r'c:\windows\system32'):
                score += 0.3
                
            # Process making suspicious network connections
            connections = event_data.get('network_connections', [])
            if any(conn.get('remote_port') in [4444, 8080, 443, 8443] for conn in connections):
                score += 0.2
                
            # Process with suspicious command line
            cmdline = event_data.get('command_line', '').lower()
            if any(susp in cmdline for susp in [
                'powershell -enc', 'rundll32', 'regsvr32', 'bitsadmin', '