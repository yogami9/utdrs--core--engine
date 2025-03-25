from typing import Dict, List, Any, Optional
from datetime import datetime
import asyncio
from core.database.repositories.alert_repository import AlertRepository
from core.rules.rule_loader import RuleManager
from core.detection.signature_detector import SignatureDetector
from core.detection.anomaly_detector import AnomalyDetector
from core.detection.ml_detector import MLDetector
from core.models.schema.alert import Alert, AlertCreate
from utils.logger import get_logger

logger = get_logger(__name__)

class DetectionEngine:
    """
    Core detection engine that orchestrates and prioritizes different detection methods.
    """
    
    def __init__(self):
        """Initialize the detection engine with its component detectors."""
        self.alert_repository = AlertRepository()
        self.rule_manager = RuleManager()
        self.signature_detector = SignatureDetector()
        self.anomaly_detector = AnomalyDetector()
        self.ml_detector = MLDetector()
        
    async def detect_threats(self, event: Dict[str, Any]) -> Optional[Alert]:
        """
        Analyze an event for threats using all available detection methods.
        
        Args:
            event: The event to analyze
            
        Returns:
            Alert object if a threat is detected, None otherwise
        """
        source = event.get('source', 'unknown')
        event_type = event.get('event_type', 'unknown')
        logger.info(f"Analyzing {event_type} event from {source}")
        
        # Assign a unique ID to the event if it doesn't have one
        if 'id' not in event:
            from uuid import uuid4
            event['id'] = str(uuid4())
            
        # Add timestamp if not present
        if 'timestamp' not in event:
            event['timestamp'] = datetime.utcnow().isoformat()
        
        # Run detection methods concurrently for better performance
        signature_task = asyncio.create_task(self._run_signature_detection(event))
        ml_task = asyncio.create_task(self._run_ml_detection(event))
        anomaly_task = asyncio.create_task(self._run_anomaly_detection(event))
        
        # Wait for all detections to complete
        signature_result, ml_result, anomaly_result = await asyncio.gather(
            signature_task, ml_task, anomaly_task
        )
        
        # Process results in order of reliability/specificity
        if signature_result:
            logger.info(f"Signature detection found threat: {signature_result['name']}")
            return await self._create_alert(event, signature_result)
            
        if ml_result:
            logger.info(f"ML detection found threat: {ml_result['name']}")
            return await self._create_alert(event, ml_result)
            
        if anomaly_result:
            logger.info(f"Anomaly detection found threat: {anomaly_result['name']}")
            return await self._create_alert(event, anomaly_result)
            
        logger.info("No threats detected in event")
        return None
    
    async def _run_signature_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run signature-based detection on the event."""
        try:
            return await self.signature_detector.detect(event)
        except Exception as e:
            logger.error(f"Error in signature detection: {str(e)}")
            return None
            
    async def _run_ml_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run ML-based detection on the event."""
        try:
            return await self.ml_detector.detect(event)
        except Exception as e:
            logger.error(f"Error in ML detection: {str(e)}")
            return None
            
    async def _run_anomaly_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run anomaly detection on the event."""
        try:
            return await self.anomaly_detector.detect(event)
        except Exception as e:
            logger.error(f"Error in anomaly detection: {str(e)}")
            return None
        
    async def _create_alert(self, event: Dict[str, Any], detection_result: Dict[str, Any]) -> Alert:
        """
        Create an alert from a detection result.
        
        Args:
            event: The event that triggered the alert
            detection_result: The detection result with threat information
            
        Returns:
            The created Alert object
        """
        # Extract MITRE ATT&CK information if available
        mitre_tactics = detection_result.get('mitre_tactics', [])
        mitre_techniques = detection_result.get('mitre_techniques', [])
        
        # Calculate risk score based on severity and confidence
        risk_score = self._calculate_risk_score(detection_result)
        
        # Create alert data
        alert_data = AlertCreate(
            title=detection_result['name'],
            description=detection_result['description'],
            severity=detection_result['severity'],
            source=event.get('source', 'unknown'),
            event_ids=[event.get('id', 'unknown')],
            detection_type=detection_result['detection_type'],
            details={
                'event': event,
                'detection': detection_result,
                'mitre_tactics': mitre_tactics,
                'mitre_techniques': mitre_techniques,
                'risk_score': risk_score
            }
        )
        
        # Store the alert in the database
        alert = await self.alert_repository.create_alert(alert_data)
        
        # In a full system, we would also:
        # 1. Send alert to notification system
        # 2. Trigger automated response actions
        # 3. Update risk scores for affected assets
        
        return alert
    
    def _calculate_risk_score(self, detection_result: Dict[str, Any]) -> float:
        """
        Calculate a risk score from 0-100 based on detection characteristics.
        
        Args:
            detection_result: The detection result with threat information
            
        Returns:
            Risk score from 0-100
        """
        # Base score from severity
        severity_scores = {
            'critical': 90,
            'high': 70,
            'medium': 50,
            'low': 30,
            'info': 10
        }
        
        base_score = severity_scores.get(detection_result.get('severity', 'medium'), 50)
        
        # Adjust based on confidence if available
        confidence = detection_result.get('confidence', 0.8)
        confidence_multiplier = confidence
        
        # Boost score for certain detection types or tags
        boost = 0
        if 'ransomware' in detection_result.get('tags', []):
            boost += 10
        if 'lateral-movement' in detection_result.get('tags', []):
            boost += 5
        if 'data-exfiltration' in detection_result.get('tags', []):
            boost += 8
            
        # Calculate final score (capped at 100)
        risk_score = min(100, base_score * confidence_multiplier + boost)
        
        return risk_score
        
    async def get_alerts(self, filters: Dict[str, Any], limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """
        Get alerts based on filters.
        
        Args:
            filters: Dictionary of filter criteria
            limit: Maximum number of alerts to return
            skip: Number of alerts to skip (for pagination)
            
        Returns:
            List of matching alerts
        """
        return await self.alert_repository.find_many(filters, limit, skip)
        
    async def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific alert by ID.
        
        Args:
            alert_id: The ID of the alert to retrieve
            
        Returns:
            The alert if found, None otherwise
        """
        return await self.alert_repository.find_by_id(alert_id)
        
    async def update_alert_status(self, alert_id: str, status: str, assigned_to: Optional[str] = None) -> Optional[Alert]:
        """
        Update the status of an alert.
        
        Args:
            alert_id: The ID of the alert to update
            status: The new status (open, in_progress, resolved, closed, false_positive)
            assigned_to: The user to assign the alert to
            
        Returns:
            The updated alert if found, None otherwise
        """
        return await self.alert_repository.update_alert_status(alert_id, status, assigned_to)
        
    async def correlate_alerts(self, time_window_minutes: int = 60) -> List[Dict[str, Any]]:
        """
        Correlate recent alerts to identify related security incidents.
        
        Args:
            time_window_minutes: Time window for correlation in minutes
            
        Returns:
            List of correlation groups (potential security incidents)
        """
        # Get recent alerts within the time window
        from datetime import datetime, timedelta
        time_threshold = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        
        recent_alerts = await self.alert_repository.find_many({
            "created_at": {"$gte": time_threshold}
        }, limit=1000)
        
        # In a real implementation, we would implement various correlation algorithms:
        # 1. Source-based correlation (events from same source)
        # 2. Target-based correlation (events affecting same target)
        # 3. Technique-based correlation (MITRE ATT&CK)
        # 4. Time-based correlation (temporal patterns)
        
        # Simple source-based correlation for demonstration
        correlations = {}
        
        for alert in recent_alerts:
            source = alert.get('source', 'unknown')
            if source not in correlations:
                correlations[source] = {
                    "source": source,
                    "alert_count": 0,
                    "severity": "low",
                    "alert_ids": [],
                    "created_at": datetime.utcnow().isoformat()
                }
                
            correlation = correlations[source]
            correlation["alert_count"] += 1
            correlation["alert_ids"].append(alert.get('_id'))
            
            # Update highest severity
            severity_levels = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
            alert_severity = alert.get('severity', 'low')
            current_severity = correlation["severity"]
            
            if severity_levels.get(alert_severity, 0) > severity_levels.get(current_severity, 0):
                correlation["severity"] = alert_severity
        
        # Filter to only include sources with multiple alerts (actual correlations)
        return [
            correlation for correlation in correlations.values() 
            if correlation["alert_count"] > 1
        ]
        
    async def get_threat_summary(self) -> Dict[str, Any]:
        """
        Get a summary of current threat activity.
        
        Returns:
            Dictionary with threat summary statistics
        """
        # Get alert counts by severity
        from datetime import datetime, timedelta
        
        # Last 24 hours
        time_threshold = datetime.utcnow() - timedelta(hours=24)
        
        # Get total alert count
        total_alerts = await self.alert_repository.count({
            "created_at": {"$gte": time_threshold}
        })
        
        # Get count by severity
        severities = ['critical', 'high', 'medium', 'low', 'info']
        severity_counts = {}
        
        for severity in severities:
            count = await self.alert_repository.count({
                "severity": severity,
                "created_at": {"$gte": time_threshold}
            })
            severity_counts[severity] = count
            
        # Get count by detection type
        detection_types = ['signature', 'anomaly', 'ml']
        detection_type_counts = {}
        
        for detection_type in detection_types:
            count = await self.alert_repository.count({
                "detection_type": detection_type,
                "created_at": {"$gte": time_threshold}
            })
            detection_type_counts[detection_type] = count
            
        # Get top sources
        pipeline = [
            {"$match": {"created_at": {"$gte": time_threshold}}},
            {"$group": {"_id": "$source", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5}
        ]
        
        top_sources = await self.alert_repository.aggregate(pipeline)
        
        return {
            "total_alerts": total_alerts,
            "by_severity": severity_counts,
            "by_detection_type": detection_type_counts,
            "top_sources": top_sources,
            "time_period": "last_24_hours"
        }