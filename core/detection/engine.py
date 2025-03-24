from typing import Dict, List, Any, Optional
from core.database.repositories.alert_repository import AlertRepository
from core.rules.rule_loader import RuleManager
from core.detection.signature_detector import SignatureDetector
from core.detection.anomaly_detector import AnomalyDetector
from core.detection.ml_detector import MLDetector
from core.models.schema.alert import Alert, AlertCreate
from utils.logger import get_logger

logger = get_logger(__name__)

class DetectionEngine:
    def __init__(self):
        self.alert_repository = AlertRepository()
        self.rule_manager = RuleManager()
        self.signature_detector = SignatureDetector()
        self.anomaly_detector = AnomalyDetector()
        self.ml_detector = MLDetector()
        
    async def detect_threats(self, event):
        logger.info(f"Analyzing event from source: {event.get('source', 'unknown')}")
        
        # Try signature-based detection first (fastest)
        signature_result = await self.signature_detector.detect(event)
        if signature_result:
            logger.info(f"Signature detection found threat: {signature_result['name']}")
            return await self._create_alert(event, signature_result)
            
        # Try ML-based detection
        ml_result = await self.ml_detector.detect(event)
        if ml_result:
            logger.info(f"ML detection found threat: {ml_result['name']}")
            return await self._create_alert(event, ml_result)
            
        # Try anomaly detection
        anomaly_result = await self.anomaly_detector.detect(event)
        if anomaly_result:
            logger.info(f"Anomaly detection found threat: {anomaly_result['name']}")
            return await self._create_alert(event, anomaly_result)
            
        logger.info("No threats detected in event")
        return None
        
    async def _create_alert(self, event, detection_result):
        alert_data = AlertCreate(
            title=detection_result['name'],
            description=detection_result['description'],
            severity=detection_result['severity'],
            source=event.get('source', 'unknown'),
            event_ids=[event.get('id', 'unknown')],
            detection_type=detection_result['detection_type'],
            details={
                'event': event,
                'detection': detection_result
            }
        )
        
        return await self.alert_repository.create_alert(alert_data)
        
    async def get_alerts(self, filters, limit=100, skip=0):
        return await self.alert_repository.find_many(filters, limit, skip)
        
    async def get_alert_by_id(self, alert_id):
        return await self.alert_repository.find_by_id(alert_id)
