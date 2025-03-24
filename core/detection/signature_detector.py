from typing import Dict, Any, Optional
from core.rules.rule_loader import RuleManager
from utils.logger import get_logger

logger = get_logger(__name__)

class SignatureDetector:
    def __init__(self):
        self.rule_manager = RuleManager()
        
    async def detect(self, event):
        # Get all enabled signature rules
        rules = await self.rule_manager.get_rules({
            "rule_type": "signature", 
            "enabled": True
        })
        
        for rule in rules:
            if await self._match_rule(event, rule):
                logger.info(f"Event matched signature rule: {rule['name']}")
                return {
                    "name": rule['name'],
                    "description": rule['description'],
                    "severity": rule['severity'],
                    "detection_type": "signature",
                    "rule_id": str(rule.get('_id', '')),
                    "tags": rule.get('tags', [])
                }
                
        return None
        
    async def _match_rule(self, event, rule):
        try:
            detection_conditions = rule.get('detection', {}).get('conditions', {})
            
            # Check for simple field matches
            for field, expected_value in detection_conditions.items():
                # Handle nested fields using dot notation (e.g., "details.ip")
                if "." in field:
                    parts = field.split(".")
                    value = event
                    for part in parts:
                        if isinstance(value, dict) and part in value:
                            value = value[part]
                        else:
                            return False
                else:
                    # Direct field access
                    if field not in event:
                        return False
                    value = event[field]
                    
                # Check if value matches expected value
                if value != expected_value:
                    return False
                    
            return True
            
        except Exception as e:
            logger.error(f"Error matching rule {rule.get('name')}: {str(e)}")
            return False
