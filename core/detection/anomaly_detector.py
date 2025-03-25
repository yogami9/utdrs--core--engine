from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import statistics
from utils.logger import get_logger
from core.database.connection import get_database

logger = get_logger(__name__)

class AnomalyDetector:
    def __init__(self):
        self.db = get_database()
        self.baseline_window = 7  # Days to look back for baseline
        self.anomaly_threshold = 2.0  # Standard deviations from mean

    async def detect(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect anomalies in the event by comparing with historical data patterns.
        
        Args:
            event: The event to analyze for anomalies
            
        Returns:
            Detection result dict if anomaly found, None otherwise
        """
        event_type = event.get('event_type', '')
        source = event.get('source', '')
        
        if not event_type or not source:
            logger.debug("Event missing type or source, skipping anomaly detection")
            return None
            
        # Different detection strategies based on event type
        if 'authentication' in event_type:
            return await self._detect_auth_anomalies(event)
        elif 'network' in event_type:
            return await self._detect_network_anomalies(event)
        elif 'file' in event_type:
            return await self._detect_file_anomalies(event)
        else:
            # Default frequency-based detection
            return await self._detect_frequency_anomalies(event)
            
    async def _detect_auth_anomalies(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect authentication anomalies such as:
        - Login from unusual location/IP
        - Login at unusual time
        - Multiple failed login attempts
        - Unusual account privilege usage
        """
        user_id = event.get('data', {}).get('user_id')
        if not user_id:
            return None
            
        # Check for unusual login time
        timestamp = datetime.fromisoformat(event.get('timestamp', datetime.utcnow().isoformat()))
        hour_of_day = timestamp.hour
        
        # Get historical login times for this user
        auth_events = await self.db.events.find({
            'event_type': 'authentication',
            'data.user_id': user_id,
            'timestamp': {'$gte': (datetime.utcnow() - timedelta(days=self.baseline_window)).isoformat()}
        }).to_list(length=1000)
        
        # If we have enough data to establish a baseline
        if len(auth_events) >= 5:
            # Extract hours of previous logins
            login_hours = [datetime.fromisoformat(e.get('timestamp')).hour for e in auth_events]
            
            # Flag logins outside usual hours (e.g., if user typically logs in 8-17, flag 3am login)
            usual_hours = set()
            for h in login_hours:
                usual_hours.add(h)
                
            # If current login hour is not in usual hours
            if hour_of_day not in usual_hours and len(usual_hours) >= 3:
                return {
                    "name": "Unusual Login Time",
                    "description": f"User logged in at {hour_of_day}:00, outside their usual pattern",
                    "severity": "medium",
                    "detection_type": "anomaly",
                    "subtype": "auth_time_anomaly",
                    "confidence": 0.75,
                    "tags": ["authentication", "time-anomaly"]
                }
        
        # Check for failed login attempts
        if event.get('data', {}).get('status') == 'failed':
            # Count recent failed attempts
            recent_failures = await self.db.events.count_documents({
                'event_type': 'authentication',
                'data.user_id': user_id,
                'data.status': 'failed',
                'timestamp': {'$gte': (datetime.utcnow() - timedelta(hours=1)).isoformat()}
            })
            
            if recent_failures >= 5:
                return {
                    "name": "Multiple Failed Login Attempts",
                    "description": f"User had {recent_failures} failed login attempts in the past hour",
                    "severity": "high",
                    "detection_type": "anomaly",
                    "subtype": "auth_brute_force",
                    "confidence": 0.85,
                    "tags": ["authentication", "brute-force"]
                }
                
        return None
        
    async def _detect_network_anomalies(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect network anomalies such as:
        - Unusual traffic volume
        - Communication with unusual destinations
        - Unusual protocol usage
        """
        src_ip = event.get('data', {}).get('src_ip')
        dst_ip = event.get('data', {}).get('dst_ip')
        bytes_sent = event.get('data', {}).get('bytes_sent', 0)
        
        if not src_ip or not dst_ip:
            return None
            
        # Check for unusual traffic volume
        if bytes_sent > 0:
            # Get historical traffic volumes for this source IP
            historical_traffic = await self.db.events.find({
                'event_type': 'network',
                'data.src_ip': src_ip,
                'timestamp': {'$gte': (datetime.utcnow() - timedelta(days=self.baseline_window)).isoformat()}
            }).to_list(length=500)
            
            if len(historical_traffic) >= 10:
                traffic_volumes = [e.get('data', {}).get('bytes_sent', 0) for e in historical_traffic]
                avg_volume = statistics.mean(traffic_volumes)
                stdev_volume = statistics.stdev(traffic_volumes) if len(traffic_volumes) > 1 else avg_volume / 2
                
                # Detect if current traffic is significantly higher than normal
                if stdev_volume > 0 and bytes_sent > avg_volume + (self.anomaly_threshold * stdev_volume):
                    return {
                        "name": "Unusual Network Traffic Volume",
                        "description": f"Traffic volume ({bytes_sent} bytes) is {(bytes_sent - avg_volume) / stdev_volume:.1f} standard deviations above normal",
                        "severity": "medium",
                        "detection_type": "anomaly",
                        "subtype": "network_volume_anomaly",
                        "confidence": min(0.9, (bytes_sent - avg_volume) / (stdev_volume * 3)),
                        "tags": ["network", "data-exfiltration"]
                    }
        
        # Check for unusual destination
        historical_destinations = await self.db.events.distinct('data.dst_ip', {
            'event_type': 'network',
            'data.src_ip': src_ip,
            'timestamp': {'$gte': (datetime.utcnow() - timedelta(days=self.baseline_window)).isoformat()}
        })
        
        if len(historical_destinations) >= 5 and dst_ip not in historical_destinations:
            return {
                "name": "Communication with Unusual Destination",
                "description": f"First time {src_ip} has connected to {dst_ip} in the baseline period",
                "severity": "low",
                "detection_type": "anomaly",
                "subtype": "network_destination_anomaly",
                "confidence": 0.65,
                "tags": ["network", "unusual-connection"]
            }
                
        return None
    
    async def _detect_file_anomalies(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect file-related anomalies such as:
        - Mass file deletions or modifications
        - Access to sensitive files
        - Unusual file operations
        """
        filepath = event.get('data', {}).get('filepath', '')
        operation = event.get('data', {}).get('operation', '')
        user_id = event.get('data', {}).get('user_id', '')
        
        if not filepath or not operation:
            return None
            
        # Check for sensitive file access
        sensitive_paths = ['/etc/passwd', '/etc/shadow', '/var/log', 
                          '/root/.ssh', '/.ssh', 'C:\\Windows\\System32',
                          'boot.ini', 'SAM', 'NTDS.dit']
                          
        if any(sensitive in filepath for sensitive in sensitive_paths):
            # Check if user has historically accessed this file
            historical_access = await self.db.events.count_documents({
                'event_type': 'file',
                'data.filepath': filepath,
                'data.user_id': user_id,
                'timestamp': {'$gte': (datetime.utcnow() - timedelta(days=self.baseline_window)).isoformat()}
            })
            
            if historical_access == 0:
                return {
                    "name": "Sensitive File Access",
                    "description": f"First time user {user_id} has accessed sensitive file/path {filepath}",
                    "severity": "high",
                    "detection_type": "anomaly",
                    "subtype": "file_access_anomaly",
                    "confidence": 0.8,
                    "tags": ["file-access", "sensitive-data"]
                }
                
        # Check for mass file operations
        if operation in ['delete', 'modify', 'encrypt']:
            # Count recent operations by this user
            recent_operations = await self.db.events.count_documents({
                'event_type': 'file',
                'data.operation': operation,
                'data.user_id': user_id,
                'timestamp': {'$gte': (datetime.utcnow() - timedelta(minutes=5)).isoformat()}
            })
            
            if recent_operations >= 10:
                return {
                    "name": "Mass File Operation",
                    "description": f"User {user_id} performed {operation} operation on {recent_operations} files in 5 minutes",
                    "severity": "high",
                    "detection_type": "anomaly",
                    "subtype": "mass_file_operation",
                    "confidence": min(0.95, recent_operations / 20),
                    "tags": ["file-operation", "potential-ransomware"]
                }
                
        return None
        
    async def _detect_frequency_anomalies(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect anomalies based on event frequency:
        - Unusual number of events from a source
        - Unusual distribution of event types
        """
        event_type = event.get('event_type', '')
        source = event.get('source', '')
        
        # Get count of events of this type in the last hour
        recent_count = await self.db.events.count_documents({
            'event_type': event_type,
            'source': source,
            'timestamp': {'$gte': (datetime.utcnow() - timedelta(hours=1)).isoformat()}
        })
        
        # Get historical hourly counts
        pipeline = [
            {'$match': {
                'event_type': event_type,
                'source': source,
                'timestamp': {'$gte': (datetime.utcnow() - timedelta(days=self.baseline_window)).isoformat()}
            }},
            {'$group': {
                '_id': {
                    'hour': {'$hour': {'$dateFromString': {'dateString': '$timestamp'}}},
                    'day': {'$dayOfMonth': {'$dateFromString': {'dateString': '$timestamp'}}}
                },
                'count': {'$sum': 1}
            }}
        ]
        
        hourly_counts = await self.db.events.aggregate(pipeline).to_list(length=1000)
        
        if len(hourly_counts) >= 24:  # If we have at least a day's worth of hourly data
            counts = [doc['count'] for doc in hourly_counts]
            avg_count = statistics.mean(counts)
            stdev_count = statistics.stdev(counts) if len(counts) > 1 else avg_count / 2
            
            # If current count is significantly higher than normal
            if stdev_count > 0 and recent_count > avg_count + (self.anomaly_threshold * stdev_count):
                return {
                    "name": "Unusual Event Frequency",
                    "description": f"Frequency of {event_type} events from {source} ({recent_count} in last hour) is {(recent_count - avg_count) / stdev_count:.1f} standard deviations above normal",
                    "severity": "medium",
                    "detection_type": "anomaly",
                    "subtype": "frequency_anomaly",
                    "confidence": min(0.9, (recent_count - avg_count) / (stdev_count * 3)),
                    "tags": ["frequency-analysis"]
                }
                
        return None