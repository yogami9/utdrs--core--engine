"""
Unit tests for UTDRS core detection modules.
"""
import pytest
import asyncio
import pickle
import os
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

# Import modules to test
from core.detection.signature_detector import SignatureDetector
from core.detection.anomaly_detector import AnomalyDetector
from core.detection.ml_detector import MLDetector
from core.detection.engine import DetectionEngine
from core.mitre.mitre_attack import MitreAttackMapper
from core.risk.risk_scoring import RiskScorer
from core.models.ml.model_registry import ModelRegistry

# Test data
@pytest.fixture
def authentication_event():
    return {
        "id": "12345",
        "source": "windows_server",
        "event_type": "authentication",
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "user_id": "jsmith",
            "user_type": "admin",
            "status": "failed",
            "failure_count": 5,
            "source_ip": "192.168.1.100"
        }
    }

@pytest.fixture
def network_event():
    return {
        "id": "23456",
        "source": "network_firewall",
        "event_type": "network",
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "src_ip": "192.168.1.100",
            "dst_ip": "203.0.113.10",
            "dst_port": 445,
            "protocol": "tcp",
            "bytes_sent": 1500000,
            "bytes_received": 4500
        }
    }

@pytest.fixture
def file_event():
    return {
        "id": "34567",
        "source": "endpoint_agent",
        "event_type": "file",
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "filepath": "/etc/passwd",
            "operation": "read",
            "user_id": "jsmith",
            "process_name": "cat",
            "file_hash": "5d41402abc4b2a76b9719d911017c592"
        }
    }

@pytest.fixture
def process_event():
    return {
        "id": "45678",
        "source": "endpoint_agent",
        "event_type": "process",
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "process_name": "powershell.exe",
            "process_id": 1234,
            "parent_process_name": "cmd.exe",
            "parent_process_id": 1200,
            "command_line": "powershell -enc QQBsAGUAcgB0ACAAIgBIAGUAbABsAG8AIgA=",
            "user_id": "jsmith"
        }
    }

# Mock Rule Manager
@pytest.fixture
def mock_rule_manager():
    manager = MagicMock()
    # Configure the mock to return test rules
    manager.get_rules.return_value = asyncio.Future()
    manager.get_rules.return_value.set_result([
        {
            "name": "Multiple Failed Login Attempts",
            "description": "Detects multiple failed login attempts",
            "rule_type": "signature",
            "detection": {
                "condition_type": "AND",
                "conditions": {
                    "event_type": "authentication",
                    "data.status": "failed"
                }
            },
            "enabled": True,
            "severity": "medium",
            "tags": ["authentication", "brute-force"],
            "mitre_tactics": ["TA0006"],
            "mitre_techniques": ["T1110"]
        },
        {
            "name": "Sensitive File Access",
            "description": "Detects access to sensitive system files",
            "rule_type": "signature",
            "detection": {
                "condition_type": "AND",
                "conditions": {
                    "event_type": "file",
                    "data.filepath": "regex:.*(passwd|shadow|\.ssh|\.aws|\.config).*"
                }
            },
            "enabled": True,
            "severity": "medium",
            "tags": ["file", "sensitive-data"],
            "mitre_tactics": ["TA0006"],
            "mitre_techniques": ["T1552"]
        },
        {
            "name": "Suspicious PowerShell Command",
            "description": "Detects PowerShell commands with encoded content",
            "rule_type": "signature",
            "detection": {
                "condition_type": "AND",
                "conditions": {
                    "event_type": "process",
                    "data.process_name": "powershell.exe",
                    "data.command_line": "regex:.*(encodedcommand|enc).*"
                }
            },
            "enabled": True,
            "severity": "high",
            "tags": ["process", "powershell", "obfuscation"],
            "mitre_tactics": ["TA0002"],
            "mitre_techniques": ["T1059.001"]
        }
    ])
    return manager

# Mock Database
@pytest.fixture
def mock_db():
    db = MagicMock()
    
    # Configure mock collections and methods
    events = MagicMock()
    events.find.return_value.to_list.return_value = asyncio.Future()
    events.find.return_value.to_list.return_value.set_result([])
    events.count_documents.return_value = asyncio.Future()
    events.count_documents.return_value.set_result(0)
    
    db.events = events
    return db

# Tests for Signature Detector
@pytest.mark.asyncio
async def test_signature_detector_match(authentication_event, mock_rule_manager):
    """Test that the signature detector correctly matches rules to events."""
    with patch('core.rules.rule_loader.RuleManager', return_value=mock_rule_manager):
        detector = SignatureDetector()
        # Patch the rule_manager attribute directly
        detector.rule_manager = mock_rule_manager
        
        result = await detector.detect(authentication_event)
        
        assert result is not None
        assert result["name"] == "Multiple Failed Login Attempts"
        assert result["severity"] == "medium"
        assert "authentication" in result["tags"]
        assert "brute-force" in result["tags"]
        assert "T1110" in result["mitre_techniques"]

@pytest.mark.asyncio
async def test_signature_detector_file_match(file_event, mock_rule_manager):
    """Test that the signature detector matches sensitive file access."""
    with patch('core.rules.rule_loader.RuleManager', return_value=mock_rule_manager):
        detector = SignatureDetector()
        detector.rule_manager = mock_rule_manager
        
        result = await detector.detect(file_event)
        
        assert result is not None
        assert result["name"] == "Sensitive File Access"
        assert "file" in result["tags"]
        assert "sensitive-data" in result["tags"]

@pytest.mark.asyncio
async def test_signature_detector_process_match(process_event, mock_rule_manager):
    """Test that the signature detector matches suspicious PowerShell commands."""
    with patch('core.rules.rule_loader.RuleManager', return_value=mock_rule_manager):
        detector = SignatureDetector()
        detector.rule_manager = mock_rule_manager
        
        result = await detector.detect(process_event)
        
        assert result is not None
        assert result["name"] == "Suspicious PowerShell Command"
        assert result["severity"] == "high"
        assert "powershell" in result["tags"]
        assert "obfuscation" in result["tags"]

@pytest.mark.asyncio
async def test_signature_detector_no_match(network_event, mock_rule_manager):
    """Test that the signature detector returns None when no rules match."""
    with patch('core.rules.rule_loader.RuleManager', return_value=mock_rule_manager):
        detector = SignatureDetector()
        detector.rule_manager = mock_rule_manager
        
        result = await detector.detect(network_event)
        
        assert result is None

# Tests for Anomaly Detector
@pytest.mark.asyncio
async def test_anomaly_detector_auth_time(authentication_event, mock_db):
    """Test that the anomaly detector can detect unusual login times."""
    # Mock database to return login event history at different hours
    mock_db.events.find.return_value.to_list.return_value.set_result([
        {"timestamp": (datetime.utcnow() - timedelta(days=1)).replace(hour=9).isoformat()},
        {"timestamp": (datetime.utcnow() - timedelta(days=2)).replace(hour=10).isoformat()},
        {"timestamp": (datetime.utcnow() - timedelta(days=3)).replace(hour=8).isoformat()},
        {"timestamp": (datetime.utcnow() - timedelta(days=4)).replace(hour=9).isoformat()},
        {"timestamp": (datetime.utcnow() - timedelta(days=5)).replace(hour=10).isoformat()}
    ])
    
    # Set current event to unusual hour (3am)
    unusual_time_event = authentication_event.copy()
    unusual_time_event["timestamp"] = datetime.utcnow().replace(hour=3).isoformat()
    
    with patch('core.database.connection.get_database', return_value=mock_db):
        detector = AnomalyDetector()
        detector.db = mock_db
        
        result = await detector._detect_auth_anomalies(unusual_time_event)
        
        assert result is not None
        assert "Unusual Login Time" in result["name"]
        assert result["severity"] == "medium"
        assert "authentication" in result["tags"]
        assert "time-anomaly" in result["tags"]

@pytest.mark.asyncio
async def test_anomaly_detector_network_volume(network_event, mock_db):
    """Test that the anomaly detector can detect unusual network traffic volume."""
    # Mock database to return network event history with lower traffic volumes
    mock_db.events.find.return_value.to_list.return_value.set_result([
        {"data": {"bytes_sent": 10000}},
        {"data": {"bytes_sent": 12000}},
        {"data": {"bytes_sent": 8000}},
        {"data": {"bytes_sent": 15000}},
        {"data": {"bytes_sent": 11000}}
    ])
    
    # Set current event to high traffic volume
    high_volume_event = network_event.copy()
    high_volume_event["data"]["bytes_sent"] = 1500000  # Much higher than normal
    
    with patch('core.database.connection.get_database', return_value=mock_db):
        detector = AnomalyDetector()
        detector.db = mock_db
        
        result = await detector._detect_network_anomalies(high_volume_event)
        
        assert result is not None
        assert "Unusual Network Traffic Volume" in result["name"]
        assert "network" in result["tags"]
        assert "data-exfiltration" in result["tags"]

# Tests for ML Detector
@pytest.mark.asyncio
async def test_ml_detector_phishing_simulation(authentication_event):
    """Test that the ML detector can simulate phishing detection."""
    # Create an email event
    email_event = {
        "id": "56789",
        "source": "email_gateway",
        "event_type": "email",
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "sender": "suspicious@example.com",
            "recipient": "user@company.com",
            "subject": "Urgent: Verify your account credentials",
            "body": "Dear user, your account will be suspended. Click here to verify your password immediately.",
            "has_attachment": False
        }
    }
    
    # Create ML detector with simulated model
    detector = MLDetector()
    
    # Test phishing detection
    result = await detector._simulate_phishing_detection(email_event)
    
    assert result is not None
    assert "Phishing" in result["name"]
    assert result["confidence"] > 0.7  # Should detect this as phishing
    assert "T1566" in result["mitre_techniques"]
    assert "TA0001" in result["mitre_tactics"]

@pytest.mark.asyncio
async def test_ml_detector_malware_simulation(process_event):
    """Test that the ML detector can simulate malware detection."""
    # Modify process event to look like potential ransomware
    ransomware_event = process_event.copy()
    ransomware_event["data"]["command_line"] = "vssadmin delete shadows /all /quiet"
    
    # Create ML detector
    detector = MLDetector()
    
    # Test malware detection
    result = await detector._run_malware_detection(ransomware_event)
    
    assert result is not None
    assert "Ransomware" in result["name"]
    assert result["confidence"] > 0.7
    assert "T1486" in result["mitre_techniques"]
    assert "TA0040" in result["mitre_tactics"]

# Tests for Detection Engine
@pytest.mark.asyncio
async def test_detection_engine_integration(process_event, mock_rule_manager, mock_db):
    """Test that the detection engine correctly integrates all detection methods."""
    # Create mocks for individual detectors
    mock_signature_detector = MagicMock()
    mock_signature_detector.detect.return_value = asyncio.Future()
    mock_signature_detector.detect.return_value.set_result({
        "name": "Suspicious PowerShell Command",
        "description": "Detected encoded PowerShell command",
        "severity": "high",
        "detection_type": "signature",
        "tags": ["process", "powershell"],
        "mitre_techniques": ["T1059.001"],
        "mitre_tactics": ["TA0002"]
    })
    
    mock_ml_detector = MagicMock()
    mock_ml_detector.detect.return_value = asyncio.Future()
    mock_ml_detector.detect.return_value.set_result(None)  # No ML detection
    
    mock_anomaly_detector = MagicMock()
    mock_anomaly_detector.detect.return_value = asyncio.Future()
    mock_anomaly_detector.detect.return_value.set_result(None)  # No anomaly detection
    
    mock_alert_repo = MagicMock()
    mock_alert_repo.create_alert.return_value = asyncio.Future()
    mock_alert_repo.create_alert.return_value.set_result({
        "_id": "alert_123",
        "title": "Suspicious PowerShell Command",
        "severity": "high",
        "source": "endpoint_agent",
        "detection_type": "signature",
        "status": "open",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    })
    
    # Create detection engine with mocked components
    engine = DetectionEngine()
    engine.signature_detector = mock_signature_detector
    engine.ml_detector = mock_ml_detector
    engine.anomaly_detector = mock_anomaly_detector
    engine.alert_repository = mock_alert_repo
    
    # Test detection with process event
    result = await engine.detect_threats(process_event)
    
    # Verify that signature detection was used and alert was created
    mock_signature_detector.detect.assert_called_once_with(process_event)
    mock_alert_repo.create_alert.assert_called_once()
    assert result["_id"] == "alert_123"
    assert result["title"] == "Suspicious PowerShell Command"
    assert result["severity"] == "high"

# Tests for MITRE ATT&CK Integration
def test_mitre_attack_mapper():
    """Test that the MITRE ATT&CK mapper correctly maps techniques and tactics."""
    mapper = MitreAttackMapper()
    
    # Test tactic lookup
    tactic = mapper.get_tactic_by_id("TA0001")
    assert tactic is not None
    assert tactic["name"] == "Initial Access"
    
    # Test technique lookup
    technique = mapper.get_technique_by_id("T1566")
    assert technique is not None
    assert technique["name"] == "Phishing"
    
    # Test getting techniques for a tactic
    techniques = mapper.get_techniques("TA0002")  # Execution
    assert techniques is not None
    assert len(techniques) > 0
    assert any(t["id"] == "T1059" for t in techniques)  # Command and Scripting Interpreter
    
    # Test alert enrichment
    alert = {
        "_id": "alert_123",
        "title": "Phishing Attempt",
        "severity": "high",
        "details": {
            "mitre_tactics": ["TA0001"],
            "mitre_techniques": ["T1566"]
        }
    }
    
    enriched = mapper.enrich_alert(alert)
    assert "mitre" in enriched
    assert "tactics" in enriched["mitre"]
    assert "techniques" in enriched["mitre"]
    assert len(enriched["mitre"]["tactics"]) == 1
    assert enriched["mitre"]["tactics"][0]["name"] == "Initial Access"
    assert len(enriched["mitre"]["techniques"]) == 1
    assert enriched["mitre"]["techniques"][0]["name"] == "Phishing"
    
    # Test getting mitigations
    mitigations = mapper.get_mitigations(["T1566"])
    assert mitigations is not None
    assert len(mitigations) > 0
    assert any(m["name"] == "User Training" for m in mitigations)

# Tests for Risk Scoring
def test_risk_scorer_alert_risk():
    """Test that the risk scorer correctly calculates alert risk scores."""
    scorer = RiskScorer()
    
    # Test critical severity with high confidence
    critical_alert = {
        "severity": "critical",
        "detection_type": "signature",
        "details": {
            "detection": {
                "confidence": 0.95
            }
        },
        "tags": ["ransomware"],
        "created_at": datetime.utcnow().isoformat()
    }
    
    critical_score = scorer.calculate_alert_risk(critical_alert)
    assert critical_score > 90  # Should be very high
    
    # Test medium severity with medium confidence
    medium_alert = {
        "severity": "medium",
        "detection_type": "anomaly",
        "details": {
            "detection": {
                "confidence": 0.75
            }
        },
        "tags": ["network"],
        "created_at": datetime.utcnow().isoformat()
    }
    
    medium_score = scorer.calculate_alert_risk(medium_alert)
    assert 25 < medium_score < 75  # Should be moderate
    
    # Test low severity
    low_alert = {
        "severity": "low",
        "detection_type": "ml",
        "details": {
            "detection": {
                "confidence": 0.6
            }
        },
        "tags": [],
        "created_at": datetime.utcnow().isoformat()
    }
    
    low_score = scorer.calculate_alert_risk(low_alert)
    assert low_score < 25  # Should be low
    
    # Test time decay for older alerts
    old_alert = {
        "severity": "high",
        "detection_type": "signature",
        "details": {
            "detection": {
                "confidence": 0.9
            }
        },
        "tags": [],
        "created_at": (datetime.utcnow() - timedelta(days=5)).isoformat()
    }
    
    old_score = scorer.calculate_alert_risk(old_alert)
    
    # Same alert but recent
    recent_alert = old_alert.copy()
    recent_alert["created_at"] = datetime.utcnow().isoformat()
    recent_score = scorer.calculate_alert_risk(recent_alert)
    
    assert old_score < recent_score  # Older alert should have lower score due to time decay

def test_risk_scorer_asset_risk():
    """Test that the risk scorer correctly calculates asset risk scores."""
    scorer = RiskScorer()
    
    # Create test alerts for an asset
    alerts = [
        {
            "severity": "critical",
            "detection_type": "signature",
            "details": {"detection": {"confidence": 0.95}},
            "tags": ["ransomware"],
            "created_at": datetime.utcnow().isoformat()
        },
        {
            "severity": "medium",
            "detection_type": "anomaly",
            "details": {"detection": {"confidence": 0.75}},
            "tags": ["network"],
            "created_at": datetime.utcnow().isoformat()
        }
    ]
    
    # Test critical asset with alerts
    asset_risk = scorer.calculate_asset_risk("server-001", alerts, {"criticality": "critical"})
    assert asset_risk["risk_score"] > 90  # Should be very high due to critical asset + critical alert
    assert asset_risk["risk_level"] == "critical"
    assert asset_risk["alert_count"] == 2
    
    # Test low criticality asset with same alerts
    low_asset_risk = scorer.calculate_asset_risk("workstation-001", alerts, {"criticality": "low"})
    assert low_asset_risk["risk_score"] < asset_risk["risk_score"]  # Should be lower due to asset criticality
    
    # Test asset with no alerts
    no_alerts_risk = scorer.calculate_asset_risk("server-002", [], {"criticality": "high"})
    assert no_alerts_risk["risk_score"] == 0
    assert no_alerts_risk["risk_level"] == "low"
    assert no_alerts_risk["alert_count"] == 0

# Tests for Model Registry
def test_model_registry():
    """Test the model registry's ability to manage ML models."""
    # Create temp directory for test
    import tempfile
    with tempfile.TemporaryDirectory() as temp_dir:
        registry = ModelRegistry(temp_dir)
        
        # Ensure directories are created
        assert os.path.exists(os.path.join(temp_dir, "phishing"))
        assert os.path.exists(os.path.join(temp_dir, "malware"))
        assert os.path.exists(os.path.join(temp_dir, "network"))
        assert os.path.exists(os.path.join(temp_dir, "user_behavior"))
        
        # Test placeholder models
        assert os.path.exists(os.path.join(temp_dir, "phishing", "model.pkl"))
        assert os.path.exists(os.path.join(temp_dir, "phishing", "metadata.json"))
        
        # Test model loading
        model = registry.get_model("phishing")
        assert model is not None
        
        # Test metadata access
        metadata = registry.get_model_metadata("phishing")
        assert metadata is not None
        assert "name" in metadata
        assert "version" in metadata
        assert metadata.get("placeholder", False) is True
        
        # Test listing models
        models = registry.list_models()
        assert len(models) > 0
        assert any(m["name"] == "phishing_model" for m in models)
        
        # Test saving a model
        from sklearn.ensemble import RandomForestClassifier
        model = RandomForestClassifier(n_estimators=10)
        
        # Save model to registry (using sync pattern for test)
        saved = registry.save_model("test_model", model, {"accuracy": 0.95})
        
        # Check that model was saved
        assert os.path.exists(os.path.join(temp_dir, "test_model", "model.pkl"))
        assert os.path.exists(os.path.join(temp_dir, "test_model", "metadata.json"))
        
        # Test loading the saved model
        loaded_model = registry.get_model("test_model")
        assert loaded_model is not None
        assert isinstance(loaded_model, RandomForestClassifier)
        
        # Test loading metadata
        loaded_metadata = registry.get_model_metadata("test_model")
        assert loaded_metadata is not None
        assert loaded_metadata.get("metrics", {}).get("accuracy") == 0.95