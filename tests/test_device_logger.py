"""
Unit tests for the Device Logger module
"""

import pytest
import tempfile
import os
from datetime import datetime
from pathlib import Path
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.scanner import DetectedDevice, DeviceSignature
from src.device_logger import DeviceLogger


class TestDeviceLogger:
    """Tests for DeviceLogger"""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def logger(self, temp_dir):
        return DeviceLogger(log_dir=temp_dir)

    @pytest.fixture
    def sample_device(self):
        now = datetime.now()
        return DetectedDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Test Device",
            rssi=-65,
            first_seen=now,
            last_seen=now,
            manufacturer_data={427: b'\x01\x00'}
        )

    @pytest.fixture
    def threat_device(self):
        now = datetime.now()
        device = DetectedDevice(
            address="11:22:33:44:55:66",
            name="Ray-Ban | Meta",
            rssi=-50,
            first_seen=now,
            last_seen=now,
            manufacturer_data={427: b'\x01\x00'}
        )
        device.is_potential_threat = True
        device.threat_level = "high"
        device.matched_signature = DeviceSignature(
            id="meta_glasses",
            name="Meta Smart Glasses",
            manufacturer="Meta",
            device_type="smart_glasses",
            has_camera=True,
            has_microphone=True,
            threat_level="high"
        )
        return device

    def test_init_creates_database(self, logger, temp_dir):
        assert (temp_dir / "device_history.db").exists()

    def test_log_device(self, logger, sample_device):
        logger.log_device(sample_device)
        devices = logger.get_all_devices()
        assert len(devices) == 1
        assert devices[0]['address'] == "AA:BB:CC:DD:EE:FF"

    def test_log_device_updates_times_seen(self, logger, sample_device):
        logger.log_device(sample_device)
        logger.log_device(sample_device)
        logger.log_device(sample_device)
        devices = logger.get_all_devices()
        assert devices[0]['times_seen'] == 3

    def test_log_threat_alert(self, logger, threat_device):
        logger.log_threat_alert(threat_device)
        alerts = logger.get_recent_alerts()
        assert len(alerts) == 1
        assert alerts[0]['device_address'] == "11:22:33:44:55:66"
        assert alerts[0]['threat_level'] == "high"

    def test_get_all_devices_threats_only(self, logger, sample_device, threat_device):
        logger.log_device(sample_device)
        logger.log_device(threat_device)

        all_devices = logger.get_all_devices(threats_only=False)
        assert len(all_devices) == 2

        threats = logger.get_all_devices(threats_only=True)
        assert len(threats) == 1
        assert threats[0]['is_threat'] == 1

    def test_acknowledge_alert(self, logger, threat_device):
        logger.log_threat_alert(threat_device)
        alerts = logger.get_recent_alerts()
        alert_id = alerts[0]['id']

        logger.acknowledge_alert(alert_id)

        alerts = logger.get_recent_alerts()
        assert alerts[0]['acknowledged'] == 1

    def test_get_statistics(self, logger, sample_device, threat_device):
        logger.log_device(sample_device)
        logger.log_device(threat_device)
        logger.log_threat_alert(threat_device)

        stats = logger.get_statistics()
        assert stats['total_devices'] == 2
        assert stats['threat_devices'] == 1
        assert stats['total_alerts'] == 1

    def test_export_to_csv(self, logger, sample_device, temp_dir):
        logger.log_device(sample_device)
        path = logger.export_to_csv()
        assert path.exists()
        with open(path, 'r') as f:
            content = f.read()
            assert "AA:BB:CC:DD:EE:FF" in content

    def test_get_device_history(self, logger, sample_device):
        logger.log_device(sample_device)
        logger.log_device(sample_device)

        history = logger.get_device_history("AA:BB:CC:DD:EE:FF")
        assert len(history) == 2

    def test_clear_old_detections(self, logger, sample_device):
        logger.log_device(sample_device)
        deleted = logger.clear_old_detections(days=0)
        assert deleted >= 0


class TestDwellTracking:
    """Tests for dwell session tracking"""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def logger(self, temp_dir):
        return DeviceLogger(log_dir=temp_dir)

    @pytest.fixture
    def threat_device(self):
        now = datetime.now()
        device = DetectedDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Threat Device",
            rssi=-50,
            first_seen=now,
            last_seen=now
        )
        device.is_potential_threat = True
        device.threat_level = "high"
        device.matched_signature = DeviceSignature(
            id="test",
            name="Test Threat",
            manufacturer="Test",
            device_type="smart_glasses",
            has_camera=True,
            has_microphone=True,
            threat_level="high"
        )
        return device

    def test_start_dwell_session(self, logger, threat_device):
        session_id = logger.start_dwell_session(threat_device)
        assert session_id is not None
        assert session_id > 0

    def test_end_dwell_session(self, logger, threat_device):
        logger.start_dwell_session(threat_device)
        dwell_seconds = logger.end_dwell_session(threat_device.address)
        assert dwell_seconds >= 0

    def test_get_device_patterns(self, logger, threat_device):
        logger.start_dwell_session(threat_device)
        logger.end_dwell_session(threat_device.address)

        patterns = logger.get_device_patterns(threat_device.address)
        assert 'hourly_heatmap' in patterns
        assert 'daily_heatmap' in patterns
        assert 'total_sessions' in patterns

    def test_surveillance_report(self, logger, threat_device):
        logger.log_device(threat_device)
        logger.start_dwell_session(threat_device)
        logger.end_dwell_session(threat_device.address)

        report = logger.get_surveillance_report()
        assert 'total_threats' in report
        assert 'threats' in report


class TestSignatureExport:
    """Tests for signature export functionality"""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def logger(self, temp_dir):
        return DeviceLogger(log_dir=temp_dir)

    @pytest.fixture
    def threat_device(self):
        now = datetime.now()
        device = DetectedDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Threat Device",
            rssi=-50,
            first_seen=now,
            last_seen=now,
            manufacturer_data={427: b'\x01\x00'}
        )
        device.is_potential_threat = True
        device.threat_level = "high"
        device.matched_signature = DeviceSignature(
            id="test",
            name="Test Threat",
            manufacturer="Test",
            device_type="smart_glasses",
            has_camera=True,
            has_microphone=True,
            threat_level="high"
        )
        return device

    def test_export_signatures(self, logger, threat_device):
        logger.log_device(threat_device)
        path = logger.export_signatures()
        assert path.exists()

        import json
        with open(path, 'r') as f:
            data = json.load(f)
            assert 'signatures' in data
            assert 'version' in data
