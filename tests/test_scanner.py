"""
Unit tests for the Bluetooth Scanner module
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.scanner import (
    BluetoothScanner,
    DetectedDevice,
    DeviceSignature,
    RecordingDeviceDatabase
)


class TestDeviceSignature:
    """Tests for DeviceSignature dataclass"""

    def test_create_signature(self):
        sig = DeviceSignature(
            id="test_device",
            name="Test Smart Glasses",
            manufacturer="Test Corp",
            device_type="smart_glasses",
            has_camera=True,
            has_microphone=True,
            threat_level="high"
        )
        assert sig.id == "test_device"
        assert sig.has_camera is True
        assert sig.threat_level == "high"

    def test_signature_defaults(self):
        sig = DeviceSignature(
            id="minimal",
            name="Minimal Device",
            manufacturer="Unknown",
            device_type="unknown",
            has_camera=False,
            has_microphone=False,
            threat_level="low"
        )
        assert sig.name_patterns == []
        assert sig.manufacturer_prefixes == []
        assert sig.ble_manufacturer_ids == []


class TestDetectedDevice:
    """Tests for DetectedDevice dataclass"""

    def test_create_detected_device(self):
        now = datetime.now()
        device = DetectedDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Test Device",
            rssi=-65,
            first_seen=now,
            last_seen=now
        )
        assert device.address == "AA:BB:CC:DD:EE:FF"
        assert device.rssi == -65
        assert device.is_potential_threat is False

    def test_to_dict(self):
        now = datetime.now()
        device = DetectedDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Test Device",
            rssi=-65,
            first_seen=now,
            last_seen=now,
            manufacturer_data={427: b'\x01\x00'}
        )
        result = device.to_dict()
        assert result["address"] == "AA:BB:CC:DD:EE:FF"
        assert result["name"] == "Test Device"
        assert "0x01AB" in result["manufacturer_ids_hex"]

    def test_estimate_distance_very_close(self):
        assert DetectedDevice._estimate_distance(-45) == "Very close (<1m)"

    def test_estimate_distance_close(self):
        assert DetectedDevice._estimate_distance(-55) == "Close (1-3m)"

    def test_estimate_distance_nearby(self):
        assert DetectedDevice._estimate_distance(-65) == "Nearby (3-7m)"

    def test_estimate_distance_medium(self):
        assert DetectedDevice._estimate_distance(-75) == "Medium (7-15m)"

    def test_estimate_distance_far(self):
        assert DetectedDevice._estimate_distance(-90) == "Far (>15m)"


class TestRecordingDeviceDatabase:
    """Tests for RecordingDeviceDatabase"""

    @pytest.fixture
    def database(self):
        return RecordingDeviceDatabase()

    def test_load_database(self, database):
        assert len(database.signatures) > 0
        assert "high" in database.threat_levels

    def test_match_by_manufacturer_id_meta(self, database):
        match = database.match_device(
            name=None,
            address="AA:BB:CC:DD:EE:FF",
            service_uuids=[],
            manufacturer_data={427: b'\x01\x00'}  # 0x01AB = Meta
        )
        assert match is not None
        assert "Meta" in match.name

    def test_match_by_manufacturer_id_snap(self, database):
        match = database.match_device(
            name=None,
            address="AA:BB:CC:DD:EE:FF",
            service_uuids=[],
            manufacturer_data={962: b'\x01\x00'}  # 0x03C2 = Snap
        )
        assert match is not None
        assert "Spectacles" in match.name or "Snap" in match.name

    def test_match_by_manufacturer_id_heycyan(self, database):
        match = database.match_device(
            name=None,
            address="AA:BB:CC:DD:EE:FF",
            service_uuids=[],
            manufacturer_data={1494: b'\x01\x00'}  # 0x05D6 = HeyCyan/Jieli
        )
        assert match is not None
        assert "HeyCyan" in match.name

    def test_match_by_mac_prefix(self, database):
        match = database.match_device(
            name=None,
            address="E4:F0:42:11:22:33",  # Meta prefix
            service_uuids=[],
            manufacturer_data={}
        )
        assert match is not None

    def test_match_by_name_pattern(self, database):
        match = database.match_device(
            name="Ray-Ban | Meta",
            address="AA:BB:CC:DD:EE:FF",
            service_uuids=[],
            manufacturer_data={}
        )
        assert match is not None
        assert match.has_camera is True

    def test_match_by_service_uuid(self, database):
        match = database.match_device(
            name=None,
            address="AA:BB:CC:DD:EE:FF",
            service_uuids=["7905fff0-b5ce-4e99-a40f-4b1e122d00d0"],  # HeyCyan
            manufacturer_data={}
        )
        assert match is not None

    def test_no_match_for_unknown_device(self, database):
        match = database.match_device(
            name="Unknown Device",
            address="11:22:33:44:55:66",
            service_uuids=[],
            manufacturer_data={76: b'\x01\x00'}  # Apple - not a threat
        )
        assert match is None


class TestBluetoothScanner:
    """Tests for BluetoothScanner"""

    @pytest.fixture
    def scanner(self):
        return BluetoothScanner()

    def test_init_defaults(self, scanner):
        assert scanner.rssi_threshold == -75
        assert scanner.notification_cooldown == 10.0
        assert scanner.custom_manufacturer_ids == []
        assert scanner._canary_status is True

    def test_set_custom_manufacturer_ids(self, scanner):
        scanner.set_custom_manufacturer_ids([0x1234, 0x5678])
        assert 0x1234 in scanner.custom_manufacturer_ids
        assert 0x5678 in scanner.custom_manufacturer_ids

    def test_add_custom_manufacturer_id(self, scanner):
        scanner.add_custom_manufacturer_id(0xABCD)
        assert 0xABCD in scanner.custom_manufacturer_ids

    def test_canary_status_default(self, scanner):
        assert scanner.get_canary_status() is True

    def test_notification_cooldown(self, scanner):
        scanner.notification_cooldown = 5.0
        assert scanner._should_alert("AA:BB:CC:DD:EE:FF") is True
        scanner._record_alert("AA:BB:CC:DD:EE:FF")
        assert scanner._should_alert("AA:BB:CC:DD:EE:FF") is False

    def test_debug_mode(self, scanner):
        scanner.set_debug_mode(True)
        assert scanner._debug_mode is True
        scanner.set_debug_mode(False)
        assert scanner._debug_mode is False

    def test_debug_log(self, scanner):
        scanner.set_debug_mode(True)
        scanner._log_debug("TEST", "Test message", {"key": "value"})
        log = scanner.get_debug_log()
        assert len(log) == 1
        assert log[0]["type"] == "TEST"

    def test_export_debug_log(self, scanner):
        scanner._log_debug("TEST", "Test message")
        export = scanner.export_debug_log()
        assert "VisionFinder Debug Log" in export
        assert "TEST" in export

    def test_clear_debug_log(self, scanner):
        scanner._log_debug("TEST", "Test message")
        scanner.clear_debug_log()
        assert len(scanner.get_debug_log()) == 0

    def test_check_for_threat_with_known_device(self, scanner):
        now = datetime.now()
        device = DetectedDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Ray-Ban | Meta",
            rssi=-50,
            first_seen=now,
            last_seen=now,
            manufacturer_data={427: b'\x01\x00'}
        )
        result = scanner._check_for_threat(device, [])
        assert result is True
        assert device.is_potential_threat is True
        assert device.matched_signature is not None

    def test_check_for_threat_with_custom_id(self, scanner):
        scanner.add_custom_manufacturer_id(0x9999)
        now = datetime.now()
        device = DetectedDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Unknown",
            rssi=-50,
            first_seen=now,
            last_seen=now,
            manufacturer_data={0x9999: b'\x01\x00'}
        )
        result = scanner._check_for_threat(device, [])
        assert result is True
        assert device.is_potential_threat is True

    def test_check_for_threat_respects_rssi_threshold(self, scanner):
        now = datetime.now()
        device = DetectedDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Ray-Ban | Meta",
            rssi=-90,  # Too far
            first_seen=now,
            last_seen=now,
            manufacturer_data={427: b'\x01\x00'}
        )
        result = scanner._check_for_threat(device, [])
        assert result is False  # No alert due to distance
        assert device.is_potential_threat is True  # Still marked as threat

    def test_get_simulated_devices(self, scanner):
        devices = scanner._get_simulated_devices()
        assert len(devices) > 0
        threats = [d for d in devices if d.is_potential_threat]
        assert len(threats) > 0

    def test_get_threats(self, scanner):
        scanner._get_simulated_devices()
        threats = scanner.get_threats()
        assert len(threats) > 0
        for threat in threats:
            assert threat.is_potential_threat is True

    def test_clear_devices(self, scanner):
        scanner._get_simulated_devices()
        assert len(scanner.detected_devices) > 0
        scanner.clear_devices()
        assert len(scanner.detected_devices) == 0


class TestThreatDetectionPriority:
    """Tests to verify detection priority order"""

    @pytest.fixture
    def scanner(self):
        return BluetoothScanner()

    def test_manufacturer_id_takes_priority(self, scanner):
        """Manufacturer ID should match even if name doesn't match"""
        now = datetime.now()
        device = DetectedDevice(
            address="11:22:33:44:55:66",  # Unknown MAC
            name="Random Name",  # Unknown name
            rssi=-50,
            first_seen=now,
            last_seen=now,
            manufacturer_data={427: b'\x01\x00'}  # Meta ID
        )
        scanner._check_for_threat(device, [])
        assert device.is_potential_threat is True
        assert "Meta" in device.matched_signature.name

    def test_mac_prefix_matches_without_manufacturer_id(self, scanner):
        """MAC prefix should match when no manufacturer ID"""
        now = datetime.now()
        device = DetectedDevice(
            address="D4:D9:19:AA:BB:CC",  # GoPro MAC prefix
            name="Unknown",
            rssi=-50,
            first_seen=now,
            last_seen=now,
            manufacturer_data={}
        )
        scanner._check_for_threat(device, [])
        assert device.is_potential_threat is True
        assert "GoPro" in device.matched_signature.name
