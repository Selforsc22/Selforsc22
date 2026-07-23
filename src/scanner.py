"""
Bluetooth Device Scanner Module
Scans for nearby BLE devices and identifies potential recording devices
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False
    BLEDevice = None
    AdvertisementData = None

logger = logging.getLogger(__name__)


@dataclass
class DeviceSignature:
    """Represents a known recording device signature"""
    id: str
    name: str
    manufacturer: str
    device_type: str
    has_camera: bool
    has_microphone: bool
    threat_level: str
    name_patterns: list[str] = field(default_factory=list)
    manufacturer_prefixes: list[str] = field(default_factory=list)
    service_uuids: list[str] = field(default_factory=list)
    ble_manufacturer_ids: list[int] = field(default_factory=list)  # BLE company IDs (e.g., 0x0969 for Woan/Meta)
    notes: str = ""


@dataclass
class DetectedDevice:
    """Represents a detected Bluetooth device"""
    address: str
    name: Optional[str]
    rssi: int
    first_seen: datetime
    last_seen: datetime
    manufacturer_data: dict = field(default_factory=dict)
    service_uuids: list[str] = field(default_factory=list)
    matched_signature: Optional[DeviceSignature] = None
    is_potential_threat: bool = False
    threat_level: str = "unknown"

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        # Format manufacturer IDs for display (e.g., "0x0969")
        mfr_ids_hex = [f"0x{k:04X}" for k in self.manufacturer_data.keys()] if self.manufacturer_data else []

        return {
            "address": self.address,
            "name": self.name or "Unknown",
            "rssi": self.rssi,
            "rssi_distance": self._estimate_distance(self.rssi),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "manufacturer_data": {str(k): v.hex() if isinstance(v, bytes) else v
                                  for k, v in self.manufacturer_data.items()},
            "manufacturer_ids_hex": mfr_ids_hex,
            "service_uuids": self.service_uuids,
            "is_potential_threat": self.is_potential_threat,
            "threat_level": self.threat_level,
            "matched_device": self.matched_signature.name if self.matched_signature else None,
            "matched_device_type": self.matched_signature.device_type if self.matched_signature else None,
            "has_camera": self.matched_signature.has_camera if self.matched_signature else None,
            "has_microphone": self.matched_signature.has_microphone if self.matched_signature else None,
        }

    @staticmethod
    def _estimate_distance(rssi: int) -> str:
        """Estimate distance based on RSSI (rough approximation)"""
        if rssi >= -50:
            return "Very close (<1m)"
        elif rssi >= -60:
            return "Close (1-3m)"
        elif rssi >= -70:
            return "Nearby (3-7m)"
        elif rssi >= -80:
            return "Medium (7-15m)"
        else:
            return "Far (>15m)"


class RecordingDeviceDatabase:
    """Manages the database of known recording device signatures"""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            db_path = Path(__file__).parent.parent / "data" / "recording_devices.json"
        self.db_path = db_path
        self.signatures: list[DeviceSignature] = []
        self.threat_levels: dict = {}
        self.load_database()

    def load_database(self):
        """Load the device signatures database"""
        try:
            with open(self.db_path, 'r') as f:
                data = json.load(f)

            self.threat_levels = data.get("threat_levels", {})

            for device in data.get("devices", []):
                identifiers = device.get("identifiers", {})
                signature = DeviceSignature(
                    id=device["id"],
                    name=device["name"],
                    manufacturer=device["manufacturer"],
                    device_type=device["type"],
                    has_camera=device.get("has_camera", False),
                    has_microphone=device.get("has_microphone", False),
                    threat_level=device.get("threat_level", "unknown"),
                    name_patterns=identifiers.get("name_patterns", []),
                    manufacturer_prefixes=identifiers.get("manufacturer_prefixes", []),
                    service_uuids=identifiers.get("service_uuids", []),
                    ble_manufacturer_ids=identifiers.get("ble_manufacturer_ids", []),
                    notes=device.get("notes", "")
                )
                self.signatures.append(signature)

            logger.info(f"Loaded {len(self.signatures)} device signatures from database")
        except FileNotFoundError:
            logger.warning(f"Device database not found at {self.db_path}")
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing device database: {e}")

    def match_device(self, name: Optional[str], address: str,
                     service_uuids: list[str],
                     manufacturer_data: Optional[dict] = None) -> Optional[DeviceSignature]:
        """
        Try to match a detected device against known signatures
        Returns the matching signature or None

        Detection priority:
        1. BLE Manufacturer ID (most reliable - e.g., 0x0969 for Meta/Woan glasses)
        2. MAC address prefix (OUI)
        3. Device name patterns
        4. Service UUIDs
        """
        address_upper = address.upper()
        manufacturer_data = manufacturer_data or {}

        for sig in self.signatures:
            # Check BLE manufacturer ID (most reliable method)
            # This catches Meta glasses even when unpaired (appear as "Woan")
            if sig.ble_manufacturer_ids and manufacturer_data:
                for mfr_id in manufacturer_data.keys():
                    if mfr_id in sig.ble_manufacturer_ids:
                        logger.debug(f"Matched device {address} by BLE manufacturer ID 0x{mfr_id:04X}")
                        return sig

            # Check MAC address prefix (OUI)
            for prefix in sig.manufacturer_prefixes:
                if address_upper.startswith(prefix.upper()):
                    logger.debug(f"Matched device {address} by MAC prefix {prefix}")
                    return sig

            # Check device name patterns
            if name:
                name_lower = name.lower()
                for pattern in sig.name_patterns:
                    if pattern.lower() in name_lower:
                        logger.debug(f"Matched device '{name}' by name pattern '{pattern}'")
                        return sig

            # Check service UUIDs
            for uuid in service_uuids:
                if uuid.lower() in [s.lower() for s in sig.service_uuids]:
                    logger.debug(f"Matched device {address} by service UUID {uuid}")
                    return sig

        return None


class BluetoothScanner:
    """Main Bluetooth scanner class"""

    # Default RSSI threshold for threat alerts (-75 dBm ~ 10-15m outdoors, 3-10m indoors)
    DEFAULT_RSSI_THRESHOLD = -75
    # Default notification cooldown in seconds (don't re-alert same device within this time)
    DEFAULT_NOTIFICATION_COOLDOWN = 10.0

    def __init__(self, device_db: Optional[RecordingDeviceDatabase] = None,
                 rssi_threshold: int = DEFAULT_RSSI_THRESHOLD,
                 notification_cooldown: float = DEFAULT_NOTIFICATION_COOLDOWN,
                 custom_manufacturer_ids: Optional[list[int]] = None):
        self.device_db = device_db or RecordingDeviceDatabase()
        self.detected_devices: dict[str, DetectedDevice] = {}
        self.scanning = False
        self._scan_task: Optional[asyncio.Task] = None
        self.on_device_detected: Optional[Callable[[DetectedDevice], None]] = None
        self.on_threat_detected: Optional[Callable[[DetectedDevice], None]] = None
        self.on_canary_status_changed: Optional[Callable[[bool], None]] = None  # Canary mode callback
        self.rssi_threshold = rssi_threshold  # Only alert for devices stronger than this
        self.notification_cooldown = notification_cooldown  # Seconds between alerts for same device
        self.custom_manufacturer_ids = custom_manufacturer_ids or []  # User-defined manufacturer IDs
        self._last_alert_times: dict[str, datetime] = {}  # Track last alert time per device
        self._canary_status = True  # True = all clear, False = threat nearby
        self._debug_mode = False  # Show all scan details
        self._debug_log: list[dict] = []  # Store debug entries

        if not BLEAK_AVAILABLE:
            logger.warning("Bleak library not available - running in simulation mode")

    def set_custom_manufacturer_ids(self, ids: list[int]):
        """Set custom manufacturer IDs to detect (user-defined threats)"""
        self.custom_manufacturer_ids = ids
        logger.info(f"Custom manufacturer IDs set: {[f'0x{id:04X}' for id in ids]}")

    def add_custom_manufacturer_id(self, manufacturer_id: int):
        """Add a single custom manufacturer ID"""
        if manufacturer_id not in self.custom_manufacturer_ids:
            self.custom_manufacturer_ids.append(manufacturer_id)
            logger.info(f"Added custom manufacturer ID: 0x{manufacturer_id:04X}")

    def set_debug_mode(self, enabled: bool):
        """Enable/disable debug mode for verbose logging"""
        self._debug_mode = enabled
        logger.info(f"Debug mode {'enabled' if enabled else 'disabled'}")

    def get_debug_log(self) -> list[dict]:
        """Get debug log entries"""
        return self._debug_log.copy()

    def export_debug_log(self) -> str:
        """Export debug log as formatted text"""
        lines = ["VisionFinder Debug Log", "=" * 50, ""]
        for entry in self._debug_log:
            lines.append(f"[{entry['timestamp']}] {entry['type']}: {entry['message']}")
            if entry.get('details'):
                for key, value in entry['details'].items():
                    lines.append(f"  {key}: {value}")
            lines.append("")
        return "\n".join(lines)

    def clear_debug_log(self):
        """Clear the debug log"""
        self._debug_log.clear()

    def _log_debug(self, log_type: str, message: str, details: Optional[dict] = None):
        """Add entry to debug log"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": log_type,
            "message": message,
            "details": details or {}
        }
        self._debug_log.append(entry)
        # Keep log size reasonable
        if len(self._debug_log) > 1000:
            self._debug_log = self._debug_log[-500:]

    def get_canary_status(self) -> bool:
        """Get canary mode status (True = all clear, False = threat detected)"""
        return self._canary_status

    def _update_canary_status(self, threat_nearby: bool):
        """Update canary status and notify if changed"""
        new_status = not threat_nearby
        if new_status != self._canary_status:
            self._canary_status = new_status
            if self.on_canary_status_changed:
                self.on_canary_status_changed(new_status)
            logger.info(f"Canary status: {'ALL CLEAR' if new_status else 'THREAT NEARBY'}")

    def _should_alert(self, device_address: str) -> bool:
        """Check if we should alert for this device (respects cooldown)"""
        now = datetime.now()
        last_alert = self._last_alert_times.get(device_address)
        if last_alert is None:
            return True
        elapsed = (now - last_alert).total_seconds()
        return elapsed >= self.notification_cooldown

    def _record_alert(self, device_address: str):
        """Record that we alerted for this device"""
        self._last_alert_times[device_address] = datetime.now()

    def _process_device(self, device: 'BLEDevice', advertisement_data: 'AdvertisementData'):
        """Process a detected BLE device"""
        now = datetime.now()
        address = device.address

        # Extract service UUIDs
        service_uuids = []
        if advertisement_data and advertisement_data.service_uuids:
            service_uuids = list(advertisement_data.service_uuids)

        # Extract manufacturer data
        manufacturer_data = {}
        if advertisement_data and advertisement_data.manufacturer_data:
            manufacturer_data = dict(advertisement_data.manufacturer_data)

        # Check if we've seen this device before
        if address in self.detected_devices:
            existing = self.detected_devices[address]
            existing.last_seen = now
            old_rssi = existing.rssi
            existing.rssi = advertisement_data.rssi if advertisement_data else -100

            # Re-check for threats if name changed or device moved into alert range
            if device.name and device.name != existing.name:
                existing.name = device.name
                if self._check_for_threat(existing, service_uuids):
                    if self.on_threat_detected:
                        self.on_threat_detected(existing)

            # Alert if previously-detected threat moved into range
            elif (existing.is_potential_threat and
                  old_rssi < self.rssi_threshold and
                  existing.rssi >= self.rssi_threshold):
                logger.warning(f"Threat moved into range: {existing.matched_signature.name} (rssi: {old_rssi} -> {existing.rssi})")
                if self.on_threat_detected:
                    self.on_threat_detected(existing)
        else:
            # New device
            detected = DetectedDevice(
                address=address,
                name=device.name,
                rssi=advertisement_data.rssi if advertisement_data else -100,
                first_seen=now,
                last_seen=now,
                manufacturer_data=manufacturer_data,
                service_uuids=service_uuids,
            )

            threat_in_range = self._check_for_threat(detected, service_uuids)
            self.detected_devices[address] = detected

            if self.on_device_detected:
                self.on_device_detected(detected)

            if threat_in_range and self.on_threat_detected:
                self.on_threat_detected(detected)

    def _check_for_threat(self, device: DetectedDevice, service_uuids: list[str]) -> bool:
        """
        Check if a device matches known recording device signatures.
        Returns True if a threat was detected within RSSI threshold and cooldown allows.
        """
        # First check custom manufacturer IDs (user-defined)
        custom_match = False
        if self.custom_manufacturer_ids and device.manufacturer_data:
            for mfr_id in device.manufacturer_data.keys():
                if mfr_id in self.custom_manufacturer_ids:
                    custom_match = True
                    device.is_potential_threat = True
                    device.threat_level = "high"
                    # Create a synthetic signature for custom matches
                    device.matched_signature = DeviceSignature(
                        id="custom_device",
                        name=f"Custom Device (0x{mfr_id:04X})",
                        manufacturer="User-defined",
                        device_type="unknown",
                        has_camera=True,
                        has_microphone=True,
                        threat_level="high",
                        notes="Matched by user-defined manufacturer ID"
                    )
                    logger.info(f"Matched custom manufacturer ID 0x{mfr_id:04X} for {device.address}")
                    break

        # Check against known device database
        if not custom_match:
            match = self.device_db.match_device(
                device.name,
                device.address,
                service_uuids,
                device.manufacturer_data
            )

            if match:
                device.matched_signature = match
                device.is_potential_threat = True
                device.threat_level = match.threat_level

        # Log debug info if enabled
        if self._debug_mode:
            mfr_ids = [f"0x{k:04X}" for k in device.manufacturer_data.keys()] if device.manufacturer_data else []
            self._log_debug("SCAN", f"Device: {device.name or 'Unknown'}", {
                "address": device.address,
                "rssi": device.rssi,
                "manufacturer_ids": mfr_ids,
                "service_uuids": service_uuids,
                "is_threat": device.is_potential_threat
            })

        if device.is_potential_threat:
            mfr_ids = [f"0x{k:04X}" for k in device.manufacturer_data.keys()] if device.manufacturer_data else []
            distance = device._estimate_distance(device.rssi)
            match_name = device.matched_signature.name if device.matched_signature else "Unknown"

            # Update canary status
            self._update_canary_status(threat_nearby=True)

            # Only trigger high-priority alert if within RSSI threshold
            if device.rssi >= self.rssi_threshold:
                # Check notification cooldown
                if self._should_alert(device.address):
                    self._record_alert(device.address)
                    logger.warning(
                        f"THREAT DETECTED: {match_name} at {device.address} "
                        f"(name='{device.name}', mfr_ids={mfr_ids}, rssi={device.rssi}dBm, distance={distance})"
                    )
                    self._log_debug("THREAT", f"Alert triggered: {match_name}", {
                        "address": device.address,
                        "rssi": device.rssi,
                        "distance": distance
                    })
                    return True
                else:
                    logger.debug(f"Threat {device.address} within cooldown period, skipping alert")
                    return False
            else:
                logger.info(
                    f"Threat detected but distant: {match_name} at {device.address} "
                    f"(rssi={device.rssi}dBm < threshold={self.rssi_threshold}dBm)"
                )
                return False

        return False

    async def scan_once(self, timeout: float = 10.0) -> list[DetectedDevice]:
        """Perform a single scan and return detected devices"""
        if not BLEAK_AVAILABLE:
            logger.warning("Bleak not available - returning simulated data")
            return self._get_simulated_devices()

        logger.info(f"Starting BLE scan (timeout: {timeout}s)")

        try:
            devices = await BleakScanner.discover(
                timeout=timeout,
                return_adv=True
            )

            for device, adv_data in devices.values():
                self._process_device(device, adv_data)

            logger.info(f"Scan complete. Found {len(self.detected_devices)} devices")
            return list(self.detected_devices.values())

        except Exception as e:
            logger.error(f"Error during scan: {e}")
            raise

    async def start_continuous_scan(self, callback: Optional[Callable] = None):
        """Start continuous background scanning"""
        if self.scanning:
            logger.warning("Scanner already running")
            return

        self.scanning = True

        if not BLEAK_AVAILABLE:
            logger.warning("Bleak not available - running in simulation mode")
            self._scan_task = asyncio.create_task(self._simulated_continuous_scan(callback))
            return

        def detection_callback(device: BLEDevice, advertisement_data: AdvertisementData):
            self._process_device(device, advertisement_data)
            if callback:
                callback(self.detected_devices.get(device.address))

        try:
            scanner = BleakScanner(detection_callback=detection_callback)
            await scanner.start()
            logger.info("Continuous scanning started")

            while self.scanning:
                await asyncio.sleep(1)

            await scanner.stop()
            logger.info("Continuous scanning stopped")

        except Exception as e:
            logger.error(f"Error in continuous scan: {e}")
            self.scanning = False
            raise

    async def _simulated_continuous_scan(self, callback: Optional[Callable] = None):
        """Simulated continuous scanning for testing without Bluetooth hardware"""
        import random

        # Simulated devices: (address, name, rssi, manufacturer_data)
        # 0x01AB (427) = Meta Platforms, Inc.
        # 0x03C2 (962) = Snap Inc.
        # 0x05D6 (1494) = Zhuhai Jieli Technology (HeyCyan)
        # 0x004C (76) = Apple
        # 0x0075 (117) = Samsung
        simulated_devices = [
            ("AA:BB:CC:DD:EE:01", "iPhone", -65, {76: b'\x10\x05\x03'}),
            ("AA:BB:CC:DD:EE:02", "Galaxy Watch", -70, {117: b'\x42\x04\x01'}),
            ("AA:BB:CC:DD:EE:03", "AirPods Pro", -55, {76: b'\x07\x19\x01'}),
            ("E4:F0:42:11:22:33", "Ray-Ban | Meta", -45, {427: b'\x01\x00\x00'}),  # Meta glasses (0x01AB)
            ("AA:BB:CC:DD:EE:08", "Spectacles", -42, {962: b'\x01\x00\x00'}),  # Snap Spectacles (0x03C2)
            ("AA:BB:CC:DD:EE:04", "Fitbit", -80, {}),
            ("AA:BB:CC:DD:EE:05", "Unknown Device", -90, {}),
            ("AA:BB:CC:DD:EE:06", "HeyCyan", -60, {1494: b'\x01\x00\x00'}),  # HeyCyan SDK glasses (0x05D6)
            ("AA:BB:CC:DD:EE:07", "MacBook Pro", -75, {76: b'\x10\x06\x11'}),
            ("D4:D9:19:AA:BB:CC", "GoPro HERO12", -50, {654: b'\x01\x00\x00'}),  # GoPro (0x028E)
            ("AA:BB:CC:DD:EE:09", "Oakley Meta", -48, {427: b'\x02\x00\x00'}),  # Oakley Meta glasses (0x01AB)
        ]

        logger.info("Starting simulated continuous scan")

        while self.scanning:
            # Randomly "discover" devices
            device_info = random.choice(simulated_devices)
            address, name, base_rssi, mfr_data = device_info

            now = datetime.now()
            rssi = base_rssi + random.randint(-10, 10)

            if address in self.detected_devices:
                self.detected_devices[address].last_seen = now
                self.detected_devices[address].rssi = rssi
            else:
                detected = DetectedDevice(
                    address=address,
                    name=name,
                    rssi=rssi,
                    first_seen=now,
                    last_seen=now,
                    manufacturer_data=mfr_data,
                )
                self._check_for_threat(detected, [])
                self.detected_devices[address] = detected

                if self.on_device_detected:
                    self.on_device_detected(detected)

                if detected.is_potential_threat and self.on_threat_detected:
                    self.on_threat_detected(detected)

            if callback:
                callback(self.detected_devices[address])

            await asyncio.sleep(random.uniform(0.5, 2.0))

    def _get_simulated_devices(self) -> list[DetectedDevice]:
        """Return simulated devices for testing"""
        now = datetime.now()
        # 0x01AB (427) = Meta Platforms, Inc.
        # 0x03C2 (962) = Snap Inc.
        # 0x05D6 (1494) = Zhuhai Jieli Technology (HeyCyan)
        simulated = [
            DetectedDevice(
                address="AA:BB:CC:DD:EE:01",
                name="iPhone 15 Pro",
                rssi=-65,
                first_seen=now,
                last_seen=now,
                manufacturer_data={76: b'\x10\x05\x03'},  # Apple
            ),
            DetectedDevice(
                address="E4:F0:42:11:22:33",
                name="Ray-Ban | Meta",
                rssi=-45,
                first_seen=now,
                last_seen=now,
                manufacturer_data={427: b'\x01\x00\x00'},  # Meta (0x01AB)
            ),
            DetectedDevice(
                address="AA:BB:CC:DD:EE:08",
                name="HeyCyan Glasses",
                rssi=-50,
                first_seen=now,
                last_seen=now,
                manufacturer_data={1494: b'\x01\x00\x00'},  # HeyCyan (0x05D6)
            ),
        ]

        for device in simulated:
            self._check_for_threat(device, [])
            self.detected_devices[device.address] = device

        return simulated

    def stop_scanning(self):
        """Stop continuous scanning"""
        self.scanning = False
        if self._scan_task:
            self._scan_task.cancel()

    def get_all_devices(self) -> list[DetectedDevice]:
        """Get all detected devices"""
        return list(self.detected_devices.values())

    def get_threats(self) -> list[DetectedDevice]:
        """Get only devices identified as potential threats"""
        return [d for d in self.detected_devices.values() if d.is_potential_threat]

    def clear_devices(self):
        """Clear the detected devices list"""
        self.detected_devices.clear()


# Simple test function
async def test_scanner():
    """Test the scanner functionality"""
    logging.basicConfig(level=logging.DEBUG)

    scanner = BluetoothScanner()

    def on_threat(device: DetectedDevice):
        print(f"ALERT! Recording device detected: {device.name} ({device.address})")

    scanner.on_threat_detected = on_threat

    print("Starting scan...")
    devices = await scanner.scan_once(timeout=5.0)

    print(f"\nFound {len(devices)} devices:")
    for device in devices:
        threat_indicator = " [THREAT]" if device.is_potential_threat else ""
        print(f"  {device.name or 'Unknown'} ({device.address}) RSSI: {device.rssi}{threat_indicator}")

    threats = scanner.get_threats()
    if threats:
        print(f"\n{len(threats)} potential recording device(s) detected!")
        for threat in threats:
            print(f"  - {threat.matched_signature.name}: {threat.address}")


if __name__ == "__main__":
    asyncio.run(test_scanner())
