"""
Flask Web Application for Bluetooth Scanner
Provides a web UI for monitoring and managing the scanner
"""

import asyncio
import json
import logging
import threading
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO, emit

from .scanner import BluetoothScanner, DetectedDevice, RecordingDeviceDatabase
from .device_logger import DeviceLogger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__,
            template_folder=str(Path(__file__).parent.parent / "templates"),
            static_folder=str(Path(__file__).parent.parent / "static"))
app.config['SECRET_KEY'] = 'bluetooth-scanner-secret-key-change-in-production'

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Global scanner and logger instances
scanner: BluetoothScanner = None
device_logger: DeviceLogger = None
scan_thread: threading.Thread = None
scan_loop: asyncio.AbstractEventLoop = None


def init_scanner():
    """Initialize scanner and logger"""
    global scanner, device_logger
    device_db = RecordingDeviceDatabase()
    scanner = BluetoothScanner(device_db)
    device_logger = DeviceLogger()

    def on_device_detected(device: DetectedDevice):
        device_logger.log_device(device)
        socketio.emit('device_detected', device.to_dict())

    def on_threat_detected(device: DetectedDevice):
        device_logger.log_threat_alert(device)
        socketio.emit('threat_alert', device.to_dict())
        logger.warning(f"THREAT ALERT: {device.matched_signature.name if device.matched_signature else 'Unknown'} detected!")

    def on_canary_status_changed(all_clear: bool):
        socketio.emit('canary_status', {'all_clear': all_clear})

    scanner.on_device_detected = on_device_detected
    scanner.on_threat_detected = on_threat_detected
    scanner.on_canary_status_changed = on_canary_status_changed


def run_async_scanner():
    """Run the async scanner in a separate thread"""
    global scan_loop
    scan_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(scan_loop)

    def callback(device):
        if device:
            socketio.emit('device_update', device.to_dict())

    try:
        scan_loop.run_until_complete(scanner.start_continuous_scan(callback))
    except asyncio.CancelledError:
        pass
    finally:
        scan_loop.close()


# Routes
@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/api/status')
def get_status():
    """Get scanner status"""
    return jsonify({
        'scanning': scanner.scanning if scanner else False,
        'device_count': len(scanner.detected_devices) if scanner else 0,
        'threat_count': len(scanner.get_threats()) if scanner else 0
    })


@app.route('/api/devices')
def get_devices():
    """Get all detected devices"""
    if not scanner:
        return jsonify({'error': 'Scanner not initialized'}), 500

    devices = [d.to_dict() for d in scanner.get_all_devices()]
    return jsonify({'devices': devices})


@app.route('/api/threats')
def get_threats():
    """Get detected threats only"""
    if not scanner:
        return jsonify({'error': 'Scanner not initialized'}), 500

    threats = [d.to_dict() for d in scanner.get_threats()]
    return jsonify({'threats': threats})


@app.route('/api/history')
def get_history():
    """Get device history from logs"""
    if not device_logger:
        return jsonify({'error': 'Logger not initialized'}), 500

    threats_only = request.args.get('threats_only', 'false').lower() == 'true'
    devices = device_logger.get_all_devices(threats_only=threats_only)
    return jsonify({'devices': devices})


@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    if not device_logger:
        return jsonify({'error': 'Logger not initialized'}), 500

    limit = request.args.get('limit', 50, type=int)
    alerts = device_logger.get_recent_alerts(limit=limit)
    return jsonify({'alerts': alerts})


@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    if not device_logger:
        return jsonify({'error': 'Logger not initialized'}), 500

    device_logger.acknowledge_alert(alert_id)
    return jsonify({'success': True})


@app.route('/api/statistics')
def get_statistics():
    """Get scanning statistics"""
    if not device_logger:
        return jsonify({'error': 'Logger not initialized'}), 500

    stats = device_logger.get_statistics()
    return jsonify(stats)


@app.route('/api/signatures')
def get_signatures():
    """Get known device signatures"""
    if not scanner:
        return jsonify({'error': 'Scanner not initialized'}), 500

    signatures = []
    for sig in scanner.device_db.signatures:
        signatures.append({
            'id': sig.id,
            'name': sig.name,
            'manufacturer': sig.manufacturer,
            'type': sig.device_type,
            'has_camera': sig.has_camera,
            'has_microphone': sig.has_microphone,
            'threat_level': sig.threat_level,
            'notes': sig.notes
        })

    return jsonify({'signatures': signatures, 'threat_levels': scanner.device_db.threat_levels})


@app.route('/api/export/csv')
def export_csv():
    """Export devices to CSV"""
    if not device_logger:
        return jsonify({'error': 'Logger not initialized'}), 500

    path = device_logger.export_to_csv()
    return jsonify({'success': True, 'path': str(path)})


@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Get current scanner settings"""
    if not scanner:
        return jsonify({'error': 'Scanner not initialized'}), 500

    return jsonify({
        'rssi_threshold': scanner.rssi_threshold,
        'notification_cooldown': scanner.notification_cooldown,
        'custom_manufacturer_ids': [f'0x{id:04X}' for id in scanner.custom_manufacturer_ids],
        'debug_mode': scanner._debug_mode,
        'canary_status': scanner.get_canary_status()
    })


@app.route('/api/settings', methods=['POST'])
def update_settings():
    """Update scanner settings"""
    if not scanner:
        return jsonify({'error': 'Scanner not initialized'}), 500

    data = request.get_json()

    if 'rssi_threshold' in data:
        scanner.rssi_threshold = int(data['rssi_threshold'])
        logger.info(f"RSSI threshold set to {scanner.rssi_threshold}")

    if 'notification_cooldown' in data:
        scanner.notification_cooldown = float(data['notification_cooldown'])
        logger.info(f"Notification cooldown set to {scanner.notification_cooldown}s")

    if 'debug_mode' in data:
        scanner.set_debug_mode(bool(data['debug_mode']))

    if 'custom_manufacturer_ids' in data:
        # Accept hex strings like "0x01AB" or integers
        ids = []
        for id_val in data['custom_manufacturer_ids']:
            if isinstance(id_val, str):
                ids.append(int(id_val, 16))
            else:
                ids.append(int(id_val))
        scanner.set_custom_manufacturer_ids(ids)

    return jsonify({'success': True, 'message': 'Settings updated'})


@app.route('/api/settings/custom_id', methods=['POST'])
def add_custom_id():
    """Add a single custom manufacturer ID"""
    if not scanner:
        return jsonify({'error': 'Scanner not initialized'}), 500

    data = request.get_json()
    id_val = data.get('manufacturer_id')

    if id_val is None:
        return jsonify({'error': 'manufacturer_id required'}), 400

    if isinstance(id_val, str):
        id_val = int(id_val, 16)
    else:
        id_val = int(id_val)

    scanner.add_custom_manufacturer_id(id_val)
    return jsonify({'success': True, 'added_id': f'0x{id_val:04X}'})


@app.route('/api/canary')
def get_canary_status():
    """Get canary mode status (all clear / threat nearby)"""
    if not scanner:
        return jsonify({'error': 'Scanner not initialized'}), 500

    return jsonify({
        'all_clear': scanner.get_canary_status(),
        'status': 'ALL CLEAR' if scanner.get_canary_status() else 'THREAT NEARBY'
    })


@app.route('/api/debug/log')
def get_debug_log():
    """Get debug log entries"""
    if not scanner:
        return jsonify({'error': 'Scanner not initialized'}), 500

    return jsonify({'log': scanner.get_debug_log()})


@app.route('/api/debug/log/export')
def export_debug_log():
    """Export debug log as text"""
    if not scanner:
        return jsonify({'error': 'Scanner not initialized'}), 500

    return scanner.export_debug_log(), 200, {'Content-Type': 'text/plain'}


@app.route('/api/debug/log/clear', methods=['POST'])
def clear_debug_log():
    """Clear debug log"""
    if not scanner:
        return jsonify({'error': 'Scanner not initialized'}), 500

    scanner.clear_debug_log()
    return jsonify({'success': True, 'message': 'Debug log cleared'})


@app.route('/api/surveillance/report')
def get_surveillance_report():
    """Get surveillance pattern analysis report"""
    if not device_logger:
        return jsonify({'error': 'Logger not initialized'}), 500

    report = device_logger.get_surveillance_report()
    return jsonify(report)


@app.route('/api/device/<address>/patterns')
def get_device_patterns(address):
    """Get pattern analysis for a specific device"""
    if not device_logger:
        return jsonify({'error': 'Logger not initialized'}), 500

    patterns = device_logger.get_device_patterns(address)
    return jsonify(patterns)


# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info("Client connected")
    emit('status', {
        'scanning': scanner.scanning if scanner else False,
        'message': 'Connected to Bluetooth Scanner'
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info("Client disconnected")


@socketio.on('start_scan')
def handle_start_scan():
    """Start scanning"""
    global scan_thread

    if not scanner:
        init_scanner()

    if scanner.scanning:
        emit('error', {'message': 'Scanner already running'})
        return

    scan_thread = threading.Thread(target=run_async_scanner, daemon=True)
    scan_thread.start()

    emit('scan_started', {'message': 'Scanning started'})
    socketio.emit('status', {'scanning': True})
    logger.info("Scanning started via WebSocket")


@socketio.on('stop_scan')
def handle_stop_scan():
    """Stop scanning"""
    if scanner:
        scanner.stop_scanning()
        emit('scan_stopped', {'message': 'Scanning stopped'})
        socketio.emit('status', {'scanning': False})
        logger.info("Scanning stopped via WebSocket")


@socketio.on('clear_devices')
def handle_clear_devices():
    """Clear detected devices"""
    if scanner:
        scanner.clear_devices()
        emit('devices_cleared', {'message': 'Devices cleared'})


@socketio.on('get_devices')
def handle_get_devices():
    """Request current device list"""
    if scanner:
        devices = [d.to_dict() for d in scanner.get_all_devices()]
        emit('device_list', {'devices': devices})


def run_server(host: str = '0.0.0.0', port: int = 5000, debug: bool = False):
    """Run the web server"""
    init_scanner()
    logger.info(f"Starting web server on {host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug)


if __name__ == '__main__':
    run_server(debug=True)
