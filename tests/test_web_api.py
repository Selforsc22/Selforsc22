"""
Unit tests for the Web API endpoints
"""

import pytest
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.web_app import app, init_scanner, scanner


@pytest.fixture
def client():
    app.config['TESTING'] = True
    init_scanner()
    with app.test_client() as client:
        yield client


class TestStatusEndpoints:
    """Tests for status-related endpoints"""

    def test_get_status(self, client):
        response = client.get('/api/status')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'scanning' in data
        assert 'device_count' in data
        assert 'threat_count' in data

    def test_get_devices(self, client):
        response = client.get('/api/devices')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'devices' in data

    def test_get_threats(self, client):
        response = client.get('/api/threats')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'threats' in data

    def test_get_signatures(self, client):
        response = client.get('/api/signatures')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'signatures' in data
        assert 'threat_levels' in data
        assert len(data['signatures']) > 0


class TestSettingsEndpoints:
    """Tests for settings-related endpoints"""

    def test_get_settings(self, client):
        response = client.get('/api/settings')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'rssi_threshold' in data
        assert 'notification_cooldown' in data
        assert 'custom_manufacturer_ids' in data
        assert 'debug_mode' in data
        assert 'canary_status' in data

    def test_update_rssi_threshold(self, client):
        response = client.post(
            '/api/settings',
            data=json.dumps({'rssi_threshold': -80}),
            content_type='application/json'
        )
        assert response.status_code == 200

        response = client.get('/api/settings')
        data = json.loads(response.data)
        assert data['rssi_threshold'] == -80

    def test_update_notification_cooldown(self, client):
        response = client.post(
            '/api/settings',
            data=json.dumps({'notification_cooldown': 15.0}),
            content_type='application/json'
        )
        assert response.status_code == 200

        response = client.get('/api/settings')
        data = json.loads(response.data)
        assert data['notification_cooldown'] == 15.0

    def test_update_debug_mode(self, client):
        response = client.post(
            '/api/settings',
            data=json.dumps({'debug_mode': True}),
            content_type='application/json'
        )
        assert response.status_code == 200

        response = client.get('/api/settings')
        data = json.loads(response.data)
        assert data['debug_mode'] is True

    def test_add_custom_manufacturer_id_hex(self, client):
        response = client.post(
            '/api/settings/custom_id',
            data=json.dumps({'manufacturer_id': '0x1234'}),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['added_id'] == '0x1234'

    def test_add_custom_manufacturer_id_int(self, client):
        response = client.post(
            '/api/settings/custom_id',
            data=json.dumps({'manufacturer_id': 5678}),
            content_type='application/json'
        )
        assert response.status_code == 200

    def test_add_custom_manufacturer_id_missing(self, client):
        response = client.post(
            '/api/settings/custom_id',
            data=json.dumps({}),
            content_type='application/json'
        )
        assert response.status_code == 400


class TestCanaryEndpoint:
    """Tests for canary mode endpoint"""

    def test_get_canary_status(self, client):
        response = client.get('/api/canary')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'all_clear' in data
        assert 'status' in data
        assert data['status'] in ['ALL CLEAR', 'THREAT NEARBY']


class TestDebugEndpoints:
    """Tests for debug-related endpoints"""

    def test_get_debug_log(self, client):
        response = client.get('/api/debug/log')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'log' in data

    def test_export_debug_log(self, client):
        response = client.get('/api/debug/log/export')
        assert response.status_code == 200
        assert response.content_type == 'text/plain; charset=utf-8'
        assert b'VisionFinder Debug Log' in response.data

    def test_clear_debug_log(self, client):
        response = client.post('/api/debug/log/clear')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True


class TestHistoryEndpoints:
    """Tests for history and alerts endpoints"""

    def test_get_history(self, client):
        response = client.get('/api/history')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'devices' in data

    def test_get_history_threats_only(self, client):
        response = client.get('/api/history?threats_only=true')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'devices' in data

    def test_get_alerts(self, client):
        response = client.get('/api/alerts')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'alerts' in data

    def test_get_alerts_with_limit(self, client):
        response = client.get('/api/alerts?limit=10')
        assert response.status_code == 200

    def test_get_statistics(self, client):
        response = client.get('/api/statistics')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'total_devices' in data
        assert 'threat_devices' in data


class TestSurveillanceEndpoints:
    """Tests for surveillance analysis endpoints"""

    def test_get_surveillance_report(self, client):
        response = client.get('/api/surveillance/report')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'total_threats' in data
        assert 'threats' in data

    def test_get_device_patterns(self, client):
        response = client.get('/api/device/AA:BB:CC:DD:EE:FF/patterns')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'hourly_heatmap' in data
        assert 'daily_heatmap' in data


class TestExportEndpoints:
    """Tests for export functionality"""

    def test_export_csv(self, client):
        response = client.get('/api/export/csv')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert 'path' in data
