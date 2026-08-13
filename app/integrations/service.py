import json
from datetime import datetime, timezone
from typing import Any

import httpx

from app.core.crypto import decrypt_secret, encrypt_secret, mask_secret
from app.core.db import (
    delete_integration,
    get_integration,
    list_integrations_db,
    upsert_integration,
)
from app.integrations.registry import get_manifest


class IntegrationService:
    def list(self):
        rows = []
        for row in list_integrations_db():
            data = dict(row)
            decrypted = decrypt_secret(data.get('credential_encrypted') or '') if data.get('credential_encrypted') else ''
            data['credential_masked'] = mask_secret(decrypted)
            data.pop('credential_encrypted', None)
            data['settings'] = json.loads(data.pop('settings_json') or '{}')
            rows.append(data)
        return rows

    def get(self, integration_id: int):
        row = get_integration(integration_id)
        if not row:
            return None
        data = dict(row)
        credential = decrypt_secret(data.get('credential_encrypted') or '') if data.get('credential_encrypted') else ''
        data['credential'] = credential
        data['credential_masked'] = mask_secret(credential)
        data['settings'] = json.loads(data.pop('settings_json') or '{}')
        return data

    def save(self, *, integration_id: int | None, name: str, kind: str, container_name: str, base_url: str,
             permission_mode: str, credential: str, settings: dict[str, Any], enabled: bool = True):
        if permission_mode not in {'OBSERVE', 'MONITOR', 'MANAGE', 'PROTECTED'}:
            raise ValueError('invalid permission mode')
        if kind not in {'jellyfin', 'n8n', 'generic_http'}:
            raise ValueError('unsupported integration type')

        existing = self.get(integration_id) if integration_id else None
        if not credential and existing:
            credential = existing.get('credential') or ''

        encrypted = encrypt_secret(credential)
        return upsert_integration(
            integration_id=integration_id,
            name=name.strip() or get_manifest(kind)['name'],
            kind=kind,
            container_name=container_name.strip(),
            base_url=base_url.rstrip('/'),
            permission_mode=permission_mode,
            credential_encrypted=encrypted,
            settings_json=json.dumps(settings),
            enabled=1 if enabled else 0,
        )

    def delete(self, integration_id: int):
        delete_integration(integration_id)

    def test(self, integration_id: int):
        item = self.get(integration_id)
        if not item:
            return {'ok': False, 'message': 'integration not found'}
        return self._test_item(item)

    def test_values(self, *, kind: str, base_url: str, credential: str, settings: dict[str, Any]):
        item = {
            'kind': kind,
            'base_url': base_url.rstrip('/'),
            'credential': credential,
            'settings': settings,
        }
        return self._test_item(item)

    def _test_item(self, item: dict):
        try:
            if item['kind'] == 'jellyfin':
                return self._test_jellyfin(item)
            if item['kind'] == 'n8n':
                return self._test_n8n(item)
            if item['kind'] == 'generic_http':
                return self._test_generic(item)
            return {'ok': False, 'message': 'unsupported integration type'}
        except Exception as exc:
            return {'ok': False, 'message': str(exc)}

    @staticmethod
    def _test_jellyfin(item: dict):
        response = httpx.get(
            f"{item['base_url']}/Sessions",
            headers={'X-Emby-Token': item.get('credential') or ''},
            timeout=5.0,
        )
        response.raise_for_status()
        sessions = response.json()
        count = len(sessions) if isinstance(sessions, list) else 0
        return {'ok': True, 'message': f'Connected to Jellyfin; {count} session record(s) visible'}

    @staticmethod
    def _test_n8n(item: dict):
        headers = {}
        if item.get('credential'):
            headers['X-N8N-API-KEY'] = item['credential']
        response = httpx.get(f"{item['base_url']}/api/v1/executions?limit=1", headers=headers, timeout=5.0)
        response.raise_for_status()
        return {'ok': True, 'message': 'Connected to n8n API'}

    @staticmethod
    def _test_generic(item: dict):
        cfg = item.get('settings') or {}
        path = cfg.get('path') or ''
        headers = {}
        if item.get('credential'):
            headers['Authorization'] = f"Bearer {item['credential']}"
        response = httpx.get(f"{item['base_url']}{path}", headers=headers, timeout=5.0)
        response.raise_for_status()
        data = response.json()
        field = cfg.get('field')
        observed = _resolve_field(data, field) if field else data
        return {'ok': True, 'message': f'Connected; observed {field or "response"}={observed!r}'}

    def activity_for_container(self, container_name: str):
        candidates = [i for i in self.list() if i.get('enabled') and (i.get('container_name') == container_name or i.get('name', '').lower() == container_name.lower())]
        if not candidates:
            return None
        full = self.get(candidates[0]['id'])
        if not full or full['permission_mode'] in {'OBSERVE', 'PROTECTED'}:
            return None
        if full['kind'] == 'jellyfin':
            return self._jellyfin_activity(full)
        if full['kind'] == 'n8n':
            return self._n8n_activity(full)
        if full['kind'] == 'generic_http':
            return self._generic_activity(full)
        return None

    @staticmethod
    def _jellyfin_activity(item: dict):
        response = httpx.get(
            f"{item['base_url']}/Sessions",
            headers={'X-Emby-Token': item.get('credential') or ''},
            timeout=5.0,
        )
        response.raise_for_status()
        sessions = response.json()
        active = [s for s in sessions if s.get('NowPlayingItem') or s.get('PlayState', {}).get('PositionTicks', 0) > 0]
        return {'busy': bool(active), 'reason': f'{len(active)} active playback session(s)', 'details': {'active_sessions': len(active)}}

    @staticmethod
    def _n8n_activity(item: dict):
        headers = {'X-N8N-API-KEY': item.get('credential') or ''}
        response = httpx.get(f"{item['base_url']}/api/v1/executions?status=running&limit=100", headers=headers, timeout=5.0)
        response.raise_for_status()
        payload = response.json()
        data = payload.get('data', []) if isinstance(payload, dict) else []
        return {'busy': bool(data), 'reason': f'{len(data)} running execution(s)', 'details': {'running_executions': len(data)}}

    @staticmethod
    def _generic_activity(item: dict):
        cfg = item.get('settings') or {}
        path = cfg.get('path') or ''
        headers = {}
        if item.get('credential'):
            headers['Authorization'] = f"Bearer {item['credential']}"
        response = httpx.get(f"{item['base_url']}{path}", headers=headers, timeout=5.0)
        response.raise_for_status()
        data = response.json()
        observed = _resolve_field(data, cfg.get('field'))
        operator = cfg.get('operator', 'gt')
        expected = cfg.get('value', 0)
        busy = _compare(observed, operator, expected)
        return {'busy': busy, 'reason': f"{cfg.get('field')}={observed!r} ({operator} {expected!r})", 'details': {'observed': observed}}


def _resolve_field(data: Any, path: str | None):
    if not path:
        return data
    current = data
    for part in path.split('.'):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            raise ValueError(f'cannot resolve field {path}')
    return current


def _coerce(value):
    if isinstance(value, str):
        lower = value.lower()
        if lower in {'true', 'false'}:
            return lower == 'true'
        try:
            return float(value) if '.' in value else int(value)
        except ValueError:
            return value
    return value


def _compare(observed, operator: str, expected):
    observed = _coerce(observed)
    expected = _coerce(expected)
    if operator == 'eq':
        return observed == expected
    if operator == 'ne':
        return observed != expected
    if operator == 'gt':
        return observed > expected
    if operator == 'gte':
        return observed >= expected
    if operator == 'lt':
        return observed < expected
    if operator == 'lte':
        return observed <= expected
    raise ValueError('unsupported comparison operator')
