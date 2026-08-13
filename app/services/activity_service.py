import json
from datetime import datetime, timezone

import httpx

from app.core.config import settings
from app.core.db import get_activity_state, upsert_activity_state
from app.integrations.service import IntegrationService


class ActivityService:
    def __init__(self):
        self.integrations = IntegrationService()

    def classify(self, container: dict, classification: dict) -> dict:
        now = datetime.now(timezone.utc)

        if container['status'] != 'running':
            expected = classification['category'] == 'one-shot'
            return self._result(
                'stopped', False,
                'expected one-shot container is stopped' if expected else 'container is not running',
                now,
            )

        try:
            integration_activity = self.integrations.activity_for_container(container['name'])
        except Exception as exc:
            return self._result(
                'unknown', False, f'integration activity check failed: {exc}', now,
                detector='integration',
            )

        if integration_activity:
            return self._with_grace(container['name'], now, integration_activity)

        # Backward-compatible v0.2 Jellyfin environment configuration.
        if container['name'].lower() == 'jellyfin' and settings.jellyfin_api_key:
            return self._legacy_jellyfin(container['name'], now)

        category = classification['category']
        if category == 'dependency':
            return self._result('managed', False, 'managed dependency; update with its application stack', now)
        if category == 'kingdom-critical':
            return self._result('protected', False, 'Kingdom-critical service; manual interruption only', now)
        if category == 'security':
            return self._result('protected', False, 'security service; manual interruption policy', now)
        if category == 'infrastructure':
            return self._result('available', False, 'maintenance-window service; no activity detector required yet', now)

        return self._result('unknown', False, 'service-specific idle detector not configured yet', now)

    def _with_grace(self, name: str, now: datetime, activity: dict) -> dict:
        previous = get_activity_state(name) or {}
        last_active_at = previous.get('last_active_at')
        grace_seconds = settings.jellyfin_idle_seconds if name.lower() == 'jellyfin' else settings.idle_default_seconds

        if activity['busy']:
            last_active_at = now.isoformat()
            idle_for = 0
            state, safe = 'active', False
            reason = activity['reason']
        else:
            if last_active_at:
                try:
                    last_active = datetime.fromisoformat(last_active_at)
                    idle_for = max(0, int((now - last_active).total_seconds()))
                except ValueError:
                    idle_for = 0
            else:
                last_active_at = now.isoformat()
                idle_for = 0

            if idle_for >= grace_seconds:
                state, safe = 'idle', True
                reason = f"{activity['reason']}; idle for {idle_for // 60} min"
            else:
                state, safe = 'grace', False
                remaining = max(0, grace_seconds - idle_for)
                reason = f"{activity['reason']}; grace has {max(1, (remaining + 59) // 60)} min remaining"

        details = {**(activity.get('details') or {}), 'idle_for_seconds': idle_for}
        upsert_activity_state(
            name,
            last_active_at=last_active_at,
            last_checked_at=now.isoformat(),
            state=state,
            details_json=json.dumps(details),
        )
        return self._result(
            state, safe, reason, now,
            detector='integration', idle_for_seconds=idle_for,
            **(activity.get('details') or {}),
        )

    def _legacy_jellyfin(self, name: str, now: datetime) -> dict:
        try:
            response = httpx.get(
                f"{settings.jellyfin_url.rstrip('/')}/Sessions",
                headers={'X-Emby-Token': settings.jellyfin_api_key},
                timeout=5.0,
            )
            response.raise_for_status()
            sessions = response.json()
        except Exception as exc:
            return self._result('unknown', False, f'Jellyfin activity check failed: {exc}', now, detector='jellyfin-env')

        active = [
            s for s in sessions
            if s.get('NowPlayingItem') or s.get('PlayState', {}).get('PositionTicks', 0) > 0
        ]
        return self._with_grace(
            name, now,
            {
                'busy': bool(active),
                'reason': f'{len(active)} active playback session(s)',
                'details': {'active_sessions': len(active)},
            },
        )

    @staticmethod
    def _result(state, safe, reason, now, **extra):
        result = {
            'state': state,
            'safe_to_interrupt': safe,
            'reason': reason,
            'checked_at': now.isoformat(),
        }
        result.update(extra)
        return result
