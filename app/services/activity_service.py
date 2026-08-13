from datetime import datetime, timezone


class ActivityService:
    """v0.1 activity framework.

    Service-specific adapters (Jellyfin, n8n, Immich, etc.) plug in here later.
    Until then, Kingdom Manager reports activity as unknown instead of guessing
    from CPU usage and accidentally declaring a service idle.
    """

    def classify(self, container: dict) -> dict:
        if container['status'] != 'running':
            return {'state': 'stopped', 'safe_to_interrupt': False, 'reason': 'container is not running'}
        return {
            'state': 'unknown',
            'safe_to_interrupt': False,
            'reason': 'no service-specific idle detector configured',
            'checked_at': datetime.now(timezone.utc).isoformat(),
        }
