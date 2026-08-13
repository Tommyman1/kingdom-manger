DATABASE_TOKENS = (
    'postgres', 'mysql', 'mariadb', 'redis', 'valkey', 'mongo', 'rabbit', 'memcached', 'database', '-db', '_db'
)
CRITICAL_NAMES = {
    'portainer', 'proxy-manager', 'kingdom-manager', 'kingdom-socket-proxy', 'pihole'
}
SECURITY_NAMES = {
    'clamav', 'cowrie', 'opencanary', 'filewatcher', 'crowdsec', 'falco', 'wazuh'
}
INFRA_NAMES = {
    'homepage', 'grafana', 'prometheus', 'netdata', 'netalertx', 'uptime-kuma', 'alloy', 'loki', 'dozzle'
}
USER_ACTIVITY_NAMES = {
    'jellyfin', 'navidrome', 'kavita', 'audiobookshelf', 'romm', 'suwayomi', 'openbooks', 'stirling-pdf',
    'trilium', 'vaultwarden', 'cook-book', 'kingdom-forge', 'kingdom-transmute', 'seafile'
}
JOB_ACTIVITY_NAMES = {'n8n', 'n8n-runner', 'paperless', 'immich_server', 'immich_machine_learning', 'arm'}
ONE_SHOT_HINTS = ('createbuckets', 'init', 'migration', 'migrate', 'setup')


class ClassificationService:
    def classify(self, container: dict) -> dict:
        name = container['name'].lower()
        image = (container.get('image') or '').lower()
        labels = container.get('labels') or {}
        project = labels.get('com.docker.compose.project')
        service = labels.get('com.docker.compose.service')

        if any(hint in name for hint in ONE_SHOT_HINTS):
            category, policy = 'one-shot', 'expected-stop'
        elif name in CRITICAL_NAMES:
            category, policy = 'kingdom-critical', 'manual'
        elif name in SECURITY_NAMES:
            category, policy = 'security', 'manual'
        elif any(token in name or token in image for token in DATABASE_TOKENS):
            category, policy = 'dependency', 'stack-controlled'
        elif name in INFRA_NAMES:
            category, policy = 'infrastructure', 'maintenance-window'
        elif name in JOB_ACTIVITY_NAMES or name.startswith('immich_'):
            category, policy = 'job-activity', 'service-aware'
        elif name in USER_ACTIVITY_NAMES or name.startswith('stoat-'):
            category, policy = 'user-activity', 'service-aware'
        else:
            category, policy = 'application', 'service-aware'

        return {
            'category': category,
            'update_policy': policy,
            'compose_project': project,
            'compose_service': service,
            'stack': project or self._infer_stack(name),
        }

    @staticmethod
    def _infer_stack(name: str):
        for prefix in ('immich_', 'paperless-', 'romm-', 'seafile-', 'stoat-'):
            if name.startswith(prefix):
                return prefix.rstrip('_-')
        return None
