BUILTIN_INTEGRATIONS = {
    'jellyfin': {
        'name': 'Jellyfin',
        'description': 'Uses read-only session information to determine whether playback is active.',
        'default_url': 'http://jellyfin:8096',
        'auth_type': 'api_key',
        'credential_label': 'API key',
        'requested_permissions': [
            'Read active sessions',
            'Read playback state',
        ],
        'not_requested': [
            'Modify users',
            'Delete media',
            'Change server settings',
        ],
    },
    'n8n': {
        'name': 'n8n',
        'description': 'Uses the n8n API to inspect execution state when configured.',
        'default_url': 'http://n8n:5678',
        'auth_type': 'api_key',
        'credential_label': 'n8n API key',
        'requested_permissions': [
            'Read execution status',
            'Read queued/running execution metadata',
        ],
        'not_requested': [
            'Create workflows',
            'Execute workflows',
            'Modify credentials',
        ],
    },
    'generic_http': {
        'name': 'Generic HTTP',
        'description': 'Poll any JSON endpoint and map a numeric/boolean field to busy or idle.',
        'default_url': '',
        'auth_type': 'optional_bearer',
        'credential_label': 'Bearer token (optional)',
        'requested_permissions': ['HTTP GET to the configured status endpoint'],
        'not_requested': ['No write requests are issued by the detector'],
    },
}


def list_integrations():
    return [{'type': key, **value} for key, value in BUILTIN_INTEGRATIONS.items()]


def get_manifest(kind: str):
    return BUILTIN_INTEGRATIONS.get(kind)
