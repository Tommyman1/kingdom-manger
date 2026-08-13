import docker
from docker.errors import DockerException
from app.core.config import settings


class DockerService:
    def __init__(self):
        self.client = docker.DockerClient(base_url=settings.docker_host, timeout=8)

    def ping(self) -> bool:
        try:
            return bool(self.client.ping())
        except DockerException:
            return False

    def containers(self):
        rows = []
        for container in self.client.containers.list(all=True):
            attrs = container.attrs
            state = attrs.get('State', {})
            config = attrs.get('Config', {})
            image = config.get('Image') or ','.join(container.image.tags)
            health = state.get('Health', {}).get('Status', 'none')
            rows.append({
                'id': container.short_id,
                'name': container.name,
                'status': state.get('Status', container.status),
                'health': health,
                'image': image,
                'created': attrs.get('Created'),
                'restart_count': attrs.get('RestartCount', 0),
                'networks': sorted((attrs.get('NetworkSettings', {}).get('Networks') or {}).keys()),
                'labels': config.get('Labels') or {},
            })
        return sorted(rows, key=lambda item: item['name'].lower())

    def inspect(self, name: str):
        c = self.client.containers.get(name)
        attrs = c.attrs
        cfg = attrs.get('Config', {})
        host = attrs.get('HostConfig', {})
        return {
            'id': c.id,
            'name': c.name,
            'image': cfg.get('Image'),
            'status': attrs.get('State', {}).get('Status'),
            'health': attrs.get('State', {}).get('Health', {}).get('Status', 'none'),
            'env': cfg.get('Env') or [],
            'labels': cfg.get('Labels') or {},
            'mounts': attrs.get('Mounts') or [],
            'networks': attrs.get('NetworkSettings', {}).get('Networks') or {},
            'restart_policy': host.get('RestartPolicy') or {},
            'port_bindings': host.get('PortBindings') or {},
            'privileged': host.get('Privileged', False),
            'cap_add': host.get('CapAdd') or [],
            'cap_drop': host.get('CapDrop') or [],
            'read_only_rootfs': host.get('ReadonlyRootfs', False),
        }
