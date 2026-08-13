from dataclasses import dataclass
from typing import Any


@dataclass
class SecuritySignal:
    source: str
    severity: str
    event_type: str
    message: str
    container: str | None = None
    raw: dict[str, Any] | None = None


# These adapters intentionally do not auto-remediate in v0.1.
# Future integrations: ClamAV, CrowdSec, Falco, Wazuh, Trivy.
class SecurityAdapterRegistry:
    names = ('clamav', 'crowdsec', 'falco', 'wazuh', 'trivy')

    def status(self):
        return [{'name': name, 'integrated': False, 'mode': 'planned'} for name in self.names]
