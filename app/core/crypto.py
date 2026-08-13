from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from app.core.config import settings


def _key_path() -> Path:
    return Path(settings.integration_key_path)


def get_or_create_key() -> bytes:
    if settings.integration_secret_key:
        return settings.integration_secret_key.encode()

    path = _key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_bytes().strip()

    key = Fernet.generate_key()
    path.write_bytes(key + b'\n')
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key


def encrypt_secret(value: str) -> str:
    if not value:
        return ''
    return Fernet(get_or_create_key()).encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    if not value:
        return ''
    try:
        return Fernet(get_or_create_key()).decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError('Unable to decrypt integration credential; check the Kingdom Manager encryption key') from exc


def mask_secret(value: str) -> str:
    if not value:
        return 'not configured'
    if len(value) <= 6:
        return '••••••'
    return f'{value[:2]}••••••{value[-2:]}'
