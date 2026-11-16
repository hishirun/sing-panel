"""Content-addressed public assets; private responses must never use this cache policy."""
from hashlib import sha256
from pathlib import Path
from urllib.parse import quote


STATIC_DIR = Path(__file__).parent / 'static'


def _asset_path(name: str) -> Path:
    name = str(name).removeprefix('/static/')
    path = Path(name)
    if path.is_absolute() or not name or any(part in {'.', '..'} for part in name.split('/')):
        raise ValueError('Invalid asset path')
    candidate = (STATIC_DIR / path).resolve()
    if not candidate.is_relative_to(STATIC_DIR.resolve()):
        raise ValueError('Invalid asset path')
    return candidate



def asset_version(name: str) -> str:
    path = _asset_path(name)
    # Filesystem timestamp precision differs across hosts. Content remains the
    # authority even when a same-size replacement preserves modification time.
    return sha256(path.read_bytes()).hexdigest()[:20]


def asset_url(name: str) -> str:
    name = str(name).removeprefix('/static/')
    return '/static/' + quote(name, safe='/') + '?v=' + asset_version(name)


def asset_is_versioned(path: str, version: str | None) -> bool:
    if not version:
        return False
    try:
        return version == asset_version(path)
    except (OSError, ValueError):
        return False
