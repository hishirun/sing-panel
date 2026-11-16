"""Content-addressed public assets; private responses must never use this cache policy."""
from functools import lru_cache
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


@lru_cache(maxsize=256)
def _digest(path: str, mtime_ns: int, ctime_ns: int, size: int) -> str:
    return sha256(Path(path).read_bytes()).hexdigest()[:20]


def asset_version(name: str) -> str:
    path = _asset_path(name)
    stat = path.stat()
    return _digest(str(path), stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size)


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
