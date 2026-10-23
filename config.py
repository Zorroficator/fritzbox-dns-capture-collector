"""Configuration (tomllib) and helpers for private files (default mode 600/700)."""
from __future__ import annotations

import datetime
import logging
import os
import stat
import tempfile
import tomllib
import urllib.parse
from pathlib import Path

import fritz_auth

log = logging.getLogger("ftrap_dns")
_warned_dirs: set = set()


def _xdg(var: str, fallback: tuple[str, ...]) -> Path:
    value = os.environ.get(var)
    if value and Path(value).expanduser().is_absolute():
        return Path(value).expanduser()
    return Path.home().joinpath(*fallback)


def default_credentials_path() -> Path:
    """$XDG_CONFIG_HOME/ftrap/capture_credentials, else ~/.config/ftrap/capture_credentials."""
    return _xdg("XDG_CONFIG_HOME", (".config",)) / "ftrap" / "capture_credentials"


def default_data_dir() -> Path:
    """$XDG_DATA_HOME/ftrap, else ~/.local/share/ftrap."""
    return _xdg("XDG_DATA_HOME", (".local", "share")) / "ftrap"


def _defaults() -> dict:
    data = default_data_dir()
    return {
        "box_url": "http://fritz.box",
        "ca_file": "",
        "pin_sha256": "",
        "allow_legacy_md5": False,
        "timeout_seconds": 10,
        "interface": "1-lan",
        "user": "",
        "credentials_file": str(default_credentials_path()),
        "out_dir": str(data / "out"),
        "db_path": str(data / "ftrap_dns.db"),
        "timezone": "",              # empty = local system time zone
        "capture": {"idle_timeout_s": 150, "connect_timeout_s": 30},
        "limits": {"client_per_min": 1200, "domains_per_day": 20000, "min_free_mb": 1024,
                   "events_per_min": 6000, "clients_per_day": 500},
        "output": {"dir_mode": 0o700, "file_mode": 0o600},
        "retention": {"events_hours": 24, "daily_days": 30},
        "log_file": "",              # empty = log to stderr
        "hosts": {"enabled": False, "refresh_seconds": 600},
        "aliases": {},               # "MAC or IPv4" -> label
    }


def load_config(path=None) -> dict:
    """Defaults, overlaid with the TOML file at ``path`` (must exist if given)."""
    cfg = _defaults()
    if path:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
        for key, value in data.items():
            if isinstance(value, dict) and isinstance(cfg.get(key), dict):
                cfg[key].update(value)
            else:
                cfg[key] = value
    for key in ("ca_file", "credentials_file", "out_dir", "db_path", "log_file"):
        if cfg.get(key):
            cfg[key] = str(Path(str(cfg[key])).expanduser())
    cfg["box_url"] = str(cfg["box_url"]).rstrip("/")
    cfg["timeout_seconds"] = float(cfg["timeout_seconds"])
    scheme = urllib.parse.urlsplit(cfg["box_url"]).scheme.lower()
    cfg["pin_sha256"] = fritz_auth.check_transport(scheme, cfg["pin_sha256"], cfg["ca_file"])
    if not isinstance(cfg["allow_legacy_md5"], bool):
        raise ValueError("allow_legacy_md5 must be true or false")
    resolve_timezone(cfg["timezone"])   # validate early
    out = cfg["output"]
    out["dir_mode"] = parse_mode(out["dir_mode"], "output.dir_mode")
    out["file_mode"] = parse_mode(out["file_mode"], "output.file_mode", is_file=True)
    cfg["hosts"]["enabled"] = bool(cfg["hosts"]["enabled"])
    cfg["hosts"]["refresh_seconds"] = max(60, int(cfg["hosts"]["refresh_seconds"]))
    aliases = cfg["aliases"]
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in aliases.items()):
        raise ValueError("[aliases] must map strings to strings")
    cfg["aliases"] = {k.strip().lower(): v for k, v in aliases.items() if v}
    return cfg


def resolve_timezone(name: str):
    """tzinfo for ``name``; None (= local system time zone) when empty."""
    if not name:
        return None
    if name == "UTC":                # no tz database needed
        return datetime.timezone.utc
    import zoneinfo
    try:
        return zoneinfo.ZoneInfo(str(name))
    except (zoneinfo.ZoneInfoNotFoundError, ValueError, OSError):
        raise ValueError(f"unknown time zone {name!r}") from None


def parse_mode(value, name="mode", is_file=False) -> int:
    """File mode from a TOML integer (``0o640``) or an octal string (``"0640"``); validated."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an octal mode such as 0o640")
    if isinstance(value, str):
        try:
            mode = int(value.strip(), 8)
        except ValueError:
            raise ValueError(f"{name} must be an octal mode such as \"0640\"") from None
    elif isinstance(value, int):
        mode = value
    else:
        raise ValueError(f"{name} must be an integer or an octal string")
    if not 0 <= mode <= 0o777:
        raise ValueError(f"{name} must only use the permission bits (0o000 - 0o777)")
    if is_file and mode & 0o111:
        raise ValueError(f"{name} must not have execute bits")
    if mode & 0o600 != 0o600:
        raise ValueError(f"{name} must give the owner read and write access")
    if not is_file and mode & 0o700 != 0o700:
        raise ValueError(f"{name} must give the owner full access")
    return mode


def ensure_private_dir(path, mode=0o700) -> Path:
    """Create ``path`` with ``mode`` if it is missing; never change an existing directory.

    An existing directory belongs to the user (it may be a web server's data
    directory or even $HOME), so it is only checked: group/other access beyond
    ``mode`` is reported once."""
    p = Path(path)
    if p.is_dir():
        extra = stat.S_IMODE(p.stat().st_mode) & 0o077 & ~mode
        if extra and str(p) not in _warned_dirs:
            _warned_dirs.add(str(p))
            log.warning("directory %s is accessible to group/others beyond mode %04o; "
                        "leaving it unchanged", p, mode)
        return p
    missing = []
    for part in (p, *p.parents):    # every path component this call creates, leaf first
        if part.exists():
            break
        missing.append(part)
    for part in reversed(missing):
        try:
            part.mkdir(mode=0o700)
        except FileExistsError:
            continue            # created concurrently: not ours, leave it alone
        os.chmod(part, mode)    # explicit: the process umask (077) would otherwise decide
    return p


def open_private(path, flags=os.O_WRONLY | os.O_CREAT | os.O_APPEND):
    """File descriptor with mode 600 (also if the file already exists).

    A symbolic link in place of the file is refused (O_NOFOLLOW), so a link
    cannot redirect writes or the chmod to another file."""
    fd = os.open(path, flags | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    return fd


def write_private(path, data, file_mode=0o600, dir_mode=0o700) -> None:
    """Write atomically (tmp + replace) with ``file_mode``; a missing directory gets ``dir_mode``."""
    p = Path(path)
    ensure_private_dir(p.parent, dir_mode)
    raw = data.encode("utf-8") if isinstance(data, str) else data
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=p.name + ".")
    try:
        os.fchmod(fd, file_mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
