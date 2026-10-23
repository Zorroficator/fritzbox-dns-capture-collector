"""Credentials of the capture user: environment, credentials file, or stdin password.

Lookup order:
  1. ``--password-stdin`` supplies the password only; the user name then comes
     from FTRAP_CAPTURE_USER or the ``user`` config key.
  2. FTRAP_CAPTURE_USER + FTRAP_CAPTURE_PASSWORD (both set).
  3. The credentials file (mode 600 enforced unless explicitly overridden).

Nothing here ever logs or puts a password into an exception message.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

ENV_USER = "FTRAP_CAPTURE_USER"
ENV_PASSWORD = "FTRAP_CAPTURE_PASSWORD"


class CredentialsError(Exception):
    """Credentials are missing, unreadable or stored insecurely."""


def read_password_stdin(stream=None) -> str:
    """Read one line from stdin (without the line ending)."""
    try:
        line = (stream or sys.stdin).readline()
    except (OSError, ValueError):
        raise CredentialsError("cannot read password from stdin") from None
    pw = line.rstrip("\r\n")
    if not pw:
        raise CredentialsError("password from stdin is empty")
    return pw


def parse_credentials(text: str) -> tuple[str, str]:
    """Accept 'user line + password line' or 'username:/login:/user: ...' + 'password: ...'."""
    lines = text.splitlines()
    keyed: dict[str, str] = {}
    for line in lines:
        k, sep, v = line.partition(":")
        if sep and k.strip().lower() in ("username", "login", "user", "password"):
            keyed[k.strip().lower()] = v.strip()
    user = next((keyed[k] for k in ("username", "login", "user") if keyed.get(k)), "")
    if user and keyed.get("password"):
        return user, keyed["password"]
    if len(lines) < 2 or not lines[0].strip() or not lines[1]:
        raise CredentialsError("credentials file needs the user name on line 1 and the "
                               "password on line 2 (or 'username: ...' / 'password: ...')")
    return lines[0].strip(), lines[1].rstrip("\r\n")


def _read_file(path: Path, allow_insecure: bool, warn) -> str:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            msg = f"credentials file {path} has mode {mode:o}; restrict it with chmod 600"
            if not allow_insecure:
                raise CredentialsError(msg + " (or pass --allow-insecure-credentials)")
            warn(msg)
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CredentialsError(f"cannot read credentials file {path}: {exc.strerror}") from exc


def load_credentials(cfg: dict, allow_insecure: bool = False, stdin_password: str | None = None,
                     environ=None, warn=lambda msg: None) -> tuple[str, str]:
    """Return (user, password) for the capture user. Raises CredentialsError."""
    env = os.environ if environ is None else environ
    if stdin_password is not None:
        user = env.get(ENV_USER) or str(cfg.get("user") or "")
        if not user:
            raise CredentialsError(f"--password-stdin needs {ENV_USER} or the 'user' config key")
        return user, stdin_password
    user, password = env.get(ENV_USER), env.get(ENV_PASSWORD)
    if user and password:
        return user, password
    cred = Path(str(cfg["credentials_file"])).expanduser()
    return parse_credentials(_read_file(cred, allow_insecure, warn))
