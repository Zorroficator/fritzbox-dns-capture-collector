"""Login test only: obtain a SID with the capture user, log out immediately. No capture."""
import argparse
import errno
import http.client
import sys
import tomllib

import config
import credentials
import fritz_auth
from capture import TLS_MSG, build_query, describe_exc


def logout(factory, sid) -> None:
    try:
        c = factory(3)
        try:
            c.request("POST", "/login_sid.lua", body=build_query({"logout": 1, "sid": sid}),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            c.getresponse().read(65536)
        finally:
            c.close()
    except (OSError, ValueError, http.client.HTTPException):
        pass


def _chain(exc):
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        yield exc
        exc = exc.__cause__ or exc.__context__


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check the capture user's login (no capture is started).")
    ap.add_argument("--config", help="path to the TOML configuration file")
    ap.add_argument("--password-stdin", action="store_true",
                    help="read the password (one line) from stdin")
    ap.add_argument("--allow-insecure-credentials", action="store_true",
                    help="accept a credentials file readable by group/others")
    args = ap.parse_args(argv)
    try:
        cfg = config.load_config(args.config)
        stdin_pw = credentials.read_password_stdin() if args.password_stdin else None
        user, password = credentials.load_credentials(
            cfg, args.allow_insecure_credentials, stdin_pw,
            warn=lambda m: print("WARNING:", m, file=sys.stderr))
        pin, ca = cfg["pin_sha256"] or None, cfg["ca_file"] or None
        factory = fritz_auth.make_conn_factory(cfg["box_url"], pin, ca)
        auth = fritz_auth.FritzAuth(cfg["box_url"], user, password, cfg["timeout_seconds"], ca, pin,
                                 allow_legacy_md5=cfg["allow_legacy_md5"])
        if cfg["box_url"].lower().startswith("http://"):
            print("WARNING: box_url uses plain http: the session ID and the login travel "
                  "unencrypted; https with pin_sha256 is recommended", file=sys.stderr)
    except (OSError, ValueError, tomllib.TOMLDecodeError, credentials.CredentialsError) as exc:
        print("ERROR:", exc)
        return 1
    try:
        sid = auth.get_sid()
    except fritz_auth.LoginRejected:
        print("ERROR: login rejected (check user name and password)")
        return 1
    except Exception as exc:  # message of the box login, never password/SID
        if any(isinstance(e, (fritz_auth.CertPinError,)) or type(e).__name__ == "SSLError"
               for e in _chain(exc)):
            print("ERROR:", TLS_MSG)
            return 1
        print("ERROR: login failed (%s)" % describe_exc(exc))
        if any(isinstance(e, OSError) and e.errno == errno.EHOSTUNREACH for e in _chain(exc)):
            print("Hint: on macOS, allow 'Local Network' access for the Python executable")
        return 1
    logout(factory, sid)
    print("Login ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
