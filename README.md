# FRITZ!Box DNS capture collector

🇬🇧 English &nbsp;|&nbsp; 🇩🇪 [Deutsch](README_DE.md)

Per-query DNS statistics for a FRITZ!Box: this collector streams the box's own packet capture (DNS only, port 53), correlates queries with answers, stores them in SQLite and writes two JSON files (`dns_live.json`, `dns_top.json`) with the live query log, a 24 h time series and top domains / devices for today, 7 and 30 days. Pure Python standard library (Python 3.11 or newer).

It is an optional companion for the [FTrap DNS filter dashboard](https://github.com/Zorroficator/fritzbox-dns-filter-dashboard): put the JSON files into the dashboard's data directory (`out_dir`) and the dashboard can show them. The output format is documented in [docs/dns_contract.md](docs/dns_contract.md), so you can use it with any other front end as well.

> [!WARNING]
> **Undocumented endpoint.** The capture is read through `/cgi-bin/capture_notimeout`, the endpoint the box's own web interface uses for "Packet capture". It is not a supported API and may change or disappear with any firmware update. Tested with **FRITZ!OS 8.50 on a FRITZ!Box 7690**, over `http://`, with the interface `1-lan` and without `[hosts]`; HTTPS with a pin and the device names are implemented and unit-tested but not yet verified on real hardware. Treat the project as experimental.

> [!IMPORTANT]
> **Privacy.** The collector sees the DNS queries of **every device in your network** - including family members, flatmates and guests. Read [Privacy and data protection](#privacy-and-data-protection) before you run it.

> Not affiliated with AVM. FRITZ! is a trademark of its respective owner (AVM / FRITZ! GmbH); the name is used here only to describe compatibility.

## How it works

```
FRITZ!Box  ──(HTTP stream, pcap)──►  ftrap_dns.py  ──►  SQLite (24 h events, 30 days totals)
                                          │
                                          └──►  dns_live.json (every 5 s), dns_top.json (every 60 s)
```

1. Log in with a dedicated box user (`/login_sid.lua`, PBKDF2 challenge).
2. Start the capture: `GET /cgi-bin/capture_notimeout?sid=...&capture=Start&snaplen=1600&filter=udp port 53 or tcp port 53&ifaceorminor=1-lan`. The box answers with an endless pcap stream.
3. Parse Ethernet / VLAN / IPv4 / IPv6 / UDP and the DNS messages, match each query with its answer (retransmits are merged, unanswered queries expire after 10 s).
4. Classify: `allowed`, `blocked` (unspecified address or empty synthesized answer from the DNS filter), `nxdomain`, `error`, `no_answer`.
5. Write to SQLite and export the JSON files. On `SIGTERM`/`SIGINT` the capture is stopped on the box (`capture=Stop`) and the session is logged out.

Protocol details that matter if you build something similar:

- The query string must use `%20` for spaces, never `+` - otherwise the box delivers no stream.
- The box expects a `Referer` and a browser-like `User-Agent`.
- The stream is either standard pcap or AVM's "modified pcap" (magic `0xA1B2CD34`, 24-byte record header). Both are handled.
- Only DNS over UDP/TCP port 53 is captured. TCP DNS is counted but not decoded. Encrypted DNS (DoH/DoT/DoQ) does not show up.

## Requirements

- FRITZ!Box with FRITZ!OS 8.50 (tested on a 7690); other models/firmware may work or not.
- Python 3.11 or newer (CI tests 3.11 - 3.13). No third-party packages.
- A **dedicated box user** (see below).

### Box user and rights

The box lets a user start a packet capture only with the right **"FRITZ!Box settings"**. In practice this is close to an administrator. Therefore:

- Create a separate user just for this tool (System > FRITZ!Box users), do not reuse your own login.
- Disable "Access from the internet" for that user.
- Treat the credentials like administrator credentials: file mode 600, never in a repository, never on a shared machine.

If you enable the optional host names (`[hosts]`), the box must allow TR-064 access for applications (a network setting of the box whose exact location depends on the firmware), and the same user needs the right for it.

## Install and run

```sh
git clone https://github.com/Zorroficator/fritzbox-dns-capture-collector.git && cd fritzbox-dns-capture-collector
cp config.example.toml capture.toml        # edit
# credentials file: user on line 1, password on line 2 (typed into the editor,
# so the password does not end up in your shell history)
install -d -m 700 ~/.config/ftrap
install -m 600 /dev/null ~/.config/ftrap/capture_credentials
${EDITOR:-nano} ~/.config/ftrap/capture_credentials

python3 check_login.py --config capture.toml     # login test only, no capture
python3 ftrap_dns.py   --config capture.toml     # run
```

Run the tests with `python3 -m unittest discover -s tests`.

### Credentials

Lookup order:

1. `--password-stdin` - the password is read from the first line of stdin; the user name comes from `FTRAP_CAPTURE_USER` or the `user` config key.
2. Environment: `FTRAP_CAPTURE_USER` and `FTRAP_CAPTURE_PASSWORD` (both).
3. Credentials file (`credentials_file`, default `$XDG_CONFIG_HOME/ftrap/capture_credentials`): user name on line 1, password on line 2, or `username: ...` / `password: ...`. A file readable by group or others is refused unless you pass `--allow-insecure-credentials`.

The password is never logged and never part of an error message.

Optional recipe for the macOS keychain (nothing in the code depends on it; use your own service/account names):

```sh
security find-generic-password -s my-ftrap-service -a my-ftrap-user -w \
  | FTRAP_CAPTURE_USER=my-ftrap-user python3 ftrap_dns.py --config capture.toml --password-stdin
```

### HTTPS with certificate pin (recommended)

With plain `http://` the session ID and the whole DNS stream cross your LAN unencrypted. Use HTTPS with a pin of the box's certificate instead:

```sh
openssl s_client -connect fritz.box:443 </dev/null 2>/dev/null \
  | openssl x509 -outform DER | openssl dgst -sha256
```

The pin is trusted on first use: determine it over a trustworthy (for example wired) connection and compare it with the certificate shown in the box's web interface. Put the 64 hex digits into the configuration:

```toml
box_url = "https://fritz.box"
pin_sha256 = "<64 hex digits>"
```

The pin is the SHA-256 of the DER-encoded certificate and is checked after every handshake. As an alternative (or in addition) set `ca_file` to a PEM file of the box certificate; then normal verification including the host name applies. `https://` without pin or `ca_file` is refused - there is no unverified mode and no fallback to http. Redirects from the box are never followed. A new certificate (for example after a factory reset) needs a new pin.

> [!NOTE]
> The HTTPS path with a pin is implemented and unit-tested, but not yet verified against real hardware (the tests on the box so far used `http://` only). Feedback is welcome.

### Run as a service

- Linux: [examples/systemd/ftrap-dns.service](examples/systemd/ftrap-dns.service)
- macOS: [examples/launchd/org.example.ftrap-dns.plist](examples/launchd/org.example.ftrap-dns.plist)

The systemd unit runs as its own unprivileged service user with `StateDirectory=ftrap` (`/var/lib/ftrap`), `ConfigurationDirectory=ftrap` (`/etc/ftrap`), the credentials passed in with `LoadCredential=` and a hardened sandbox; its header lists the setup steps and the paths to put into `capture.toml`. The launchd agent runs as the logged-in user and reads the credentials file (mode 600). Both stop cleanly on `SIGTERM`.

### Occupying the box's packet capture

The box can run **one** packet capture at a time. While this collector runs, a manual capture in the box's web interface (System > Diagnostics > Packet capture) fails, and the collector reports `capture_busy` if someone else holds the capture. To stop the collector: send `SIGTERM` (or `systemctl stop`). If the process was killed hard (`SIGKILL`, power loss), open the box's capture page and stop the running capture there once.

If login is rejected repeatedly, the collector backs off (up to 2 hours between attempts, and at least the block time the box reports) so it does not extend the box's login lock.

## Configuration

All keys are optional; see [config.example.toml](config.example.toml).

| Key | Default | Meaning |
|---|---|---|
| `box_url` | `http://fritz.box` | box web interface |
| `pin_sha256`, `ca_file` | empty | TLS trust for `https://` (one of them is required there) |
| `allow_legacy_md5` | `false` | accept the old MD5 login of firmware older than FRITZ!OS 7.24. Off by default: over plain `http://` an attacker in the network could force the weaker login by sending a challenge without `2$`; FRITZ!OS 7.24 and newer use PBKDF2 |
| `timeout_seconds` | 10 | login / helper request timeout |
| `interface` | `1-lan` | capture interface |
| `user`, `credentials_file` | | see [Credentials](#credentials) |
| `out_dir` | `~/.local/share/ftrap/out` | where `dns_live.json` / `dns_top.json` go |
| `db_path` | `~/.local/share/ftrap/ftrap_dns.db` | SQLite file |
| `timezone` | local zone | IANA name or `UTC`; defines calendar days |
| `log_file` | stderr | rotating log file |
| `[capture]` | 150 s / 30 s | idle and connect timeouts |
| `[limits]` | 1200 / 20000 / 1024 / 6000 / 500 | `client_per_min`: stored queries per device and minute; `domains_per_day`: new domains per day; `min_free_mb`: minimum free disk MB; `events_per_min`: stored queries per minute in total; `clients_per_day`: distinct devices per day in the daily totals (further ones are summed as `(other)`); it also bounds the distinct devices tracked per minute for `client_per_min` (further ones share one counter) and the devices ranked for the 24 h view. Queries over a limit are only counted (`health.rate_limited`) |
| `[output]` | `0o700` / `0o600` | `dir_mode` (for `out_dir`, only when it is created) and `file_mode` of the JSON files; octal integer or string, see [Web server as another user](#web-server-as-another-user) |
| `[retention]` | 24 h / 30 days | individual queries / daily totals |
| `[hosts]` | disabled / 600 s | device names from the box (TR-064); `refresh_seconds`: refresh interval (default 600, minimum 60) |
| `[aliases]` | empty | your own labels by MAC or IPv4 |

Paths follow the XDG conventions (`XDG_CONFIG_HOME`, `XDG_DATA_HOME`). Directories are created with the configured mode only if they are missing; existing directories are never changed (a warning is logged if group/others have more access than `dir_mode`).

### Web server as another user

By default the output directory is created with mode 700 and the JSON files with mode 600, so only the collector's user can read them. If a web server running as a different user serves the files (for example the dashboard's `data/` directory), it gets "403 Forbidden". Choose one of:

- run the collector and the web server as the same user;
- set `file_mode = 0o640` and `dir_mode = 0o750` in `[output]`, and give the collector's user and the web server a common group (`chgrp` the directory). An existing directory is not changed by the collector, so set its group and mode yourself;
- let the collector write to its own `out_dir` and copy only `dns_*.json` to the web directory (never the database).

## Privacy and data protection

This tool records **which domains each device in your household asks for, and when**. That is sensitive behavioral data, also about people who never agreed to it.

- **Inform everyone** who uses your network - family, flatmates, guests - before you start. Depending on your country and situation, monitoring other people's traffic can be legally restricted. You are responsible for your use.
- **Keep the data in your LAN.** Do not publish `dns_live.json` / `dns_top.json` or the database on the internet. If a web server serves the output directory, restrict access to trusted devices or add authentication. See [docs/dns_contract.md](docs/dns_contract.md) for which fields are personal data.
- **Retention is limited**: individual queries are kept for `retention.events_hours` (24 h by default), daily totals for `retention.daily_days` (30 days). Lower the values if you can.
- **Host names are off by default.** Without `[hosts]`, devices appear as IP/MAC address unless you add an `[aliases]` entry yourself.
- **Logs contain only counters and error types** - never domains, host names, IPs, MACs, session IDs or passwords.
- The database files are always mode 600; the output directory and the JSON files are created with mode 700 / 600 by default (configurable, see [Web server as another user](#web-server-as-another-user)). Keep the database outside any web-served folder.
- Encrypted DNS is not visible. Collect only what you actually need.

## Optional: device names

> [!NOTE]
> Implemented and unit-tested, but not yet verified on real hardware (the tests on the box so far ran without `[hosts]`). Feedback is welcome.

```toml
[hosts]
enabled = true

[aliases]
"02:00:00:00:00:01" = "Living room TV"
"192.0.2.10"        = "Printer"
```

With `enabled = true` the collector fetches the host list via the box's TR-064 interface (port 49000, or 49443 with `https://`; same credentials, same pin) every `refresh_seconds`. A repeater that shares one MAC address between several devices is detected and shown by IP. `[aliases]` always win over host list names. If the fetch fails, the previous names are kept and `health.host_errors` increases.

## Limitations

- Only DNS traffic that passes the selected box interface (`1-lan` by default) is captured. Devices that use a different resolver bypassing the box, or encrypted DNS, are invisible.
- DNS over TCP is counted, not decoded; fragmented UDP is skipped.
- The capture uses `snaplen=1600`: larger DNS answers (for example big EDNS/DNSSEC answers above 1600 bytes per frame) are truncated; such packets may not be parsed at all and then show up as `no_answer`.
- Single process, single capture; no authentication or web server of its own.
- The endpoint and the pcap framing are undocumented; firmware updates can break the collector.

## Credits

Idea and approach inspired by [FritzHole](https://github.com/Milinator/fritzhole-ha), a Home Assistant app that reads the box's packet capture for the DNS filter. No code was copied.

## License

MIT - see [LICENSE](LICENSE).
