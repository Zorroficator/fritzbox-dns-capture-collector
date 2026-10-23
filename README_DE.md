# FRITZ!Box-DNS-Mitschnitt-Sammler

🇬🇧 [English](README.md) &nbsp;|&nbsp; 🇩🇪 Deutsch

DNS-Statistik pro Anfrage für eine FRITZ!Box: Der Sammler liest den Paketmitschnitt der Box (nur DNS, Port 53) als Datenstrom, ordnet Anfragen und Antworten zu, speichert sie in SQLite und schreibt zwei JSON-Dateien (`dns_live.json`, `dns_top.json`) mit dem Live-Protokoll, einer 24-Stunden-Zeitreihe und den häufigsten Domains und Geräten für heute, 7 und 30 Tage. Reine Python-Standardbibliothek (Python 3.11 oder neuer).

Er ist eine optionale Ergänzung zum [FTrap-DNS-Filter-Dashboard](https://github.com/Zorroficator/fritzbox-dns-filter-dashboard): Die JSON-Dateien kommen in das Datenverzeichnis des Dashboards (`out_dir`), dann kann das Dashboard sie anzeigen. Das Ausgabeformat steht in [docs/dns_contract.md](docs/dns_contract.md) (englisch), sodass sich auch eine andere Oberfläche anbinden lässt.

> [!WARNING]
> **Undokumentierter Endpunkt.** Der Mitschnitt kommt über `/cgi-bin/capture_notimeout`, den Endpunkt, den auch die Weboberfläche der Box für „Paketmitschnitt“ verwendet. Das ist keine unterstützte Schnittstelle und kann mit jedem Firmware-Update ändern oder wegfallen. Getestet mit **FRITZ!OS 8.50 auf einer FRITZ!Box 7690**, über `http://`, mit der Schnittstelle `1-lan` und ohne `[hosts]`; HTTPS mit Pin und die Gerätenamen sind umgesetzt und per Unit-Test geprüft, aber noch nicht an echter Hardware verifiziert. Das Projekt ist experimentell.

> [!IMPORTANT]
> **Datenschutz.** Der Sammler sieht die DNS-Anfragen **aller Geräte in Ihrem Netzwerk** – auch von Familienmitgliedern, Mitbewohnern und Gästen. Lesen Sie vor dem Start den Abschnitt [Datenschutz](#datenschutz).

> Nicht mit AVM verbunden. FRITZ! ist eine Marke des jeweiligen Inhabers (AVM / FRITZ! GmbH); der Name dient hier nur der Beschreibung der Kompatibilität.

## Funktionsweise

```
FRITZ!Box  ──(HTTP-Strom, pcap)──►  ftrap_dns.py  ──►  SQLite (24 h Einzelanfragen, 30 Tage Tagessummen)
                                         │
                                         └──►  dns_live.json (alle 5 s), dns_top.json (alle 60 s)
```

1. Anmeldung mit einem eigenen Box-Benutzer (`/login_sid.lua`, PBKDF2-Challenge).
2. Mitschnitt starten: `GET /cgi-bin/capture_notimeout?sid=...&capture=Start&snaplen=1600&filter=udp port 53 or tcp port 53&ifaceorminor=1-lan`. Die Box antwortet mit einem endlosen pcap-Strom.
3. Ethernet / VLAN / IPv4 / IPv6 / UDP und die DNS-Nachrichten auswerten, jede Anfrage ihrer Antwort zuordnen (Wiederholungen werden zusammengefasst, unbeantwortete Anfragen laufen nach 10 s ab).
4. Einordnung: `allowed`, `blocked` (unspezifizierte Adresse oder leere, von der Box erzeugte Antwort des DNS-Filters), `nxdomain`, `error`, `no_answer`.
5. In SQLite speichern und die JSON-Dateien schreiben. Bei `SIGTERM`/`SIGINT` wird der Mitschnitt an der Box beendet (`capture=Stop`) und die Sitzung abgemeldet.

Protokolldetails, die bei ähnlichen Eigenbauten wichtig sind:

- Die Abfragezeichenfolge muss Leerzeichen als `%20` kodieren, nie als `+` – sonst liefert die Box keinen Datenstrom.
- Die Box erwartet einen `Referer` und einen browserähnlichen `User-Agent`.
- Der Strom ist entweder Standard-pcap oder das „modified pcap“ von AVM (Magic `0xA1B2CD34`, 24-Byte-Satzkopf). Beides wird verarbeitet.
- Mitgeschnitten wird nur DNS über UDP/TCP-Port 53. TCP-DNS wird gezählt, aber nicht entschlüsselt. Verschlüsseltes DNS (DoH/DoT/DoQ) erscheint nicht.

## Voraussetzungen

- FRITZ!Box mit FRITZ!OS 8.50 (getestet auf einer 7690); andere Modelle und Firmware funktionieren eventuell nicht.
- Python 3.11 oder neuer (CI testet 3.11 - 3.13). Keine Pakete von Drittanbietern.
- Ein **eigener Box-Benutzer** (siehe unten).

### Box-Benutzer und Rechte

Die Box erlaubt einen Paketmitschnitt nur mit dem Recht **„FRITZ!Box Einstellungen“**. Praktisch entspricht das fast einem Administrator. Deshalb:

- Legen Sie einen eigenen Benutzer nur für dieses Werkzeug an (System > FRITZ!Box-Benutzer), verwenden Sie nicht Ihre eigene Anmeldung.
- Schalten Sie für diesen Benutzer „Zugang aus dem Internet“ aus.
- Behandeln Sie die Zugangsdaten wie Administrator-Zugangsdaten: Dateimodus 600, nie in einem Repository, nie auf einem geteilten Rechner.

Aktivieren Sie die optionalen Gerätenamen (`[hosts]`), muss die Box TR-064-Zugriff für Anwendungen erlauben (eine Netzwerkeinstellung der Box, deren genauer Ort von der Firmware abhängt) und derselbe Benutzer das dafür nötige Recht haben.

## Installation und Start

```sh
git clone https://github.com/Zorroficator/fritzbox-dns-capture-collector.git && cd fritzbox-dns-capture-collector
cp config.example.toml capture.toml        # anpassen
# Zugangsdatei: Benutzer in Zeile 1, Kennwort in Zeile 2 (im Editor eintippen,
# so landet das Kennwort nicht in der Shell-Historie)
install -d -m 700 ~/.config/ftrap
install -m 600 /dev/null ~/.config/ftrap/capture_credentials
${EDITOR:-nano} ~/.config/ftrap/capture_credentials

python3 check_login.py --config capture.toml     # nur Anmeldetest, kein Mitschnitt
python3 ftrap_dns.py   --config capture.toml     # starten
```

Die Tests laufen mit `python3 -m unittest discover -s tests`.

### Zugangsdaten

Reihenfolge der Suche:

1. `--password-stdin` – das Kennwort wird aus der ersten Zeile von stdin gelesen; der Benutzername kommt aus `FTRAP_CAPTURE_USER` oder dem Konfigurationsschlüssel `user`.
2. Umgebung: `FTRAP_CAPTURE_USER` und `FTRAP_CAPTURE_PASSWORD` (beide).
3. Zugangsdatei (`credentials_file`, Standard `$XDG_CONFIG_HOME/ftrap/capture_credentials`): Benutzername in Zeile 1, Kennwort in Zeile 2, oder `username: ...` / `password: ...`. Eine für Gruppe oder andere lesbare Datei wird abgelehnt, außer Sie geben `--allow-insecure-credentials` an.

Das Kennwort wird nie geloggt und taucht nie in einer Fehlermeldung auf.

Optionales Rezept für die macOS-Schlüsselbund-Verwaltung (der Code hängt nicht davon ab; eigene Dienst- und Kontonamen verwenden):

```sh
security find-generic-password -s mein-ftrap-dienst -a mein-ftrap-benutzer -w \
  | FTRAP_CAPTURE_USER=mein-ftrap-benutzer python3 ftrap_dns.py --config capture.toml --password-stdin
```

### HTTPS mit Zertifikat-Pin (empfohlen)

Mit reinem `http://` laufen die Sitzungs-ID und der gesamte DNS-Datenstrom unverschlüsselt durch Ihr LAN. Verwenden Sie stattdessen HTTPS mit einem Pin des Box-Zertifikats:

```sh
openssl s_client -connect fritz.box:443 </dev/null 2>/dev/null \
  | openssl x509 -outform DER | openssl dgst -sha256
```

Der Pin wird beim ersten Mal ungeprüft übernommen (Trust on first use): Ermitteln Sie ihn über eine vertrauenswürdige (z. B. kabelgebundene) Verbindung und vergleichen Sie ihn mit dem Zertifikat aus der Oberfläche der Box. Tragen Sie die 64 Hexziffern in die Konfiguration ein:

```toml
box_url = "https://fritz.box"
pin_sha256 = "<64 Hexziffern>"
```

Der Pin ist der SHA-256-Wert des DER-kodierten Zertifikats und wird nach jedem Verbindungsaufbau geprüft. Alternativ (oder zusätzlich) kann `ca_file` auf eine PEM-Datei mit dem Box-Zertifikat zeigen; dann gilt die normale Prüfung einschließlich Hostname. `https://` ohne Pin und ohne `ca_file` wird abgelehnt – es gibt keinen ungeprüften Modus und keinen Rückfall auf http. Weiterleitungen der Box werden nie verfolgt. Ein neues Zertifikat (zum Beispiel nach dem Zurücksetzen auf Werkseinstellungen) braucht einen neuen Pin.

> [!NOTE]
> Der HTTPS-Weg mit Pin ist umgesetzt und per Unit-Test geprüft, aber noch nicht an echter Hardware verifiziert (die Tests an der Box liefen bisher nur mit `http://`). Rückmeldungen sind willkommen.

### Als Dienst betreiben

- Linux: [examples/systemd/ftrap-dns.service](examples/systemd/ftrap-dns.service)
- macOS: [examples/launchd/org.example.ftrap-dns.plist](examples/launchd/org.example.ftrap-dns.plist)

Die systemd-Unit läuft als eigener unprivilegierter Dienstbenutzer mit `StateDirectory=ftrap` (`/var/lib/ftrap`), `ConfigurationDirectory=ftrap` (`/etc/ftrap`), den Zugangsdaten über `LoadCredential=` und einer gehärteten Sandbox; im Kopf der Datei stehen die Einrichtungsschritte und die Pfade für `capture.toml`. Der launchd-Agent läuft als angemeldeter Benutzer und liest die Zugangsdatei (Modus 600). Beide beenden sich bei `SIGTERM` sauber.

### Belegung des Paketmitschnitts der Box

Die Box kann **einen** Paketmitschnitt gleichzeitig. Solange der Sammler läuft, schlägt ein manueller Mitschnitt in der Weboberfläche der Box (System > Diagnose > Paketmitschnitt) fehl; hält jemand anderes den Mitschnitt, meldet der Sammler `capture_busy`. Zum Beenden des Sammlers `SIGTERM` senden (oder `systemctl stop`). Wurde der Prozess hart beendet (`SIGKILL`, Stromausfall), öffnen Sie einmal die Mitschnittseite der Box und beenden dort den laufenden Mitschnitt.

Wird die Anmeldung wiederholt abgelehnt, wartet der Sammler länger (bis zu 2 Stunden zwischen den Versuchen, mindestens aber die von der Box gemeldete Sperrzeit), damit die Anmeldesperre der Box nicht verlängert wird.

## Konfiguration

Alle Schlüssel sind optional; siehe [config.example.toml](config.example.toml).

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `box_url` | `http://fritz.box` | Weboberfläche der Box |
| `pin_sha256`, `ca_file` | leer | TLS-Vertrauen für `https://` (einer von beiden ist dort Pflicht) |
| `allow_legacy_md5` | `false` | alte MD5-Anmeldung von Firmware vor FRITZ!OS 7.24 akzeptieren. Standardmäßig aus: über reines `http://` könnte ein Angreifer im Netz die schwächere Anmeldung erzwingen, indem er eine Challenge ohne `2$` sendet; FRITZ!OS ab 7.24 nutzt PBKDF2 |
| `timeout_seconds` | 10 | Zeitlimit für Anmeldung und Hilfsabfragen |
| `interface` | `1-lan` | Mitschnitt-Schnittstelle |
| `user`, `credentials_file` | | siehe [Zugangsdaten](#zugangsdaten) |
| `out_dir` | `~/.local/share/ftrap/out` | Ablage von `dns_live.json` / `dns_top.json` |
| `db_path` | `~/.local/share/ftrap/ftrap_dns.db` | SQLite-Datei |
| `timezone` | lokale Zone | IANA-Name oder `UTC`; legt die Kalendertage fest |
| `log_file` | stderr | rotierende Logdatei |
| `[capture]` | 150 s / 30 s | Leerlauf- und Verbindungs-Zeitlimit |
| `[limits]` | 1200 / 20000 / 1024 / 6000 / 500 | `client_per_min`: gespeicherte Anfragen je Gerät und Minute; `domains_per_day`: neue Domains je Tag; `min_free_mb`: freier Plattenplatz mindestens (MB); `events_per_min`: gespeicherte Anfragen je Minute insgesamt; `clients_per_day`: verschiedene Geräte je Tag in den Tagessummen (weitere werden als `(other)` zusammengefasst); zugleich Obergrenze für die je Minute für `client_per_min` verfolgten Geräte (weitere teilen sich einen Zähler) und für die in der 24-h-Ansicht eingestuften Geräte. Anfragen über einem Limit werden nur gezählt (`health.rate_limited`) |
| `[output]` | `0o700` / `0o600` | `dir_mode` (für `out_dir`, nur beim Anlegen) und `file_mode` der JSON-Dateien; Oktalzahl oder Zeichenkette, siehe [Webserver unter anderem Benutzer](#webserver-unter-anderem-benutzer) |
| `[retention]` | 24 h / 30 Tage | Einzelanfragen / Tagessummen |
| `[hosts]` | aus / 600 s | Gerätenamen von der Box (TR-064); `refresh_seconds`: Abrufintervall (Standard 600, Minimum 60) |
| `[aliases]` | leer | eigene Bezeichnungen nach MAC oder IPv4 |

Die Pfade folgen den XDG-Konventionen (`XDG_CONFIG_HOME`, `XDG_DATA_HOME`). Verzeichnisse werden nur dann mit dem eingestellten Modus angelegt, wenn sie fehlen; bestehende Verzeichnisse werden nie verändert (bei mehr Zugriff für Gruppe/andere als `dir_mode` erscheint eine Warnung im Log).

### Webserver unter anderem Benutzer

Standardmäßig entsteht das Ausgabeverzeichnis mit Modus 700 und die JSON-Dateien mit Modus 600; nur der Benutzer des Sammlers kann sie lesen. Liefert ein Webserver unter einem anderen Benutzer die Dateien aus (zum Beispiel das Verzeichnis `data/` des Dashboards), meldet er „403 Forbidden“. Wählen Sie eine Möglichkeit:

- Sammler und Webserver unter demselben Benutzer betreiben;
- in `[output]` `file_mode = 0o640` und `dir_mode = 0o750` setzen und dem Benutzer des Sammlers und dem Webserver eine gemeinsame Gruppe geben (`chgrp` für das Verzeichnis). Ein bestehendes Verzeichnis ändert der Sammler nicht, Gruppe und Modus setzen Sie selbst;
- den Sammler in ein eigenes `out_dir` schreiben lassen und nur `dns_*.json` ins Webverzeichnis kopieren (nie die Datenbank).

## Datenschutz

Dieses Werkzeug zeichnet auf, **welche Domains jedes Gerät in Ihrem Haushalt wann abfragt**. Das sind sensible Verhaltensdaten – auch über Personen, die dem nie zugestimmt haben.

- **Informieren Sie alle**, die Ihr Netzwerk nutzen – Familie, Mitbewohner, Gäste –, bevor Sie starten. Je nach Land und Situation kann die Überwachung fremden Datenverkehrs rechtlich eingeschränkt sein. Sie sind für Ihre Nutzung verantwortlich.
- **Halten Sie die Daten im LAN.** Veröffentlichen Sie `dns_live.json` / `dns_top.json` und die Datenbank nicht im Internet. Wenn ein Webserver das Ausgabeverzeichnis ausliefert, beschränken Sie den Zugriff auf vertrauenswürdige Geräte oder verlangen Sie eine Anmeldung. Welche Felder personenbezogen sind, steht in [docs/dns_contract.md](docs/dns_contract.md).
- **Die Aufbewahrung ist begrenzt**: Einzelanfragen bleiben `retention.events_hours` (standardmäßig 24 h), Tagessummen `retention.daily_days` (30 Tage). Senken Sie die Werte, wenn möglich.
- **Hostnamen sind standardmäßig aus.** Ohne `[hosts]` erscheinen Geräte mit IP- bzw. MAC-Adresse, solange Sie nicht selbst einen `[aliases]`-Eintrag anlegen.
- **Logs enthalten nur Zähler und Fehlerarten** – nie Domains, Hostnamen, IPs, MACs, Sitzungs-IDs oder Kennwörter.
- Die Datenbankdateien haben immer Modus 600; Ausgabeverzeichnis und JSON-Dateien entstehen standardmäßig mit Modus 700 / 600 (einstellbar, siehe [Webserver unter anderem Benutzer](#webserver-unter-anderem-benutzer)). Legen Sie die Datenbank außerhalb jedes über das Web ausgelieferten Ordners ab.
- Verschlüsseltes DNS ist nicht sichtbar. Erfassen Sie nur, was Sie wirklich brauchen.

## Optional: Gerätenamen

> [!NOTE]
> Umgesetzt und per Unit-Test geprüft, aber noch nicht an echter Hardware verifiziert (die Tests an der Box liefen bisher ohne `[hosts]`). Rückmeldungen sind willkommen.

```toml
[hosts]
enabled = true

[aliases]
"02:00:00:00:00:01" = "Fernseher Wohnzimmer"
"192.0.2.10"        = "Drucker"
```

Mit `enabled = true` ruft der Sammler alle `refresh_seconds` die Hostliste über die TR-064-Schnittstelle der Box ab (Port 49000, bei `https://` Port 49443; gleiche Zugangsdaten, gleicher Pin). Ein Repeater, der eine MAC-Adresse für mehrere Geräte verwendet, wird erkannt und mit der IP angezeigt. `[aliases]` haben immer Vorrang vor Namen aus der Hostliste. Schlägt der Abruf fehl, bleiben die bisherigen Namen erhalten und `health.host_errors` steigt.

## Einschränkungen

- Erfasst wird nur DNS-Verkehr, der über die gewählte Schnittstelle der Box läuft (standardmäßig `1-lan`). Geräte, die an der Box vorbei einen anderen Resolver nutzen, und verschlüsseltes DNS sind unsichtbar.
- DNS über TCP wird gezählt, nicht ausgewertet; fragmentiertes UDP wird übersprungen.
- Der Mitschnitt verwendet `snaplen=1600`: größere DNS-Antworten (zum Beispiel große EDNS-/DNSSEC-Antworten über 1600 Byte je Rahmen) werden abgeschnitten; solche Pakete lassen sich unter Umständen gar nicht auswerten und erscheinen dann als `no_answer`.
- Ein Prozess, ein Mitschnitt; keine eigene Anmeldung und kein eigener Webserver.
- Endpunkt und pcap-Rahmen sind undokumentiert; Firmware-Updates können den Sammler beschädigen.

## Danksagung

Idee und Ansatz sind von [FritzHole](https://github.com/Milinator/fritzhole-ha) inspiriert, einer Home-Assistant-App, die den Paketmitschnitt der Box für den DNS-Filter liest. Es wurde kein Code übernommen.

## Lizenz

MIT – siehe [LICENSE](LICENSE).
