Architecture

Single static binary (dollhouse-q) that serves:

Static UI (the HTML mockup)

JSON API endpoints

Default bind: 127.0.0.1:<port> (tunnel or reverse proxy later if desired)

No DB. No background workers. No websockets.

UI (single page)
Top strip:

App name: “Dollhouse q”

Host label (optional)

Status dot + OK/WARN/DOWN

“Last check: Ns”

Cards:

Status

VPN: CONNECTED/DOWN (initially derived from gluetun/qb reachability rules)

qB: REACHABLE/DOWN

Storage

Disk free % + free/total (human readable)

Simple bar

Torrent list (max 20)

Each row: state dot + name + (progress pill OR state pill)

Optional right-side: down speed + ETA (can be hidden if you want calmer)

Actions

Button: Open WebUI (links to configured URL)

Optional: Pause all (POST action)

API endpoints

GET /health

returns { ok, version, uptime_s, ts }

GET /status

returns { overall, last_check_s, vpn:{state}, qb:{state}, disk:{path, free_pct, free_bytes, total_bytes}, webui_url }

GET /torrents?limit=20

returns list of { name, state, progress, down_bps, up_bps, eta_s }

Optional:

POST /actions/pause_all

POST /actions/resume_all

Data sources

qBittorrent: Web API over HTTP (local URL from config)

Disk: statvfs on configured path (downloads mount)

VPN:

MVP: “VPN OK if qB is reachable AND (optional) gluetun health URL responds”

Later: dedicated gluetun health/IP checks

Config (file-based)

listen_addr (default 127.0.0.1:17666)

qb_url (default http://127.0.0.1:8080)

qb_username, qb_password (or token/cookie approach)

webui_url (what the UI button opens)

disk_path (e.g. /data or /downloads)

optional: gluetun_health_url

poll_interval_s (UI uses this only for front-end refresh timing)

Non-goals (explicit)

No container management

No file browser

No user accounts

No public exposure by default

No media indexing

Install

Copy binary to /usr/local/bin/dollhouse-q

Config to /etc/dollhouse-q/config.json

systemd service runs it

Access via SSH tunnel / WireGuard / localhost
