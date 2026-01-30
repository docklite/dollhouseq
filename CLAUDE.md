# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Dollhouse q** is a lightweight qBittorrent monitoring dashboard delivered as a single static Go binary. It provides a read-only web interface for monitoring qBittorrent status, VPN connectivity, disk usage, and active torrents.

**Core principles:**
- Single static binary (`dollhouse-q`) - no database, no background workers, no websockets
- Minimal dependencies - serves static UI + JSON API endpoints
- Local-first - binds to `127.0.0.1` by default (accessed via SSH tunnel/WireGuard)
- No container management, file browsing, user accounts, or public exposure

## Architecture

### Components
1. **Static UI**: Embedded single-page HTML (see `dollhouseq.html` for design mockup)
2. **JSON API**: HTTP endpoints for status/health/torrents
3. **Data sources**:
   - qBittorrent Web API (HTTP)
   - Disk metrics via `statvfs` on configured path
   - VPN health check (qBittorrent reachability + optional Gluetun health URL)

### API Endpoints

```
GET /health
→ { ok, version, uptime_s, ts }

GET /status
→ { overall, last_check_s, vpn:{state}, qb:{state}, disk:{path, free_pct, free_bytes, total_bytes}, webui_url }

GET /torrents?limit=20
→ [ { name, state, progress, down_bps, up_bps, eta_s }, ... ]

POST /actions/pause_all (optional)
POST /actions/resume_all (optional)
```

### Configuration

File-based config (e.g., `/etc/dollhouse-q/config.json`):
- `listen_addr` - default: `127.0.0.1:17666`
- `qb_url` - qBittorrent API URL, default: `http://127.0.0.1:8080`
- `qb_username`, `qb_password` - qBittorrent credentials
- `webui_url` - URL for "Open WebUI" button
- `disk_path` - path to monitor (e.g., `/data` or `/downloads`)
- `gluetun_health_url` - (optional) Gluetun health check endpoint
- `poll_interval_s` - UI refresh timing hint

## UI Design

The `dollhouseq.html` file is the reference design mockup with:
- **Color scheme**: Dark theme with pink/purple accents (`--pink: #ff4fd8`, `--ok: #58ffcc`, `--warn: #ffd36b`, `--bad: #ff4f6d`)
- **Top bar**: App name, host label, overall status dot, last check timer
- **Status card**: VPN and qBittorrent reachability pills
- **Storage card**: Disk usage bar + percentage free
- **Torrent list**: Max 20 torrents with state dots (downloading/seeding/paused/error), progress pills, speed, ETA
- **Actions**: "Open WebUI" button, optional "Pause all" button

### State Indicators
- **VPN states**: CONNECTED, DOWN
- **qBittorrent states**: REACHABLE, DOWN
- **Torrent states**: Downloading (pink dot), Seeding (green dot), Paused (gray dot), Error (red dot)

## Implementation Notes

### Go Binary Structure
When implementing the Go service:
1. Embed `dollhouseq.html` as static asset (use `//go:embed`)
2. HTTP handlers for API endpoints + static file serving
3. qBittorrent client wrapper (authenticate, fetch torrents, pause/resume actions)
4. VPN health logic: "VPN OK if qB is reachable AND (optional) gluetun health URL responds"
5. Disk metrics via `golang.org/x/sys/unix.Statvfs`

### Deployment
```
/usr/local/bin/dollhouse-q         # binary
/etc/dollhouse-q/config.json       # config
```

Typically run via systemd service and accessed through SSH tunnel or WireGuard.

## Explicit Non-Goals
- No container management (no Docker API calls)
- No file browser or download management
- No user authentication system
- No public-facing deployment by default
- No media library indexing or streaming
