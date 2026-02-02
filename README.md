# Dollhouse q

A lightweight qBittorrent monitoring dashboard delivered as a single static Go binary with automated VPN setup.

## Features

### Core
- **Single static binary** - No database, no Node.js, no containers (except for qBittorrent itself)
- **One-command setup** - Interactive wizard handles everything
- **Automated VPN integration** - Sets up Mullvad WireGuard via Gluetun automatically
- **HTTPS out of the box** - Self-signed certs generated for magnet link support
- **Tailscale-ready** - Optional Tailnet integration for secure remote access

### Monitoring
- Real-time qBittorrent status and torrent list
- VPN connectivity verification (Gluetun health checks)
- Disk usage metrics for downloads directory
- Clean, minimal web UI with dark theme

### API
- JSON endpoints for programmatic access
- Health checks and status reporting
- Torrent list with filtering
- Pause/resume all torrents

## Quick Start

### Prerequisites

- Linux VPS or server
- Docker (for qBittorrent + Gluetun)
- (Optional) Tailscale for remote access
- (Optional) Mullvad VPN subscription for automated VPN setup

### Installation

**1. Download the binary:**

```bash
# For amd64 (most common)
wget https://github.com/docklite/dollhouseq/releases/latest/download/dollhouse-q-linux-amd64
chmod +x dollhouse-q-linux-amd64
sudo mv dollhouse-q-linux-amd64 /usr/local/bin/dollhouse-q

# For arm64 (Raspberry Pi 4, etc)
wget https://github.com/docklite/dollhouseq/releases/latest/download/dollhouse-q-linux-arm64
chmod +x dollhouse-q-linux-arm64
sudo mv dollhouse-q-linux-arm64 /usr/local/bin/dollhouse-q

# For armv7 (Raspberry Pi 3, etc)
wget https://github.com/docklite/dollhouseq/releases/latest/download/dollhouse-q-linux-arm
chmod +x dollhouse-q-linux-arm
sudo mv dollhouse-q-linux-arm /usr/local/bin/dollhouse-q
```

**2. Run the wizard:**

```bash
sudo dollhouse-q
```

The wizard will:
- Detect your system (Tailscale, Docker)
- Optionally set up Tailscale for remote access
- Help you choose localhost or Tailnet access mode
- Set up Docker if needed
- **Automatically configure Mullvad WireGuard VPN via Gluetun** (if you provide credentials)
- Generate HTTPS certificates for qBittorrent
- Configure qBittorrent credentials
- Create a systemd service

**3. Access the dashboard:**

- **Localhost mode:** `ssh -L 17666:localhost:17666 user@your-server` then open http://localhost:17666
- **Tailnet mode:** Open http://your-hostname:17666 from any device on your Tailscale network

## Wizard Features

### System Detection (Phase 1)
Automatically detects:
- Dollhouse q installation status
- Tailscale installation and connection state
- Docker installation and running status

### Tailscale Setup (Phase 2)
- Guide for installing Tailscale (if needed)
- Connection methods: interactive login or auth key
- Skip option if you prefer localhost-only access

### Access Mode (Phase 3)
Choose how to access the dashboard:
- **Localhost** (`127.0.0.1:17666`) - Access via SSH tunnel
- **Tailnet** (`100.x.x.x:17666`) - Direct access from Tailscale network

### Docker Setup (Phase 4)
- Guide for installing Docker (if needed)
- Enable/disable container features

### VPN Setup (Phase 5) - Optional but Recommended
**Fully automated Gluetun + Mullvad WireGuard setup:**
- Inspects existing qBittorrent container configuration
- Launches Gluetun with your Mullvad credentials
- Restarts qBittorrent networked through Gluetun
- Verifies VPN connection is working
- **Generates SSL certificates for HTTPS**
- **Enables HTTPS in qBittorrent** (required for magnet link handlers)
- Creates `/downloads/incomplete` directory
- Waits for health checks to pass

All qBittorrent traffic is then routed through the VPN - no leaks.

### Finish (Phase 6)
- Enter qBittorrent credentials (validated before saving)
- Auto-detects qBittorrent port (usually 8081 after VPN setup)
- Auto-fills disk path from Docker volume mounts
- Saves config and restarts service

## Manual Installation (Advanced)

If you prefer to skip the wizard:

```bash
# Create config directory
sudo mkdir -p /etc/dollhouse-q

# Create config file
sudo nano /etc/dollhouse-q/config.json
```

Example config:

```json
{
  "listen_addr": "127.0.0.1:17666",
  "qb_url": "https://127.0.0.1:8081",
  "qb_username": "admin",
  "qb_password": "your-password",
  "webui_url": "https://127.0.0.1:8081",
  "disk_path": "/opt/seedbox/qbittorrent/downloads",
  "gluetun_health_url": "http://127.0.0.1:9999",
  "poll_interval_s": 15,
  "host_label": "",
  "server": {
    "port": 17666,
    "bind_mode": "localhost",
    "bind_addr": "127.0.0.1:17666"
  },
  "wizard_completed": true
}
```

Create systemd service:

```bash
sudo nano /etc/systemd/system/dollhouse-q.service
```

```ini
[Unit]
Description=Dollhouse q - qBittorrent monitoring dashboard
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dollhouse-q /etc/dollhouse-q/config.json
Restart=on-failure
RestartSec=10s
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable dollhouse-q
sudo systemctl start dollhouse-q
```

## VPN Verification

After VPN setup, verify your IP is hidden:

```bash
# Check qBittorrent's public IP
docker exec qbittorrent wget -qO- https://api.ipify.org

# Should show Mullvad's IP (NOT your server's real IP)
```

## API Endpoints

- `GET /` - Web UI
- `GET /health` - Health check `{"ok": true, "version": "0.6.1", "uptime_s": 123, "ts": 1234567890}`
- `GET /status` - System status (VPN, qBittorrent, disk)
- `GET /torrents?limit=20` - Torrent list with summary
- `POST /actions/pause_all` - Pause all torrents
- `POST /actions/resume_all` - Resume all torrents

### Wizard Endpoints (used during setup)
- `GET /wizard` - Wizard UI
- `GET /api/wizard/detect` - System detection
- `POST /api/wizard/qb-test` - Test qBittorrent credentials
- `POST /api/wizard/vpn/setup` - Start VPN setup
- `GET /api/wizard/vpn/status` - VPN setup progress (SSE stream)
- `POST /api/wizard/configure` - Save config and restart

## Development

### Build from Source

```bash
# Clone repository
git clone https://github.com/docklite/dollhouseq.git
cd dollhouseq

# Build for current platform
make build

# Cross-compile for all platforms
make build-all

# Run locally with example config
make run
```

### Project Structure

```
dollhouseq/
├── main.go              # Core application + wizard backend
├── dollhouseq.html      # Dashboard UI (embedded)
├── wizard.html          # Setup wizard UI (embedded)
├── Makefile             # Build tasks
├── config.example.json  # Example configuration
├── dollhouse-q.service  # Systemd unit file
├── CLAUDE.md            # Architecture documentation
└── README.md            # This file
```

## Configuration Reference

### Basic Settings
- `listen_addr` - Address to bind web server (default: `127.0.0.1:17666`)
- `qb_url` - qBittorrent API URL (use `https://` after VPN setup)
- `qb_username` - qBittorrent username (required)
- `qb_password` - qBittorrent password (required)
- `webui_url` - URL for "Open WebUI" button (should match client access method)
- `disk_path` - Path to monitor for disk usage
- `gluetun_health_url` - Gluetun health endpoint (usually `http://127.0.0.1:9999`)
- `poll_interval_s` - UI refresh interval (default: 15)
- `host_label` - Optional label shown in dashboard header

### Server Settings
- `server.port` - Server port (default: 17666)
- `server.bind_mode` - `"localhost"` or `"tailnet"`
- `server.bind_addr` - Resolved bind address

### Tailscale Settings
- `tailscale.enabled` - Enable Tailscale integration
- `tailscale.node_name` - Tailscale hostname (e.g., `my-server`)
- `tailscale.tailnet_ip` - Tailscale IP (e.g., `100.100.1.200`)

### Docker Settings
- `docker.enabled` - Enable Docker features (for future use)

### Wizard State
- `wizard_completed` - Set to `true` to skip wizard on next start

## Troubleshooting

### Wizard Issues

**Wizard won't start:**
- Delete config and restart: `sudo rm /etc/dollhouse-q/config.json && sudo dollhouse-q`

**Detection fails:**
- Check Docker is running: `docker ps`
- Check Tailscale: `tailscale status`

**VPN setup fails:**
- Check qBittorrent container exists: `docker ps -a | grep qbittorrent`
- Check Mullvad credentials are correct
- View Gluetun logs: `docker logs gluetun`

### Runtime Issues

**Authentication fails:**
- Verify qBittorrent credentials in config
- Test login manually: `curl -d 'username=admin&password=yourpass' https://localhost:8081/api/v2/auth/login -k`

**Disk metrics show 0%:**
- Verify `disk_path` exists and is correct
- Should match qBittorrent's downloads mount

**VPN shows DOWN:**
- Check Gluetun container: `docker ps | grep gluetun`
- Check health endpoint: `curl http://127.0.0.1:9999`
- View logs: `docker logs gluetun`

**"Unauthorized" when opening WebUI:**
- This is a Referer header issue - fixed in v0.6.0
- Update to latest version

**Magnet links don't work:**
- qBittorrent needs HTTPS for browser security
- Wizard auto-configures this in VPN setup phase
- Manually enable in qBittorrent settings if needed

### Service Management

```bash
# View logs
sudo journalctl -u dollhouse-q -f

# Check status
sudo systemctl status dollhouse-q

# Restart service
sudo systemctl restart dollhouse-q

# Stop service
sudo systemctl stop dollhouse-q
```

## Security Notes

- **Localhost mode**: Only accessible via SSH tunnel - secure by default
- **Tailnet mode**: Only accessible from your Tailscale network - secure by default
- **HTTPS**: Self-signed certs are fine for localhost/Tailnet (not exposed to internet)
- **VPN**: qBittorrent traffic is fully encrypted through Mullvad - your real IP is never exposed to trackers
- **No public exposure**: Never bind to `0.0.0.0` unless behind proper authentication

## Architecture

- **Single binary**: No database, no background workers, no websockets
- **Polling model**: API endpoints query current state on demand
- **Embedded UI**: HTML/CSS/JS embedded in binary via `go:embed`
- **Minimal dependencies**: Only `golang.org/x/sys/unix` for disk metrics
- **No qBittorrent modifications**: Uses standard Web API

See `CLAUDE.md` for detailed architecture documentation.

## Changelog

### v0.6.1 (2026-02-02)
- Fix critical wizard finish button silent failure on config save error
- Extract qBittorrent config path dynamically (no more hardcoded paths)
- Add HTTPS verification after qBittorrent restart
- Proper error handling for mkdir/chown in VPN setup
- UI feedback for wizard detection failures
- Dashboard shows "ERROR" on API fetch failures

### v0.6.0 (2026-02-02)
- Automated HTTPS setup during VPN wizard
- SSL certificate generation for qBittorrent
- Auto-creates `/downloads/incomplete` directory
- Fix torrent list display bug
- Fix state mapping for stopped torrents
- WebUI button uses noreferrer to bypass CSRF blocking
- TLS verification skipped for localhost HTTPS

### v0.5.0 and earlier
- Initial wizard implementation
- Tailscale integration
- VPN setup with Gluetun
- Basic monitoring features

## License

See project license file.

## Contributing

This project was built with [Claude Code](https://claude.com/claude-code). See `CLAUDE.md` for development guidance.
