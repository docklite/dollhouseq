# Dollhouse q

A lightweight qBittorrent monitoring dashboard delivered as a single static Go binary.

## Features

- Single static binary with no external dependencies
- Real-time monitoring of:
  - qBittorrent status and torrents
  - VPN connectivity (via qBittorrent + optional Gluetun health check)
  - Disk usage metrics
- Clean, minimal web UI
- JSON API for programmatic access
- Local-first design (binds to 127.0.0.1 by default)

## Installation

### Prerequisites

- Go 1.22 or later (for building)
- qBittorrent with Web UI enabled
- Linux system (for deployment)

### Build from Source

```bash
# Clone or download this repository
cd smallvps

# Build the binary
make build

# Or cross-compile for different platforms
make build-all
```

### System Installation

```bash
# Install binary and create config directory
sudo make install

# Edit the configuration file
sudo nano /etc/dollhouse-q/config.json

# Install and enable systemd service
sudo make install-service
sudo systemctl enable dollhouse-q
sudo systemctl start dollhouse-q
```

### Configuration

Edit `/etc/dollhouse-q/config.json`:

```json
{
  "listen_addr": "127.0.0.1:17666",
  "qb_url": "http://127.0.0.1:8080",
  "qb_username": "admin",
  "qb_password": "your-password",
  "webui_url": "http://127.0.0.1:8080",
  "disk_path": "/data",
  "gluetun_health_url": "",
  "poll_interval_s": 15,
  "host_label": "my-server"
}
```

**Configuration options:**

- `listen_addr`: Address to bind the web server (default: `127.0.0.1:17666`)
- `qb_url`: qBittorrent Web API URL (default: `http://127.0.0.1:8080`)
- `qb_username`: qBittorrent Web UI username (required)
- `qb_password`: qBittorrent Web UI password (required)
- `webui_url`: URL for "Open WebUI" button
- `disk_path`: Path to monitor for disk usage (default: `/data`)
- `gluetun_health_url`: Optional Gluetun health check endpoint
- `poll_interval_s`: UI refresh interval hint (default: 15)
- `host_label`: Optional label shown in UI (e.g., "my-vps • 10.0.0.1")

## Usage

### Access the Dashboard

By default, the dashboard runs on `http://127.0.0.1:17666`.

**Remote access options:**
- SSH tunnel: `ssh -L 17666:localhost:17666 user@yourserver`
- WireGuard VPN to your server
- Reverse proxy (if you know what you're doing)

### API Endpoints

- `GET /` - Web UI
- `GET /health` - Health check endpoint
- `GET /status` - System status (VPN, qBittorrent, disk)
- `GET /torrents?limit=20` - Torrent list
- `POST /actions/pause_all` - Pause all torrents
- `POST /actions/resume_all` - Resume all torrents

### Development

```bash
# Run locally with example config
make run

# Format code
make fmt

# Clean build artifacts
make clean
```

## Systemd Service Management

```bash
# Start the service
sudo systemctl start dollhouse-q

# Stop the service
sudo systemctl stop dollhouse-q

# Restart the service
sudo systemctl restart dollhouse-q

# View logs
sudo journalctl -u dollhouse-q -f

# Check status
sudo systemctl status dollhouse-q
```

## Uninstallation

```bash
sudo make uninstall
```

This removes the binary and systemd service but preserves your configuration in `/etc/dollhouse-q/`.

## Architecture

- **Single binary**: No database, no background workers, no websockets
- **Polling model**: API endpoints query current state on demand
- **Embedded UI**: HTML/CSS embedded in binary via `go:embed`
- **Minimal dependencies**: Only `golang.org/x/sys/unix` for disk metrics

See `CLAUDE.md` for detailed architecture documentation.

## Troubleshooting

### Authentication fails
- Verify qBittorrent credentials in config
- Check qBittorrent Web UI is enabled and accessible
- Ensure qBittorrent allows local API access

### Disk metrics show error
- Verify `disk_path` exists and is accessible
- Check file permissions for the service user

### VPN shows DOWN but qBittorrent is reachable
- If using Gluetun, verify `gluetun_health_url` is correct
- Check Gluetun container is running and healthy

### Service won't start
- Check logs: `journalctl -u dollhouse-q -n 50`
- Verify config file exists and is valid JSON
- Ensure port 17666 is not already in use

## License

See project license file.
