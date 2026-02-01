OVERVIEW
v0.3.0 introduces an onboarding wizard used by both Dollhouse apps (D and Q) with the same dependency flow:

Detect system state (Tailscale, Docker, service status, connectivity)

Offer guided setup actions (install/connect/enable)

Configure safe networking defaults (localhost-first, tailnet-only optional)

Confirm access with copy-paste URLs and “test connection” checks

GOALS

Make initial setup “works on first try” for a VPS or home server.

Default-secure: control panel is NOT public internet reachable.

Tailscale-first: if present, show MagicDNS + tailnet URL immediately.

Headless-friendly: onboarding works when the server has no GUI.

Same flow across both apps, with shared implementation.

NON-GOALS

Implement “Log in with Tailscale” as OAuth/SSO. That’s not what Tailscale is.

Build full RBAC. v0.3.0 can do single-admin or minimal roles if you already have it.

Public reverse proxy wizard. That’s vLater, if you hate peace.

ASSUMPTIONS

Control panel runs on port 17666 (adjustable).

The app can execute OS commands (or has a helper/agent that can).

Supported platforms for v0.3.0: Linux first (Ubuntu/Debian). Others can be “best effort.”

SECURITY DEFAULTS
Default network exposure:

App binds to 127.0.0.1:17666 (localhost only).

No firewall ports opened to the public interface.

Remote access is via:
A) Tailscale (direct tailnet bind or tailnet-only firewall rule), OR
B) SSH tunnel (works over tailnet or normal internet SSH).

Optional exposure modes (explicit opt-in):

Tailnet-only: bind to tailscale0 or allow port 17666 inbound only on tailscale0.

Never ship “public internet exposure” as a one-click option in v0.3.0.

ONBOARDING WIZARD
The wizard is the same for both apps. It has phases with detection and actions.

Phase 1: System check
Show a checklist with statuses:

App service: Installed / Running

Tailscale: Not installed / Installed / Connected

Docker: Not installed / Installed / Running

Detection logic (Linux):

Tailscale installed: command -v tailscale and systemctl is-active tailscaled

Tailscale connected: tailscale status --json (or tailscale ip -4 succeeds)

Docker installed: command -v docker

Docker running: systemctl is-active docker or docker info returns 0

Phase 2: Tailscale path (optional route)
If Tailscale is not installed:

Button: “Install Tailscale”

Use official package method for distro (script-based is acceptable for v0.3.0 if you log what you’re doing).

After install, re-check tailscaled status.

If installed but not connected:
Offer two connect methods:

Method A: Interactive login (recommended for humans)

Action: run tailscale up (or tailscale login then tailscale up if needed)

Show the login URL text in UI and copy button.

Poll connection state until connected (timeout with clear error).

Method B: Auth key (recommended for headless / automation)

Input: auth key (masked)

Optional input: hostname override

Action: tailscale up --authkey <key> [--hostname <name>]

Important rule: Do NOT persist auth key. Use once and discard.

After connected:
Display connection summary:

Tailnet IPv4: from tailscale ip -4

MagicDNS name guess: use tailscale status --json node name if available; otherwise OS hostname.

Show URLs:

“Try MagicDNS:” http://<node-name>:17666

“Fallback IP:” http://<tailscale-ip>:17666
Also show: “If this doesn’t load, your panel is probably bound to localhost only. Use tunnel mode or enable tailnet-only bind.”

Phase 3: Access mode selection
User chooses how the panel should be reachable.

Option 1 (default): Localhost only

Bind: 127.0.0.1

Show “Access via SSH tunnel” instructions:

If Tailscale connected: suggest ssh user@<magicdns> or tailscale ssh <magicdns> if enabled.

Tunnel command template:

ssh -N -L 17666:127.0.0.1:17666 user@<host>

Provide “Copy command” button.

Option 2: Tailnet-only direct access (opt-in, recommended if you trust your tailnet)
Two implementation choices. Pick one and be consistent:

A) Bind to Tailscale IP

Bind address becomes the host’s Tailscale IPv4 (preferred if your server supports binding to that IP).

Firewall: optionally also restrict to tailscale0.

B) Bind to 0.0.0.0 but restrict firewall to tailscale0

Bind: 0.0.0.0

Firewall rules (ufw example):

allow inbound 17666 on tailscale0

deny inbound 17666 on public interfaces
This is easier operationally, but requires firewall tooling and permission.

After applying the mode:

Restart app service.

Run “Reachability test”:

From host: curl localhost:17666/health

If tailnet-only: also curl <tailscale-ip>:17666/health

Wizard reports pass/fail with exact error text.

Phase 4: Docker route (optional route)
If Docker not installed:

Button: “Install Docker”

After install, verify docker info works.

If installed:

Optional: “Enable container features” toggle

Validate permission:

If user is not in docker group, either:

instruct to add + re-login, or

run Docker operations via sudo (less ideal, but pragmatic for v0.3.0)

Phase 5: Finish
Show a “Your control panel” card:

Primary URL (MagicDNS if enabled)

Fallback URL (Tailscale IP)

Tunnel command (if localhost mode)

“Open health check” link

“View logs” link (tail to journald or log file)

CONFIG + STATE
Persist the minimal state needed:

Config file keys (example names, adjust to your structure):

server.port: 17666

server.bind_mode: localhost | tailnet

server.bind_addr: 127.0.0.1 OR <tailscale-ip> OR 0.0.0.0

tailscale.enabled: true/false (means “we detected and used it,” not installed)

tailscale.node_name: cached display name

tailscale.tailnet_ip: cached display ip

docker.enabled: true/false

Never store:

Tailscale auth keys

Any secrets printed to console during install

UI REQUIREMENTS

Wizard must be resumable. If the user closes it mid-way, re-run detection and continue.

Every action shows:

what it will do

the exact command(s) being run (expandable “details”)

live output view (scrolling), with copy button

Clear errors with fixes:

“tailscaled not running” -> show systemctl start command

“MagicDNS name doesn’t resolve” -> show fallback IP URL

“Connection refused” -> explain bind mode mismatch

LOGGING + DIAGNOSTICS
Add a diagnostics bundle generator:

versions: app version, OS, tailscale version, docker version

network: detected bind addr/port, tailscale IP, node name

service status: systemctl status summaries

last N lines of logs for app + tailscaled
Output: a single text file the user can copy/download.

TEST PLAN
Unit-ish tests (where possible):

Parse tailscale status output (json)

Bind mode transitions update config correctly

No secret persistence (auth key never written)

Integration tests (manual is fine for v0.3.0):

Fresh VPS: no tailscale/docker -> install tailscale -> interactive connect -> localhost mode -> tunnel works

Tailnet-only mode: verify reachable from another tailnet device

MagicDNS off: ensure fallback IP URL works

Firewall present vs absent: behavior is clear and doesn’t brick access

RELEASE CHECKLIST FOR v0.3.0

Default install exposes nothing publicly.

Wizard completes end-to-end on a clean Ubuntu VPS.

“Copy URL” and “Copy tunnel command” both correct.

No secrets stored.

Logs/diagnostics bundle works.
