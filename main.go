package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const version = "0.4.0"

//go:embed dollhouseq.html wizard.html
var htmlContent embed.FS

// Config represents the application configuration
type Config struct {
	ListenAddr       string          `json:"listen_addr"`
	QBUrl            string          `json:"qb_url"`
	QBUsername       string          `json:"qb_username"`
	QBPassword       string          `json:"qb_password"`
	WebUIUrl         string          `json:"webui_url"`
	DiskPath         string          `json:"disk_path"`
	GluetunHealthURL string          `json:"gluetun_health_url"`
	PollIntervalS    int             `json:"poll_interval_s"`
	HostLabel        string          `json:"host_label"`
	Server           ServerConfig    `json:"server"`
	Tailscale        TailscaleConfig `json:"tailscale"`
	Docker           DockerConfig    `json:"docker"`
	WizardCompleted  bool            `json:"wizard_completed"`
}

// ServerConfig contains server binding configuration
type ServerConfig struct {
	Port     int    `json:"port"`
	BindMode string `json:"bind_mode"` // "localhost" or "tailnet"
	BindAddr string `json:"bind_addr"` // resolved bind address
}

// TailscaleConfig contains Tailscale integration state
type TailscaleConfig struct {
	Enabled   bool   `json:"enabled"`
	NodeName  string `json:"node_name"`
	TailnetIP string `json:"tailnet_ip"`
}

// DockerConfig contains Docker integration state
type DockerConfig struct {
	Enabled bool `json:"enabled"`
}

// SetDefaults applies default values to config fields
func (c *Config) SetDefaults() {
	// Legacy support: if ListenAddr is set but Server.Port/BindAddr are not,
	// parse ListenAddr and populate Server config
	if c.ListenAddr != "" && c.Server.BindAddr == "" {
		c.Server.BindAddr = c.ListenAddr
		if c.Server.BindMode == "" {
			c.Server.BindMode = "localhost"
		}
	}

	if c.Server.BindAddr == "" {
		c.Server.BindAddr = "127.0.0.1:17666"
		c.Server.BindMode = "localhost"
	}
	if c.Server.Port == 0 {
		c.Server.Port = 17666
	}

	// Sync ListenAddr with Server.BindAddr for backward compatibility
	c.ListenAddr = c.Server.BindAddr

	if c.QBUrl == "" {
		c.QBUrl = "http://127.0.0.1:8080"
	}
	if c.WebUIUrl == "" {
		c.WebUIUrl = c.QBUrl
	}
	if c.DiskPath == "" {
		c.DiskPath = "/data"
	}
	if c.PollIntervalS == 0 {
		c.PollIntervalS = 15
	}
}

// Validate checks that required config fields are set
func (c *Config) Validate() error {
	if c.QBUsername == "" {
		return fmt.Errorf("qb_username is required")
	}
	if c.QBPassword == "" {
		return fmt.Errorf("qb_password is required")
	}
	return nil
}

// NeedsWizard returns true if the onboarding wizard should run
func (c *Config) NeedsWizard() bool {
	// If wizard was explicitly completed, don't run it
	if c.WizardCompleted {
		return false
	}

	// If essential fields are missing, wizard is needed
	if c.QBUsername == "" || c.QBPassword == "" {
		return true
	}

	return false
}

// System Detection Structures

type DetectionResult struct {
	App       AppDetection       `json:"app"`
	Tailscale TailscaleDetection `json:"tailscale"`
	Docker    DockerDetection    `json:"docker"`
}

type AppDetection struct {
	Installed bool `json:"installed"`
	Running   bool `json:"running"`
}

type TailscaleDetection struct {
	Installed bool   `json:"installed"`
	Connected bool   `json:"connected"`
	NodeName  string `json:"node_name,omitempty"`
	TailnetIP string `json:"tailnet_ip,omitempty"`
}

type DockerDetection struct {
	Installed bool `json:"installed"`
	Running   bool `json:"running"`
}

// API Response Structures

type HealthResponse struct {
	OK      bool   `json:"ok"`
	Version string `json:"version"`
	UptimeS int64  `json:"uptime_s"`
	Ts      int64  `json:"ts"`
}

type StatusResponse struct {
	Overall    string     `json:"overall"`
	LastCheckS int        `json:"last_check_s"`
	VPN        VPNStatus  `json:"vpn"`
	QB         QBStatus   `json:"qb"`
	Disk       DiskStatus `json:"disk"`
	WebUIUrl   string     `json:"webui_url"`
	HostLabel  string     `json:"host_label"`
}

type VPNStatus struct {
	State string `json:"state"`
}

type QBStatus struct {
	State string `json:"state"`
}

type DiskStatus struct {
	Path       string  `json:"path"`
	FreePct    float64 `json:"free_pct"`
	FreeBytes  uint64  `json:"free_bytes"`
	TotalBytes uint64  `json:"total_bytes"`
}

type Torrent struct {
	Name     string  `json:"name"`
	State    string  `json:"state"`
	Progress float64 `json:"progress"`
	DownBps  int64   `json:"down_bps"`
	UpBps    int64   `json:"up_bps"`
	EtaS     int64   `json:"eta_s"`
}

type TorrentsResponse struct {
	Torrents []Torrent `json:"torrents"`
	Summary  struct {
		Active int `json:"active"`
		Seed   int `json:"seed"`
		Error  int `json:"error"`
	} `json:"summary"`
}

// qBittorrent API Client

type QBClient struct {
	baseURL  string
	username string
	password string
	client   *http.Client
	sidMu    sync.RWMutex
	sid      string
}

func NewQBClient(baseURL, username, password string) *QBClient {
	jar, _ := cookiejar.New(nil)
	return &QBClient{
		baseURL:  strings.TrimRight(baseURL, "/"),
		username: username,
		password: password,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Jar:     jar,
		},
	}
}

// Login authenticates with qBittorrent and stores the session cookie
func (q *QBClient) Login() error {
	loginURL := q.baseURL + "/api/v2/auth/login"

	data := url.Values{}
	data.Set("username", q.username)
	data.Set("password", q.password)

	req, err := http.NewRequest("POST", loginURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", q.baseURL)

	resp, err := q.client.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "Ok." {
		return fmt.Errorf("login failed: status %d, body: %s", resp.StatusCode, body)
	}

	// Extract SID cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "SID" {
			q.sidMu.Lock()
			q.sid = cookie.Value
			q.sidMu.Unlock()
			return nil
		}
	}

	return fmt.Errorf("no SID cookie in login response")
}

// doAuthenticatedRequest performs an HTTP request with authentication
func (q *QBClient) doAuthenticatedRequest(method, path string, body io.Reader) (*http.Response, error) {
	fullURL := q.baseURL + path

	req, err := http.NewRequest(method, fullURL, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Add SID cookie
	q.sidMu.RLock()
	sid := q.sid
	q.sidMu.RUnlock()

	if sid != "" {
		req.AddCookie(&http.Cookie{Name: "SID", Value: sid})
	}

	req.Header.Set("Referer", q.baseURL)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := q.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// Handle authentication failure - retry once
	if resp.StatusCode == http.StatusForbidden {
		resp.Body.Close()
		if err := q.Login(); err != nil {
			return nil, fmt.Errorf("re-authentication failed: %w", err)
		}
		// Retry with new session
		return q.doAuthenticatedRequest(method, path, body)
	}

	return resp, nil
}

// Ping checks if qBittorrent is reachable
func (q *QBClient) Ping() error {
	resp, err := q.doAuthenticatedRequest("GET", "/api/v2/app/version", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return nil
}

// qBittorrent torrent info structure
type qbTorrentInfo struct {
	Name     string  `json:"name"`
	State    string  `json:"state"`
	Progress float64 `json:"progress"`
	Dlspeed  int64   `json:"dlspeed"`
	Upspeed  int64   `json:"upspeed"`
	Eta      int64   `json:"eta"`
}

// GetTorrents fetches the torrent list from qBittorrent
func (q *QBClient) GetTorrents(limit int) ([]Torrent, error) {
	path := fmt.Sprintf("/api/v2/torrents/info?limit=%d", limit)
	resp, err := q.doAuthenticatedRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var qbTorrents []qbTorrentInfo
	if err := json.NewDecoder(resp.Body).Decode(&qbTorrents); err != nil {
		return nil, fmt.Errorf("decode torrents: %w", err)
	}

	torrents := make([]Torrent, len(qbTorrents))
	for i, qt := range qbTorrents {
		torrents[i] = Torrent{
			Name:     qt.Name,
			State:    mapQBStateToSimple(qt.State),
			Progress: qt.Progress,
			DownBps:  qt.Dlspeed,
			UpBps:    qt.Upspeed,
			EtaS:     qt.Eta,
		}
		// Normalize infinite ETA
		if torrents[i].EtaS == 8640000 {
			torrents[i].EtaS = -1
		}
	}

	return torrents, nil
}

// mapQBStateToSimple maps qBittorrent states to simplified states
func mapQBStateToSimple(qbState string) string {
	switch qbState {
	case "downloading", "stalledDL", "queuedDL", "forcedDL", "metaDL", "allocating",
		"checkingDL", "checkingResumeData":
		return "downloading"
	case "uploading", "stalledUP", "queuedUP", "forcedUP", "checkingUP":
		return "seeding"
	case "pausedDL", "pausedUP":
		return "paused"
	case "error", "missingFiles", "unknown":
		return "error"
	default:
		return "error"
	}
}

// PauseAll pauses all torrents
func (q *QBClient) PauseAll() error {
	data := url.Values{}
	data.Set("hashes", "all")

	resp, err := q.doAuthenticatedRequest("POST", "/api/v2/torrents/pause", strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return nil
}

// ResumeAll resumes all torrents
func (q *QBClient) ResumeAll() error {
	data := url.Values{}
	data.Set("hashes", "all")

	resp, err := q.doAuthenticatedRequest("POST", "/api/v2/torrents/resume", strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return nil
}

// VPN Health Check

func checkVPNHealth(qbReachable bool, gluetunURL string) string {
	if !qbReachable {
		return "DOWN"
	}

	if gluetunURL != "" {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(gluetunURL)
		if err != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				resp.Body.Close()
			}
			return "DOWN"
		}
		resp.Body.Close()
	}

	return "CONNECTED"
}

// Disk Metrics

func getDiskMetrics(path string) (DiskStatus, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return DiskStatus{}, fmt.Errorf("statfs failed: %w", err)
	}

	totalBytes := stat.Blocks * uint64(stat.Bsize)
	freeBytes := stat.Bavail * uint64(stat.Bsize)
	freePct := (float64(freeBytes) / float64(totalBytes)) * 100

	return DiskStatus{
		Path:       path,
		FreePct:    freePct,
		FreeBytes:  freeBytes,
		TotalBytes: totalBytes,
	}, nil
}

// HTTP Server

type Server struct {
	config      *Config
	qbClient    *QBClient
	startTime   time.Time
	lastCheck   time.Time
	lastCheckMu sync.RWMutex
}

func NewServer(cfg *Config) *Server {
	return &Server{
		config:    cfg,
		qbClient:  NewQBClient(cfg.QBUrl, cfg.QBUsername, cfg.QBPassword),
		startTime: time.Now(),
		lastCheck: time.Now(),
	}
}

// handleUI serves the static HTML UI
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	content, err := htmlContent.ReadFile("dollhouseq.html")
	if err != nil {
		http.Error(w, "UI not found", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(content)
}

// handleHealth returns health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{
		OK:      true,
		Version: version,
		UptimeS: int64(time.Since(s.startTime).Seconds()),
		Ts:      time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleStatus returns system status
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	qbErr := s.qbClient.Ping()
	qbState := "REACHABLE"
	if qbErr != nil {
		qbState = "DOWN"
	}

	vpnState := checkVPNHealth(qbState == "REACHABLE", s.config.GluetunHealthURL)

	disk, diskErr := getDiskMetrics(s.config.DiskPath)

	overall := "OK"
	if qbState == "DOWN" || vpnState == "DOWN" {
		overall = "DOWN"
	} else if diskErr != nil || disk.FreePct < 10 {
		overall = "WARN"
	}

	s.lastCheckMu.Lock()
	s.lastCheck = time.Now()
	s.lastCheckMu.Unlock()

	resp := StatusResponse{
		Overall:    overall,
		LastCheckS: 0,
		VPN:        VPNStatus{State: vpnState},
		QB:         QBStatus{State: qbState},
		Disk:       disk,
		WebUIUrl:   s.config.WebUIUrl,
		HostLabel:  s.config.HostLabel,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleTorrents returns torrent list
func (s *Server) handleTorrents(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
		if limit > 100 {
			limit = 100
		}
		if limit < 1 {
			limit = 1
		}
	}

	torrents, err := s.qbClient.GetTorrents(limit)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch torrents: %v", err), http.StatusServiceUnavailable)
		return
	}

	var active, seed, errorCount int
	for _, t := range torrents {
		switch t.State {
		case "downloading":
			active++
		case "seeding":
			seed++
		case "error":
			errorCount++
		}
	}

	resp := TorrentsResponse{
		Torrents: torrents,
	}
	resp.Summary.Active = active
	resp.Summary.Seed = seed
	resp.Summary.Error = errorCount

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handlePauseAll pauses all torrents
func (s *Server) handlePauseAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := s.qbClient.PauseAll(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to pause: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// handleResumeAll resumes all torrents
func (s *Server) handleResumeAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := s.qbClient.ResumeAll(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to resume: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// System Detection Functions

func detectSystem() DetectionResult {
	return DetectionResult{
		App:       detectApp(),
		Tailscale: detectTailscale(),
		Docker:    detectDocker(),
	}
}

func detectApp() AppDetection {
	return AppDetection{
		Installed: true, // If we're running, we're installed
		Running:   true,
	}
}

func detectTailscale() TailscaleDetection {
	result := TailscaleDetection{}

	// Check if tailscale command exists
	if _, err := exec.LookPath("tailscale"); err != nil {
		return result
	}
	result.Installed = true

	// Check if connected by getting Tailscale IP
	cmd := exec.Command("tailscale", "ip", "-4")
	output, err := cmd.Output()
	if err != nil {
		return result
	}

	tailnetIP := strings.TrimSpace(string(output))
	if tailnetIP != "" {
		result.Connected = true
		result.TailnetIP = tailnetIP

		// Get node name from status
		statusCmd := exec.Command("tailscale", "status", "--json")
		statusOutput, err := statusCmd.Output()
		if err == nil {
			var status struct {
				Self struct {
					DNSName string `json:"DNSName"`
				} `json:"Self"`
			}
			if json.Unmarshal(statusOutput, &status) == nil {
				// DNSName is like "hostname.tailnet-name.ts.net."
				nodeName := strings.TrimSuffix(status.Self.DNSName, ".")
				nodeName = strings.Split(nodeName, ".")[0]
				result.NodeName = nodeName
			}
		}
	}

	return result
}

func detectDocker() DockerDetection {
	result := DockerDetection{}

	// Check if docker command exists
	if _, err := exec.LookPath("docker"); err != nil {
		return result
	}
	result.Installed = true

	// Check if docker is running
	cmd := exec.Command("docker", "info")
	if err := cmd.Run(); err == nil {
		result.Running = true
	}

	return result
}

// Config persistence helpers

var configPathOverride string

func setConfigPath(path string) {
	configPathOverride = path
}

func getConfigPath() string {
	if configPathOverride != "" {
		return configPathOverride
	}
	return "/etc/dollhouse-q/config.json"
}

func saveConfig(cfg *Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	// Write to temp file first, then rename (atomic)
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("rename config: %w", err)
	}

	return nil
}

// handleWizard serves the wizard UI
func (s *Server) handleWizard(w http.ResponseWriter, r *http.Request) {
	content, err := htmlContent.ReadFile("wizard.html")
	if err != nil {
		http.Error(w, "Wizard UI not found", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(content)
}

// handleWizardDetect performs system detection
func (s *Server) handleWizardDetect(w http.ResponseWriter, r *http.Request) {
	result := detectSystem()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleWizardConfigure saves wizard configuration
func (s *Server) handleWizardConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var updates Config
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Merge updates into current config
	if updates.QBUrl != "" {
		s.config.QBUrl = updates.QBUrl
	}
	if updates.QBUsername != "" {
		s.config.QBUsername = updates.QBUsername
	}
	if updates.QBPassword != "" {
		s.config.QBPassword = updates.QBPassword
	}
	if updates.WebUIUrl != "" {
		s.config.WebUIUrl = updates.WebUIUrl
	}
	if updates.Server.BindMode != "" {
		s.config.Server.BindMode = updates.Server.BindMode
	}
	if updates.Server.BindAddr != "" {
		s.config.Server.BindAddr = updates.Server.BindAddr
		s.config.ListenAddr = updates.Server.BindAddr
	}
	if updates.Tailscale.Enabled {
		s.config.Tailscale = updates.Tailscale
	}
	if updates.Docker.Enabled {
		s.config.Docker = updates.Docker
	}

	s.config.WizardCompleted = true

	// Save config to disk
	if err := saveConfig(s.config, getConfigPath()); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save config: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true, "restarting": true})

	// Re-exec ourselves after a short delay so the response is sent first.
	// The new process will read the updated config from disk.
	go func() {
		time.Sleep(500 * time.Millisecond)
		self, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "restart: cannot find executable: %v\n", err)
			return
		}
		fmt.Println("Restarting with updated config...")
		cmd := exec.Command(self, getConfigPath())
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "restart: %v\n", err)
			return
		}
		os.Exit(0)
	}()
}

// setupRoutes configures HTTP routes
func (s *Server) setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	// Redirect to wizard if needed
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if s.config.NeedsWizard() && r.URL.Path == "/" {
			http.Redirect(w, r, "/wizard", http.StatusTemporaryRedirect)
			return
		}
		s.handleUI(w, r)
	})

	mux.HandleFunc("/wizard", s.handleWizard)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/torrents", s.handleTorrents)
	mux.HandleFunc("/actions/pause_all", s.handlePauseAll)
	mux.HandleFunc("/actions/resume_all", s.handleResumeAll)
	mux.HandleFunc("/api/wizard/detect", s.handleWizardDetect)
	mux.HandleFunc("/api/wizard/configure", s.handleWizardConfigure)

	return mux
}

// Main

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.SetDefaults()
	// Skip validation if wizard is needed — creds will be set during setup
	if !cfg.NeedsWizard() {
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("invalid config: %w", err)
		}
	}

	return &cfg, nil
}

func main() {
	configPath := "/etc/dollhouse-q/config.json"
	if len(os.Args) > 1 {
		if os.Args[1] == "-h" || os.Args[1] == "--help" {
			fmt.Printf("Dollhouse q v%s\n", version)
			fmt.Println("Usage: dollhouse-q [config-path]")
			fmt.Println("Default config: /etc/dollhouse-q/config.json")
			os.Exit(0)
		}
		configPath = os.Args[1]
	}

	setConfigPath(configPath)

	cfg, err := loadConfig(configPath)
	if err != nil {
		// If config doesn't exist, create a minimal one for wizard
		if errors.Is(err, os.ErrNotExist) {
			cfg = &Config{}
			cfg.SetDefaults()
		} else {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}
	}

	server := NewServer(cfg)

	// Skip qBittorrent login if wizard is needed
	if !cfg.NeedsWizard() {
		if err := server.qbClient.Login(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to authenticate with qBittorrent: %v\n", err)
			fmt.Fprintln(os.Stderr, "Continuing anyway - will retry on first request")
		}
	}

	mux := server.setupRoutes()
	httpServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	fmt.Printf("Dollhouse q v%s starting on %s\n", version, cfg.ListenAddr)
	if err := httpServer.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
