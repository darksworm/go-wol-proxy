package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh"
)

// Interfaces for dependency injection
type HealthChecker interface {
	Check(ctx context.Context, endpoint string) bool
	StartBackgroundChecks(ctx context.Context, targets map[string]*TargetState, interval time.Duration)
	WaitForInitialChecks(ctx context.Context) error
}

type WOLSender interface {
	SendWOL(macAddr, broadcastIP string, port int) error
}

type SSHExecutor interface {
	ExecuteCommand(host, user, keyPath, command string) error
}

type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// Config structs
type Config struct {
	Port                string   `toml:"port"`
	Timeout             string   `toml:"timeout"`
	PollInterval        string   `toml:"poll_interval"`
	HealthCheckInterval string   `toml:"health_check_interval"`
	HealthCacheDuration string   `toml:"health_cache_duration"`
	Targets             []Target `toml:"targets"`
	SSLCertificate      string   `toml:"ssl_certificate"`
	SSLCertificateKey   string   `toml:"ssl_certificate_key"`
}

type Target struct {
	Name                string `toml:"name"`
	Hostname            string `toml:"hostname"`
	Destination         string `toml:"destination"`
	HealthEndpoint      string `toml:"health_endpoint"`
	MacAddress          string `toml:"mac_address"`
	BroadcastIP         string `toml:"broadcast_ip"`
	WolPort             int    `toml:"wol_port"`
	SSHHost             string `toml:"ssh_host"`
	SSHUser             string `toml:"ssh_user"`
	SSHKeyPath          string `toml:"ssh_key_path"`
	ShutdownCommand     string `toml:"shutdown_command"`
	InactivityThreshold string `toml:"inactivity_threshold"`
}

type ProxyConfig struct {
	Port                 string
	Timeout              time.Duration
	PollInterval         time.Duration
	HealthCheckInterval  time.Duration
	HealthCacheDuration  time.Duration
	Targets              map[string]*TargetState
	HostnameMap          map[string]string        // hostname -> target name
	InactivityThresholds map[string]time.Duration // target name -> inactivity threshold
	SSLCertificate       string
	SSLCertificateKey    string
}

type TargetState struct {
	Target       *Target
	IsHealthy    bool
	LastCheck    time.Time
	IsWaking     bool
	LastActivity time.Time
	mu           sync.RWMutex
}

// HTTP Health Checker implementation
type HTTPHealthChecker struct {
	client           *http.Client
	logger           Logger
	initialCheckDone map[string]bool
	initialCheckMu   sync.RWMutex
	initialWaitGroup sync.WaitGroup
}

func NewHTTPHealthChecker(logger Logger) *HTTPHealthChecker {
	return &HTTPHealthChecker{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		logger:           logger,
		initialCheckDone: make(map[string]bool),
	}
}

func (h *HTTPHealthChecker) Check(ctx context.Context, endpoint string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return false
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func (h *HTTPHealthChecker) StartBackgroundChecks(ctx context.Context, targets map[string]*TargetState, interval time.Duration) {
	for name, target := range targets {
		h.initialWaitGroup.Add(1)
		go h.backgroundCheck(ctx, name, target, interval)
	}
}

func (h *HTTPHealthChecker) WaitForInitialChecks(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		h.initialWaitGroup.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *HTTPHealthChecker) backgroundCheck(ctx context.Context, name string, target *TargetState, interval time.Duration) {
	// Perform initial check
	h.performCheck(name, target)
	h.markInitialCheckDone(name)
	h.initialWaitGroup.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.performCheck(name, target)
		}
	}
}

func (h *HTTPHealthChecker) performCheck(name string, target *TargetState) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	healthy := h.Check(ctx, target.Target.HealthEndpoint)

	target.mu.Lock()
	previousHealth := target.IsHealthy
	target.IsHealthy = healthy
	target.LastCheck = time.Now()
	target.mu.Unlock()

	if healthy != previousHealth {
		status := "DOWN"
		if healthy {
			status = "UP"
		}
		h.logger.Info("Health check for %s (%s): %s", name, target.Target.Hostname, status)
	}
}

func (h *HTTPHealthChecker) markInitialCheckDone(name string) {
	h.initialCheckMu.Lock()
	defer h.initialCheckMu.Unlock()
	h.initialCheckDone[name] = true
}

// Wake-on-LAN sender implementation
type UDPWOLSender struct {
	logger Logger
}

func NewUDPWOLSender(logger Logger) *UDPWOLSender {
	return &UDPWOLSender{logger: logger}
}

// SSH command executor implementation
type DefaultSSHExecutor struct {
	logger Logger
}

func NewDefaultSSHExecutor(logger Logger) *DefaultSSHExecutor {
	return &DefaultSSHExecutor{logger: logger}
}

func (s *DefaultSSHExecutor) ExecuteCommand(host, user, keyPath, command string) error {
	// Read private key
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("unable to read private key: %w", err)
	}

	// Create signer
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("unable to parse private key: %w", err)
	}

	// Configure SSH client
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// Connect to SSH server
	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		return fmt.Errorf("unable to connect to SSH server: %w", err)
	}
	defer client.Close()

	// Create session
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("unable to create SSH session: %w", err)
	}
	defer session.Close()

	// Execute command
	s.logger.Info("Executing SSH command on %s@%s: %s", user, host, command)
	output, err := session.CombinedOutput(command)
	if err != nil {
		return fmt.Errorf("command execution failed: %w, output: %s", err, string(output))
	}

	s.logger.Info("SSH command executed successfully on %s@%s, output: %s", user, host, string(output))
	return nil
}

func (w *UDPWOLSender) SendWOL(macAddr, broadcastIP string, port int) error {
	// Parse MAC address
	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		return fmt.Errorf("invalid MAC address: %w", err)
	}

	// Create magic packet
	packet := w.createMagicPacket(mac)

	// Send UDP packet
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", broadcastIP, port))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to dial UDP: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to send WOL packet: %w", err)
	}

	w.logger.Info("WOL packet sent to %s via %s:%d", macAddr, broadcastIP, port)
	return nil
}

func (w *UDPWOLSender) createMagicPacket(mac net.HardwareAddr) []byte {
	var packet bytes.Buffer

	// 6 bytes of 0xFF
	for i := 0; i < 6; i++ {
		packet.WriteByte(0xFF)
	}

	// 16 repetitions of the MAC address
	for i := 0; i < 16; i++ {
		packet.Write(mac)
	}

	return packet.Bytes()
}

// Main proxy service
type ProxyService struct {
	config        *ProxyConfig
	healthChecker HealthChecker
	wolSender     WOLSender
	sshExecutor   SSHExecutor
	logger        Logger
}

func NewProxyService(
	config *ProxyConfig,
	healthChecker HealthChecker,
	wolSender WOLSender,
	sshExecutor SSHExecutor,
	logger Logger,
) *ProxyService {
	return &ProxyService{
		config:        config,
		healthChecker: healthChecker,
		wolSender:     wolSender,
		sshExecutor:   sshExecutor,
		logger:        logger,
	}
}

func (p *ProxyService) shutdownTarget(targetName string) error {
	targetState, exists := p.config.Targets[targetName]
	if !exists {
		return fmt.Errorf("unknown target: %s", targetName)
	}

	target := targetState.Target
	if target.SSHHost == "" || target.SSHUser == "" || target.SSHKeyPath == "" || target.ShutdownCommand == "" {
		return fmt.Errorf("target %s is missing SSH configuration or shutdown command", targetName)
	}

	p.logger.Info("Shutting down target %s (%s) due to inactivity", targetName, target.Hostname)
	err := p.sshExecutor.ExecuteCommand(target.SSHHost, target.SSHUser, target.SSHKeyPath, target.ShutdownCommand)
	if err != nil {
		p.logger.Error("Failed to shut down target %s: %v", targetName, err)
		return err
	}

	// Mark the target as unhealthy after shutdown
	targetState.mu.Lock()
	targetState.IsHealthy = false
	targetState.mu.Unlock()

	p.logger.Info("Target %s (%s) has been shut down", targetName, target.Hostname)
	return nil
}

func (p *ProxyService) startInactivityMonitor(ctx context.Context) {
	// Check every 10 seconds for inactive targets
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.checkInactiveTargets()
		}
	}
}

func (p *ProxyService) checkInactiveTargets() {
	now := time.Now()

	for name, targetState := range p.config.Targets {
		// Skip targets without inactivity threshold
		threshold, exists := p.config.InactivityThresholds[name]
		if !exists {
			continue
		}

		// Skip targets that are not healthy (already down)
		targetState.mu.RLock()
		isHealthy := targetState.IsHealthy
		lastActivity := targetState.LastActivity
		targetState.mu.RUnlock()

		if !isHealthy {
			continue
		}

		// Check if the target has been inactive for too long
		inactiveDuration := now.Sub(lastActivity)
		if inactiveDuration > threshold {
			p.logger.Info("Target %s has been inactive for %v (threshold: %v), shutting down",
				name, inactiveDuration.Round(time.Second), threshold)

			if err := p.shutdownTarget(name); err != nil {
				p.logger.Error("Failed to shut down inactive target %s: %v", name, err)
			}
		}
	}
}

func isSecureServer(config *ProxyConfig) bool {
	return config.SSLCertificate != "" && config.SSLCertificateKey != ""
}

func (p *ProxyService) Start(ctx context.Context) error {
	// Start background health checks
	p.healthChecker.StartBackgroundChecks(
		ctx,
		p.config.Targets,
		p.config.HealthCheckInterval,
	)

	// Wait for initial health checks to complete
	p.logger.Info("Waiting for initial health checks to complete...")
	if err := p.healthChecker.WaitForInitialChecks(ctx); err != nil {
		return fmt.Errorf("initial health checks failed: %w", err)
	}

	// Start background inactivity monitor
	go p.startInactivityMonitor(ctx)

	p.logger.Info("Initial health checks completed, starting HTTP server")

	// Log configured targets
	for name, target := range p.config.Targets {
		p.logger.Info("Configured target: %s -> %s (%s)",
			target.Target.Hostname, name, target.Target.Destination)
	}

	// Start HTTP/HTTPS server
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.handleRequest)

	server := &http.Server{
		Addr:              p.config.Port,
		Handler:           mux,
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       120 * time.Second, // 2 minutes for keep-alive connections
		ReadHeaderTimeout: 30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	if isSecureServer(p.config) {
		// Use HTTPS when both certificate and key are provided
		tlsConfig := &tls.Config{
			Certificates: make([]tls.Certificate, 1),
		}

		cert, err := tls.LoadX509KeyPair(p.config.SSLCertificate, p.config.SSLCertificateKey)
		if err != nil {
			return fmt.Errorf("failed to load SSL certificate: %w", err)
		}
		tlsConfig.Certificates[0] = cert
		server.TLSConfig = tlsConfig

		p.logger.Info("HTTPS server listening on %s with SSL certificates", p.config.Port)
		//The files in these methods are ignored since there is already a certificate in the config.
		return server.ListenAndServeTLS("", "")
	} else {
		p.logger.Info("HTTP server listening on %s", p.config.Port)
		return server.ListenAndServe()
	}
}

func (p *ProxyService) handleRequest(w http.ResponseWriter, r *http.Request) {
	targetName := p.extractTarget(r)

	if targetName == "" {
		p.logger.Error("No target found for hostname: %s", r.Host)
		http.Error(w, "No target configured for this hostname", http.StatusNotFound)
		return
	}

	p.logger.Info("Incoming request for hostname: %s -> target: %s, path: %s",
		r.Host, targetName, r.URL.Path)

	targetState, exists := p.config.Targets[targetName]
	if !exists {
		p.logger.Error("Unknown target: %s", targetName)
		http.Error(w, "Target not found", http.StatusNotFound)
		return
	}

	// Check if we have fresh health data
	if p.isHealthyCached(targetState) {
		p.logger.Info("Target %s is healthy, proxying immediately", targetName)
		p.proxyRequest(w, r, targetState.Target)
		return
	}

	// Need to wake up the server
	p.logger.Info("Target %s appears down, attempting to wake", targetName)
	if err := p.wakeAndWait(r.Context(), targetState); err != nil {
		p.logger.Error("Failed to wake target %s: %v", targetName, err)
		http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}

	p.logger.Info("Target %s is now healthy, proxying request", targetName)
	p.proxyRequest(w, r, targetState.Target)
}

func (p *ProxyService) extractTarget(r *http.Request) string {
	// Remove port from host if present
	host := r.Host
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	// Look up target by hostname
	if targetName, exists := p.config.HostnameMap[host]; exists {
		return targetName
	}

	return ""
}

func (p *ProxyService) isHealthyCached(target *TargetState) bool {
	target.mu.RLock()
	defer target.mu.RUnlock()

	if !target.IsHealthy {
		return false
	}

	return time.Since(target.LastCheck) <= p.config.HealthCacheDuration
}

func (p *ProxyService) wakeAndWait(ctx context.Context, target *TargetState) error {
	target.mu.Lock()
	if target.IsWaking {
		target.mu.Unlock()
		return p.waitForWake(ctx, target)
	}

	target.IsWaking = true
	target.mu.Unlock()

	err := p.wolSender.SendWOL(
		target.Target.MacAddress,
		target.Target.BroadcastIP,
		target.Target.WolPort,
	)

	target.mu.Lock()
	target.LastActivity = time.Now()
	target.IsWaking = false
	target.mu.Unlock()

	if err != nil {
		return fmt.Errorf("failed to send WOL: %w", err)
	}

	p.logger.Info("WOL packet sent to %s (%s), waiting for server to wake",
		target.Target.Name, target.Target.Hostname)

	return p.waitForWake(ctx, target)
}

func (p *ProxyService) waitForWake(ctx context.Context, target *TargetState) error {
	timeout := time.After(p.config.Timeout)
	healthCheckTicker := time.NewTicker(p.config.PollInterval)
	defer healthCheckTicker.Stop()

	// Create a separate ticker for sending WOL packets
	// Send a packet once per second
	wolTicker := time.NewTicker(500 * time.Millisecond)
	defer wolTicker.Stop()

	wakeStartTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			target.mu.Lock()
			target.IsWaking = false
			target.mu.Unlock()
			return fmt.Errorf("timeout waiting for %s to wake up after %v",
				target.Target.Name, p.config.Timeout)
		case <-wolTicker.C:
			// Send additional WOL packets while waiting
			err := p.wolSender.SendWOL(
				target.Target.MacAddress,
				target.Target.BroadcastIP,
				target.Target.WolPort,
			)
			if err != nil {
				p.logger.Error("Failed to send additional WOL packet: %v", err)
				// Continue waiting even if a packet fails to send
			} else {
				p.logger.Info("Sent additional WOL packet to %s (%s)",
					target.Target.Name, target.Target.Hostname)
			}
		case <-healthCheckTicker.C:
			if p.healthChecker.Check(ctx, target.Target.HealthEndpoint) {
				target.mu.Lock()
				target.IsHealthy = true
				target.LastCheck = time.Now()
				target.IsWaking = false
				target.mu.Unlock()

				wakeDuration := time.Since(wakeStartTime)
				p.logger.Info("Target %s (%s) woke up after %v",
					target.Target.Name, target.Target.Hostname, wakeDuration)
				return nil
			}
		}

		target.mu.Lock()
		target.IsWaking = false
		target.mu.Unlock()
	}
}

func (p *ProxyService) proxyRequest(w http.ResponseWriter, r *http.Request, target *Target) {
	if targetState, exists := p.config.Targets[target.Name]; exists {
		targetState.mu.Lock()
		targetState.LastActivity = time.Now()
		targetState.mu.Unlock()
	}

	targetURL, err := url.Parse(target.Destination)
	if err != nil {
		p.logger.Error("Invalid target URL %s: %v", target.Destination, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Create a custom transport with optimized settings for large uploads
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   60 * time.Second, // Increased timeout for slow connections
			KeepAlive: 60 * time.Second, // Increased keep-alive
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       120 * time.Second, // Increased idle timeout
		TLSHandshakeTimeout:   20 * time.Second,  // Increased TLS handshake timeout
		ExpectContinueTimeout: 5 * time.Second,   // Increased expect-continue timeout
		MaxIdleConnsPerHost:   10,
		// Disable compression to avoid issues with already compressed data
		DisableCompression: true,
		// Increase response header timeout
		ResponseHeaderTimeout: 60 * time.Second, // Increased response header timeout
		// No timeout for reading the entire response
		ReadBufferSize:  1024 * 1024, // 1MB buffer for reading
		WriteBufferSize: 1024 * 1024, // 1MB buffer for writing
	}

	// Customize the proxy to handle errors and logging
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Set the Host header to the target's hostname from the URL
		req.Host = targetURL.Host

		// Log request details including content length for debugging
		contentLength := req.ContentLength
		contentType := req.Header.Get("Content-Type")
		p.logger.Info("Proxying %s %s to %s (Host: %s, Content-Length: %d, Content-Type: %s)",
			req.Method, req.URL.Path, targetURL, req.Host, contentLength, contentType)

		// For large uploads, add special handling
		if contentLength > 1024*1024 { // If larger than 1MB
			p.logger.Info("Large upload detected (%d bytes) for %s %s",
				contentLength, req.Method, req.URL.Path)
		}
	}

	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		p.logger.Error("Proxy error for %s (%s): %v", target.Name, target.Hostname, err)
		http.Error(rw, "Bad Gateway", http.StatusBadGateway)
	}

	// Disable buffering of response body for streaming uploads/downloads
	proxy.ModifyResponse = func(resp *http.Response) error {
		p.logger.Info("Response from %s: status=%d, content-length=%d",
			target.Name, resp.StatusCode, resp.ContentLength)
		return nil
	}

	proxy.ServeHTTP(w, r)
}

// Config loader
func LoadConfig(filename string) (*ProxyConfig, error) {
	var config Config
	_, err := toml.DecodeFile(filename, &config)
	if err != nil {
		return nil, err
	}

	// Trim whitespace and handle optional SSL certificate fields
	config.SSLCertificate = strings.TrimSpace(config.SSLCertificate)
	config.SSLCertificateKey = strings.TrimSpace(config.SSLCertificateKey)

	// Set defaults
	if config.Port == "" {
		config.Port = ":8080"
	}
	if !strings.HasPrefix(config.Port, ":") {
		config.Port = ":" + config.Port
	}

	timeout, err := time.ParseDuration(config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("invalid timeout: %w", err)
	}

	pollInterval, err := time.ParseDuration(config.PollInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid poll_interval: %w", err)
	}

	healthCheckInterval, err := time.ParseDuration(config.HealthCheckInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid health_check_interval: %w", err)
	}

	healthCacheDuration, err := time.ParseDuration(config.HealthCacheDuration)
	if err != nil {
		return nil, fmt.Errorf("invalid health_cache_duration: %w", err)
	}

	targets := make(map[string]*TargetState)
	hostnameMap := make(map[string]string)
	inactivityThresholds := make(map[string]time.Duration)

	for _, target := range config.Targets {
		if target.Hostname == "" {
			return nil, fmt.Errorf("target %s is missing hostname", target.Name)
		}

		// Check for duplicate hostnames
		if existingTarget, exists := hostnameMap[target.Hostname]; exists {
			return nil, fmt.Errorf("duplicate hostname %s for targets %s and %s",
				target.Hostname, existingTarget, target.Name)
		}

		// Parse inactivity threshold if provided
		if target.InactivityThreshold != "" {
			inactivityThreshold, err := time.ParseDuration(target.InactivityThreshold)
			if err != nil {
				return nil, fmt.Errorf("invalid inactivity_threshold for target %s: %w", target.Name, err)
			}
			inactivityThresholds[target.Name] = inactivityThreshold
		}

		targetCopy := target
		targets[target.Name] = &TargetState{
			Target:       &targetCopy,
			LastActivity: time.Now(), // Initialize with current time
		}
		hostnameMap[target.Hostname] = target.Name
	}

	return &ProxyConfig{
		Port:                 config.Port,
		SSLCertificate:       config.SSLCertificate,
		SSLCertificateKey:    config.SSLCertificateKey,
		Timeout:              timeout,
		PollInterval:         pollInterval,
		HealthCheckInterval:  healthCheckInterval,
		HealthCacheDuration:  healthCacheDuration,
		Targets:              targets,
		HostnameMap:          hostnameMap,
		InactivityThresholds: inactivityThresholds,
	}, nil
}

// Simple logger implementation
type StdLogger struct{}

func (l *StdLogger) Info(msg string, args ...interface{}) {
	log.Printf("[INFO] "+msg, args...)
}

func (l *StdLogger) Error(msg string, args ...interface{}) {
	log.Printf("[ERROR] "+msg, args...)
}

// Main function
func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: wol-proxy <config.toml>")
	}

	configFile := os.Args[1]

	// Load configuration
	config, err := LoadConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize dependencies
	logger := &StdLogger{}
	healthChecker := NewHTTPHealthChecker(logger)
	wolSender := NewUDPWOLSender(logger)
	sshExecutor := NewDefaultSSHExecutor(logger)

	// Create proxy service
	proxy := NewProxyService(config, healthChecker, wolSender, sshExecutor, logger)

	// Start the service
	ctx := context.Background()
	if err := proxy.Start(ctx); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}
