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
	Check(ctx context.Context, endpoint string, source string) bool
	StartBackgroundChecks(ctx context.Context, machines map[string]*MachineState, interval time.Duration)
	WaitForInitialChecks(ctx context.Context) error
	CloseIdleConnections()
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

type Ticker interface {
	C() <-chan time.Time
	Stop()
}

type Clock interface {
	Now() time.Time
	NewTicker(d time.Duration) Ticker
	After(d time.Duration) <-chan time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time                         { return time.Now() }
func (RealClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
func (RealClock) NewTicker(d time.Duration) Ticker       { return &realTicker{time.NewTicker(d)} }

type realTicker struct{ t *time.Ticker }

func (r *realTicker) C() <-chan time.Time { return r.t.C }
func (r *realTicker) Stop()               { r.t.Stop() }

// Config structs
type Config struct {
	Port                  string   `toml:"port"`
	Timeout               string   `toml:"timeout"`
	ResponseHeaderTimeout string   `toml:"response_header_timeout"`
	PollInterval          string   `toml:"poll_interval"`
	HealthCheckInterval   string   `toml:"health_check_interval"`
	HealthCacheDuration   string   `toml:"health_cache_duration"`
	SSLCertificate        string   `toml:"ssl_certificate"`
	SSLCertificateKey     string   `toml:"ssl_certificate_key"`
	Targets               []Target `toml:"targets"`
}

type Target struct {
	Name                 string `toml:"name"`
	Hostname             string `toml:"hostname"`
	Destination          string `toml:"destination"`
	HealthEndpoint       string `toml:"health_endpoint"`
	MacAddress           string `toml:"mac_address"`
	BroadcastIP          string `toml:"broadcast_ip"`
	WolPort              int    `toml:"wol_port"`
	SSHHost              string `toml:"ssh_host"`
	SSHUser              string `toml:"ssh_user"`
	SSHKeyPath           string `toml:"ssh_key_path"`
	ShutdownCommand      string `toml:"shutdown_command"`
	ShutdownHTTPUrl      string `toml:"shutdown_http_url"`
	ShutdownHTTPMethod   string `toml:"shutdown_http_method"`
	ShutdownHTTPOKStatus int    `toml:"shutdown_http_ok_status"`
	InactivityThreshold  string `toml:"inactivity_threshold"`
}

// Machine is a host that is woken, health-checked and shut down as one unit,
// however many routes point at it.
type Machine struct {
	Name                 string
	MacAddress           string
	BroadcastIP          string
	WolPort              int
	HealthCheck          string
	SSHHost              string
	SSHUser              string
	SSHKeyPath           string
	ShutdownCommand      string
	ShutdownHTTPUrl      string
	ShutdownHTTPMethod   string
	ShutdownHTTPOKStatus int
	InactivityThreshold  time.Duration
}

// Route is one way in to a machine.
type Route struct {
	Name        string
	Machine     *MachineState
	Hostname    string
	Destination string
}

type ProxyConfig struct {
	Port                  string
	Timeout               time.Duration
	ResponseHeaderTimeout time.Duration
	PollInterval          time.Duration
	HealthCheckInterval   time.Duration
	HealthCacheDuration   time.Duration
	Machines              map[string]*MachineState
	Routes                []*Route
	RoutesByHostname      map[string]*Route
	SSLCertificate        string
	SSLCertificateKey     string
}

type MachineState struct {
	Machine      *Machine
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
	clock            Clock
	initialCheckDone map[string]bool
	initialCheckMu   sync.RWMutex
	initialWaitGroup sync.WaitGroup
}

func NewHTTPHealthChecker(logger Logger, clock Clock) *HTTPHealthChecker {
	transport := &http.Transport{
		DisableKeepAlives: true,
	}
	return &HTTPHealthChecker{
		client: &http.Client{
			Timeout:   5 * time.Second,
			Transport: transport,
		},
		logger:           logger,
		clock:            clock,
		initialCheckDone: make(map[string]bool),
	}
}

func (h *HTTPHealthChecker) CloseIdleConnections() {
	if transport, ok := h.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (h *HTTPHealthChecker) Check(ctx context.Context, endpoint string, source string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		h.logger.Info("Health check (%s) failed for %s: %v", source, endpoint, err)
		return false
	}

	resp, err := h.client.Do(req)
	if err != nil {
		h.logger.Info("Health check (%s) failed for %s: %v", source, endpoint, err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		h.logger.Info("Health check (%s) failed for %s: status %d", source, endpoint, resp.StatusCode)
		return false
	}

	return true
}

func (h *HTTPHealthChecker) StartBackgroundChecks(ctx context.Context, machines map[string]*MachineState, interval time.Duration) {
	for name, machine := range machines {
		h.initialWaitGroup.Add(1)
		go h.backgroundCheck(ctx, name, machine, interval)
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

func (h *HTTPHealthChecker) backgroundCheck(ctx context.Context, name string, machine *MachineState, interval time.Duration) {
	// Perform initial check
	h.performCheck(name, machine)
	h.markInitialCheckDone(name)
	h.initialWaitGroup.Done()

	ticker := h.clock.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			h.performCheck(name, machine)
		}
	}
}

func (h *HTTPHealthChecker) performCheck(name string, machine *MachineState) {
	machine.mu.RLock()
	isWaking := machine.IsWaking
	machine.mu.RUnlock()
	if isWaking {
		h.logger.Info("Background health check for %s (%s) running while wake is in progress",
			name, machine.Machine.HealthCheck)
	}

	checkStarted := h.clock.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	healthy := h.Check(ctx, machine.Machine.HealthCheck, "background")

	machine.mu.Lock()
	previousHealth := machine.IsHealthy
	machine.IsHealthy = healthy
	machine.LastCheck = h.clock.Now()
	machine.mu.Unlock()

	if healthy != previousHealth {
		status := "DOWN"
		if healthy {
			status = "UP"
		}
		h.logger.Info("Health check for %s (%s): %s", name, machine.Machine.HealthCheck, status)
	}

	if !healthy && previousHealth {
		h.logger.Info(
			"Background health check for %s (%s): downgrading healthy to unhealthy (check took %v)",
			name, machine.Machine.HealthCheck, h.clock.Now().Sub(checkStarted).Round(time.Millisecond),
		)
	}

	if !healthy {
		h.CloseIdleConnections()
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
	clock         Clock
}

func NewProxyService(
	config *ProxyConfig,
	healthChecker HealthChecker,
	wolSender WOLSender,
	sshExecutor SSHExecutor,
	logger Logger,
	clock Clock,
) *ProxyService {
	return &ProxyService{
		config:        config,
		healthChecker: healthChecker,
		wolSender:     wolSender,
		sshExecutor:   sshExecutor,
		logger:        logger,
		clock:         clock,
	}
}

func (p *ProxyService) shutdownMachine(machineName string) error {
	machineState, exists := p.config.Machines[machineName]
	if !exists {
		return fmt.Errorf("unknown machine: %s", machineName)
	}

	machine := machineState.Machine
	if (machine.SSHHost == "" || machine.SSHUser == "" || machine.SSHKeyPath == "" || machine.ShutdownCommand == "") && machine.ShutdownHTTPUrl == "" {
		return fmt.Errorf("machine %s is missing SSH configuration or shutdown command or shutdown HTTP URL", machineName)
	}

	p.logger.Info("Shutting down machine %s due to inactivity", machineName)
	if machine.ShutdownHTTPUrl != "" {
		// Attempt to shut down via HTTP request
		method := machine.ShutdownHTTPMethod
		if method == "" {
			method = "POST" // Default to POST if not specified
		}

		req, err := http.NewRequest(method, machine.ShutdownHTTPUrl, nil)
		if err != nil {
			return fmt.Errorf("failed to create shutdown request: %w", err)
		}

		// Send the request
		client := &http.Client{
			Timeout: 10 * time.Second,
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send shutdown request: %w", err)
		}
		defer resp.Body.Close()

		// Accept any 2xx status by default; allow explicit status override
		if machine.ShutdownHTTPOKStatus != 0 {
			if resp.StatusCode != machine.ShutdownHTTPOKStatus {
				return fmt.Errorf("shutdown request failed with status: %s", resp.Status)
			}
		} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("shutdown request failed with status: %s", resp.Status)
		}

	} else {
		err := p.sshExecutor.ExecuteCommand(machine.SSHHost, machine.SSHUser, machine.SSHKeyPath, machine.ShutdownCommand)
		if err != nil {
			p.logger.Error("Failed to shut down machine %s: %v", machineName, err)
			return err
		}
	}

	// Mark the machine as unhealthy after shutdown
	machineState.mu.Lock()
	machineState.IsHealthy = false
	machineState.mu.Unlock()
	p.healthChecker.CloseIdleConnections()

	p.logger.Info("Machine %s has been shut down", machineName)
	return nil
}

func (p *ProxyService) startInactivityMonitor(ctx context.Context) {
	// Check every 10 seconds for inactive machines
	ticker := p.clock.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			p.checkInactiveMachines()
		}
	}
}

func (p *ProxyService) checkInactiveMachines() {
	now := p.clock.Now()

	for name, machineState := range p.config.Machines {
		// Skip machines without inactivity threshold
		threshold := machineState.Machine.InactivityThreshold
		if threshold == 0 {
			continue
		}

		// Skip machines that are not healthy (already down)
		machineState.mu.RLock()
		isHealthy := machineState.IsHealthy
		lastActivity := machineState.LastActivity
		machineState.mu.RUnlock()

		if !isHealthy {
			continue
		}

		// Check if the machine has been inactive for too long
		inactiveDuration := now.Sub(lastActivity)
		if inactiveDuration > threshold {
			p.logger.Info("Machine %s has been inactive for %v (threshold: %v), shutting down",
				name, inactiveDuration.Round(time.Second), threshold)

			if err := p.shutdownMachine(name); err != nil {
				p.logger.Error("Failed to shut down inactive machine %s: %v", name, err)
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
		p.config.Machines,
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

	// Log configured routes
	for _, route := range p.config.Routes {
		p.logger.Info("Configured route: %s -> %s (%s)",
			route.Hostname, route.Machine.Machine.Name, route.Destination)
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
	route := p.routeForRequest(r)

	if route == nil {
		p.logger.Error("No route found for hostname: %s", r.Host)
		http.Error(w, "No route configured for this hostname", http.StatusNotFound)
		return
	}

	machineState := route.Machine
	machineName := machineState.Machine.Name

	p.logger.Info("Incoming request for hostname: %s -> machine: %s, path: %s",
		r.Host, machineName, r.URL.Path)

	// Check if we have fresh health data
	cached, reason := p.healthCacheStatus(machineState)
	if cached {
		p.logger.Info("Machine %s is healthy, proxying immediately", machineName)
		p.proxyRequest(w, r, route)
		return
	}

	// Need to wake up the server
	p.logger.Info("Machine %s appears down (%s), attempting to wake", machineName, reason)
	p.healthChecker.CloseIdleConnections()
	if err := p.wakeAndWait(r.Context(), machineState); err != nil {
		p.logger.Error("Failed to wake machine %s: %v", machineName, err)
		http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}

	p.logger.Info("Machine %s is now healthy, proxying request", machineName)
	p.proxyRequest(w, r, route)
}

func (p *ProxyService) routeForRequest(r *http.Request) *Route {
	// Remove port from host if present
	host := r.Host
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	return p.config.RoutesByHostname[host]
}

func (p *ProxyService) healthCacheStatus(machine *MachineState) (cached bool, reason string) {
	machine.mu.RLock()
	defer machine.mu.RUnlock()

	if !machine.IsHealthy {
		if machine.LastCheck.IsZero() {
			return false, "no prior health check"
		}
		return false, fmt.Sprintf(
			"marked unhealthy (last check %v ago)",
			p.clock.Now().Sub(machine.LastCheck).Round(time.Second),
		)
	}

	age := p.clock.Now().Sub(machine.LastCheck)
	if age > p.config.HealthCacheDuration {
		return false, fmt.Sprintf(
			"cached health expired (last check %v ago, cache duration %v)",
			age.Round(time.Second), p.config.HealthCacheDuration,
		)
	}

	return true, ""
}

func (p *ProxyService) wakeAndWait(ctx context.Context, machine *MachineState) error {
	machine.mu.Lock()
	if machine.IsWaking {
		machine.mu.Unlock()
		p.logger.Info("Machine %s wake already in progress, joining existing wait",
			machine.Machine.Name)
		return p.waitForWake(ctx, machine)
	}

	machine.IsWaking = true
	machine.mu.Unlock()

	defer func() {
		machine.mu.Lock()
		machine.IsWaking = false
		machine.mu.Unlock()
	}()

	err := p.wolSender.SendWOL(
		machine.Machine.MacAddress,
		machine.Machine.BroadcastIP,
		machine.Machine.WolPort,
	)

	machine.mu.Lock()
	machine.LastActivity = p.clock.Now()
	machine.mu.Unlock()

	if err != nil {
		return fmt.Errorf("failed to send WOL: %w", err)
	}

	p.logger.Info("WOL packet sent to %s, waiting for server to wake",
		machine.Machine.Name)

	return p.waitForWake(ctx, machine)
}

func (p *ProxyService) waitForWake(ctx context.Context, machine *MachineState) error {
	timeout := p.clock.After(p.config.Timeout)
	healthCheckTicker := p.clock.NewTicker(p.config.PollInterval)
	defer healthCheckTicker.Stop()

	wolTicker := p.clock.NewTicker(500 * time.Millisecond)
	defer wolTicker.Stop()

	wakeStartTime := p.clock.Now()
	p.logger.Info("Waiting for %s to wake (poll interval %v, timeout %v)",
		machine.Machine.Name, p.config.PollInterval, p.config.Timeout)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout waiting for %s to wake up after %v",
				machine.Machine.Name, p.config.Timeout)
		case <-wolTicker.C():
			// Send additional WOL packets while waiting
			err := p.wolSender.SendWOL(
				machine.Machine.MacAddress,
				machine.Machine.BroadcastIP,
				machine.Machine.WolPort,
			)
			if err != nil {
				p.logger.Error("Failed to send additional WOL packet: %v", err)
				// Continue waiting even if a packet fails to send
			} else {
				p.logger.Info("Sent additional WOL packet to %s",
					machine.Machine.Name)
			}
		case <-healthCheckTicker.C():
			if p.healthChecker.Check(ctx, machine.Machine.HealthCheck, "wake") {
				machine.mu.Lock()
				machine.IsHealthy = true
				machine.LastCheck = p.clock.Now()
				machine.mu.Unlock()

				wakeDuration := p.clock.Now().Sub(wakeStartTime)
				p.logger.Info("Machine %s woke up after %v",
					machine.Machine.Name, wakeDuration)
				return nil
			}
		}
	}
}

func (p *ProxyService) proxyRequest(w http.ResponseWriter, r *http.Request, route *Route) {
	machineState := route.Machine
	machineState.mu.Lock()
	machineState.LastActivity = p.clock.Now()
	machineState.mu.Unlock()

	targetURL, err := url.Parse(route.Destination)
	if err != nil {
		p.logger.Error("Invalid target URL %s: %v", route.Destination, err)
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
		DisableCompression:    true,
		ResponseHeaderTimeout: p.config.ResponseHeaderTimeout,
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
		p.logger.Error("Proxy error for %s (%s): %v", route.Machine.Machine.Name, route.Hostname, err)
		http.Error(rw, "Bad Gateway", http.StatusBadGateway)
	}

	// Disable buffering of response body for streaming uploads/downloads
	proxy.ModifyResponse = func(resp *http.Response) error {
		p.logger.Info("Response from %s: status=%d, content-length=%d",
			route.Name, resp.StatusCode, resp.ContentLength)
		return nil
	}

	proxy.ServeHTTP(w, r)
}

// Config loader
func LoadConfig(filename string, clock Clock) (*ProxyConfig, error) {
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

	if config.ResponseHeaderTimeout == "" {
		config.ResponseHeaderTimeout = "1m"
	}
	responseHeaderTimeout, err := time.ParseDuration(config.ResponseHeaderTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid response_header_timeout: %w", err)
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

	machines := make(map[string]*MachineState)
	routes := make([]*Route, 0, len(config.Targets))
	routesByHostname := make(map[string]*Route)

	for _, target := range config.Targets {
		if target.Hostname == "" {
			return nil, fmt.Errorf("target %s is missing hostname", target.Name)
		}

		// Check for duplicate hostnames
		if existing, exists := routesByHostname[target.Hostname]; exists {
			return nil, fmt.Errorf("duplicate hostname %s for targets %s and %s",
				target.Hostname, existing.Name, target.Name)
		}

		// Validate shutdown configuration
		// Disallow using both SSH shutdown command and HTTP shutdown URL
		if strings.TrimSpace(target.ShutdownHTTPUrl) != "" && strings.TrimSpace(target.ShutdownCommand) != "" {
			return nil, fmt.Errorf("target %s: cannot define both shutdown_http_url and shutdown_command; choose one", target.Name)
		}

		// Disallow http method/ok status without URL
		if strings.TrimSpace(target.ShutdownHTTPUrl) == "" && (strings.TrimSpace(target.ShutdownHTTPMethod) != "" || target.ShutdownHTTPOKStatus != 0) {
			return nil, fmt.Errorf("target %s: shutdown_http_method and/or shutdown_http_ok_status require shutdown_http_url to be set", target.Name)
		}

		var inactivityThreshold time.Duration
		if target.InactivityThreshold != "" {
			inactivityThreshold, err = time.ParseDuration(target.InactivityThreshold)
			if err != nil {
				return nil, fmt.Errorf("invalid inactivity_threshold for target %s: %w", target.Name, err)
			}
		}

		machineState := &MachineState{
			Machine: &Machine{
				Name:                 target.Name,
				MacAddress:           target.MacAddress,
				BroadcastIP:          target.BroadcastIP,
				WolPort:              target.WolPort,
				HealthCheck:          target.HealthEndpoint,
				SSHHost:              target.SSHHost,
				SSHUser:              target.SSHUser,
				SSHKeyPath:           target.SSHKeyPath,
				ShutdownCommand:      target.ShutdownCommand,
				ShutdownHTTPUrl:      target.ShutdownHTTPUrl,
				ShutdownHTTPMethod:   target.ShutdownHTTPMethod,
				ShutdownHTTPOKStatus: target.ShutdownHTTPOKStatus,
				InactivityThreshold:  inactivityThreshold,
			},
			LastActivity: clock.Now(),
		}
		machines[target.Name] = machineState

		route := &Route{
			Name:        target.Name,
			Machine:     machineState,
			Hostname:    target.Hostname,
			Destination: target.Destination,
		}
		routes = append(routes, route)
		routesByHostname[target.Hostname] = route
	}

	return &ProxyConfig{
		Port:                  config.Port,
		SSLCertificate:        config.SSLCertificate,
		SSLCertificateKey:     config.SSLCertificateKey,
		Timeout:               timeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		PollInterval:          pollInterval,
		HealthCheckInterval:   healthCheckInterval,
		HealthCacheDuration:   healthCacheDuration,
		Machines:              machines,
		Routes:                routes,
		RoutesByHostname:      routesByHostname,
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
	clock := RealClock{}

	config, err := LoadConfig(configFile, clock)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize dependencies
	logger := &StdLogger{}
	healthChecker := NewHTTPHealthChecker(logger, clock)
	wolSender := NewUDPWOLSender(logger)
	sshExecutor := NewDefaultSSHExecutor(logger)

	// Create proxy service
	proxy := NewProxyService(config, healthChecker, wolSender, sshExecutor, logger, clock)

	// Start the service
	ctx := context.Background()
	if err := proxy.Start(ctx); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}
