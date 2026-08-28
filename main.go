package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh"
)

// Interfaces for dependency injection
type HealthChecker interface {
	Check(ctx context.Context, endpoint string, source string) bool
	StartBackgroundChecks(ctx context.Context, machines map[string]*Machine, routes []*Route, interval time.Duration)
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

const tcpScheme = "tcp://"

// shutdownGrace is how long in-flight requests get to finish on shutdown.
const shutdownGrace = 15 * time.Second

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
	Port                  string         `toml:"port"`
	Timeout               string         `toml:"timeout"`
	ResponseHeaderTimeout string         `toml:"response_header_timeout,omitempty"`
	PollInterval          string         `toml:"poll_interval"`
	HealthCheckInterval   string         `toml:"health_check_interval"`
	HealthCacheDuration   string         `toml:"health_cache_duration"`
	SSLCertificate        string         `toml:"ssl_certificate,omitempty"`
	SSLCertificateKey     string         `toml:"ssl_certificate_key,omitempty"`
	Targets               []Target       `toml:"targets,omitempty"` // legacy, superseded by machines + routes
	Machines              []MachineEntry `toml:"machines,omitempty"`
	Routes                []RouteEntry   `toml:"routes,omitempty"`
}

// MachineEntry is a [[machines]] block as written in the config file.
type MachineEntry struct {
	Name                 string `toml:"name"`
	MacAddress           string `toml:"mac_address,omitempty"`
	BroadcastIP          string `toml:"broadcast_ip,omitempty"`
	WolPort              int    `toml:"wol_port,omitempty"`
	HealthCheck          string `toml:"health_check,omitempty"`
	SSHHost              string `toml:"ssh_host,omitempty"`
	SSHUser              string `toml:"ssh_user,omitempty"`
	SSHKeyPath           string `toml:"ssh_key_path,omitempty"`
	ShutdownCommand      string `toml:"shutdown_command,omitempty"`
	ShutdownHTTPUrl      string `toml:"shutdown_http_url,omitempty"`
	ShutdownHTTPMethod   string `toml:"shutdown_http_method,omitempty"`
	ShutdownHTTPOKStatus int    `toml:"shutdown_http_ok_status,omitempty"`
	InactivityThreshold  string `toml:"inactivity_threshold,omitempty"`
}

// RouteEntry is a [[routes]] block as written in the config file.
type RouteEntry struct {
	Machine     string `toml:"machine"`
	Hostname    string `toml:"hostname,omitempty"`
	ListenPort  int    `toml:"listen_port,omitempty"`
	Destination string `toml:"destination,omitempty"`
	HealthCheck string `toml:"health_check,omitempty"`
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
type MachineConfig struct {
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
	Machine     *Machine
	Hostname    string
	ListenPort  int
	Destination string
	// HealthCheck is this route's readiness check: can this route serve? It is
	// distinct from the machine's liveness check, which answers whether the box is
	// up at all. Defaults to dialing Destination.
	HealthCheck string

	IsReady   bool
	LastCheck time.Time
	mu        sync.RWMutex
}

// IsTCP reports whether this route is reached by its own listening socket rather
// than by Host header. A route has a hostname or a listen port, never both.
func (r *Route) IsTCP() bool { return r.ListenPort != 0 }

// routing is the runtime routing model: machines and the routes that reach them.
type routing struct {
	machines     map[string]*Machine
	routes       []*Route
	byHostname   map[string]*Route
	byListenPort map[int]*Route
}

type ProxyConfig struct {
	Port                  string
	Timeout               time.Duration
	ResponseHeaderTimeout time.Duration
	PollInterval          time.Duration
	HealthCheckInterval   time.Duration
	HealthCacheDuration   time.Duration
	Machines              map[string]*Machine
	Routes                []*Route
	RoutesByHostname      map[string]*Route
	RoutesByListenPort    map[int]*Route
	SSLCertificate        string
	SSLCertificateKey     string
}

type Machine struct {
	Name         string
	Config       *MachineConfig
	IsHealthy    bool
	LastCheck    time.Time
	IsWaking     bool
	LastActivity time.Time
	openConns    int
	mu           sync.RWMutex
}

// openConnections reports how many forwarded connections are currently open. A
// long-lived idle connection — an ssh session is the motivating case — moves no
// bytes, so LastActivity alone cannot tell the machine is still in use.
func (m *Machine) openConnections() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.openConns
}

func (m *Machine) holdConnection() {
	m.mu.Lock()
	m.openConns++
	m.mu.Unlock()
}

// releaseConnection decrements the in-flight counter and stamps LastActivity to
// now. Stamping on release is what makes the inactivity countdown start at
// disconnect: a long-running session — an ssh login left open for hours — would
// otherwise carry a stale LastActivity from when it began, and the very next
// inactivity tick after logout would exceed the threshold and shut the box down.
func (m *Machine) releaseConnection(now time.Time) {
	m.mu.Lock()
	if m.openConns > 0 {
		m.openConns--
	}
	m.LastActivity = now
	m.mu.Unlock()
}

// Health checker: dispatches on the endpoint scheme — tcp:// dials, anything else is an HTTP GET
type EndpointHealthChecker struct {
	client           *http.Client
	logger           Logger
	clock            Clock
	initialCheckDone map[string]bool
	initialCheckMu   sync.RWMutex
	initialWaitGroup sync.WaitGroup
}

func NewEndpointHealthChecker(logger Logger, clock Clock) *EndpointHealthChecker {
	transport := &http.Transport{
		DisableKeepAlives: true,
	}
	return &EndpointHealthChecker{
		client: &http.Client{
			Timeout:   5 * time.Second,
			Transport: transport,
		},
		logger:           logger,
		clock:            clock,
		initialCheckDone: make(map[string]bool),
	}
}

func (h *EndpointHealthChecker) CloseIdleConnections() {
	if transport, ok := h.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (h *EndpointHealthChecker) Check(ctx context.Context, endpoint string, source string) bool {
	if address, ok := strings.CutPrefix(endpoint, tcpScheme); ok {
		return h.checkTCP(ctx, address, source)
	}
	return h.checkHTTP(ctx, endpoint, source)
}

// checkTCP reports liveness by opening and immediately closing a connection. For
// anything that is not an HTTP server — sshd being the motivating case — accepting
// a connection is the only readiness signal there is.
func (h *EndpointHealthChecker) checkTCP(ctx context.Context, address string, source string) bool {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		h.logger.Info("Health check (%s) failed for %s%s: %v", source, tcpScheme, address, err)
		return false
	}
	conn.Close()
	return true
}

func (h *EndpointHealthChecker) checkHTTP(ctx context.Context, endpoint string, source string) bool {
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

func (h *EndpointHealthChecker) StartBackgroundChecks(ctx context.Context, machines map[string]*Machine, routes []*Route, interval time.Duration) {
	for name, machine := range machines {
		h.initialWaitGroup.Add(1)
		go h.backgroundCheck(ctx, name, machine, routesTo(machine, routes), interval)
	}
}

func (h *EndpointHealthChecker) WaitForInitialChecks(ctx context.Context) error {
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

func (h *EndpointHealthChecker) backgroundCheck(ctx context.Context, name string, machine *Machine, routes []*Route, interval time.Duration) {
	// Perform initial check
	h.performCheck(ctx, name, machine, routes)
	h.markInitialCheckDone(name)
	h.initialWaitGroup.Done()

	ticker := h.clock.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			h.performCheck(ctx, name, machine, routes)
		}
	}
}

func (h *EndpointHealthChecker) performCheck(ctx context.Context, name string, machine *Machine, routes []*Route) {
	machine.mu.RLock()
	isWaking := machine.IsWaking
	machine.mu.RUnlock()
	if isWaking {
		h.logger.Info("Background health check for %s (%s) running while wake is in progress",
			name, machine.Config.HealthCheck)
	}

	checkStarted := h.clock.Now()
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	healthy := h.Check(checkCtx, machine.Config.HealthCheck, "background")

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
		h.logger.Info("Health check for %s (%s): %s", name, machine.Config.HealthCheck, status)
	}

	if !healthy && previousHealth {
		h.logger.Info(
			"Background health check for %s (%s): downgrading healthy to unhealthy (check took %v)",
			name, machine.Config.HealthCheck, h.clock.Now().Sub(checkStarted).Round(time.Millisecond),
		)
	}

	if !healthy {
		h.CloseIdleConnections()
	}

	h.checkRoutes(ctx, machine, routes, healthy)
}

// checkRoutes polls each route's readiness, but only while its machine is live. A
// machine that is meant to be asleep most of the time would otherwise generate a
// failed connection per route per interval, forever.
func (h *EndpointHealthChecker) checkRoutes(ctx context.Context, machine *Machine, routes []*Route, machineLive bool) {
	for _, route := range routes {
		if !machineLive {
			route.mu.Lock()
			route.IsReady = false
			route.mu.Unlock()
			continue
		}

		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ready := h.Check(checkCtx, route.HealthCheck, "background")
		cancel()

		route.mu.Lock()
		previous := route.IsReady
		route.IsReady = ready
		route.LastCheck = h.clock.Now()
		route.mu.Unlock()

		if ready != previous {
			status := "NOT READY"
			if ready {
				status = "READY"
			}
			h.logger.Info("Route %s on machine %s: %s", route.Name, machine.Name, status)
		}
	}
}

// routesTo returns the routes that reach the given machine.
func routesTo(machine *Machine, routes []*Route) []*Route {
	matched := make([]*Route, 0, len(routes))
	for _, route := range routes {
		if route.Machine == machine {
			matched = append(matched, route)
		}
	}
	return matched
}

func (h *EndpointHealthChecker) markInitialCheckDone(name string) {
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

	cfg := machineState.Config
	if (cfg.SSHHost == "" || cfg.SSHUser == "" || cfg.SSHKeyPath == "" || cfg.ShutdownCommand == "") && cfg.ShutdownHTTPUrl == "" {
		return fmt.Errorf("machine %s is missing SSH configuration or shutdown command or shutdown HTTP URL", machineName)
	}

	p.logger.Info("Shutting down machine %s due to inactivity", machineName)
	if cfg.ShutdownHTTPUrl != "" {
		// Attempt to shut down via HTTP request
		method := cfg.ShutdownHTTPMethod
		if method == "" {
			method = "POST" // Default to POST if not specified
		}

		req, err := http.NewRequest(method, cfg.ShutdownHTTPUrl, nil)
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
		if cfg.ShutdownHTTPOKStatus != 0 {
			if resp.StatusCode != cfg.ShutdownHTTPOKStatus {
				return fmt.Errorf("shutdown request failed with status: %s", resp.Status)
			}
		} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("shutdown request failed with status: %s", resp.Status)
		}

	} else {
		err := p.sshExecutor.ExecuteCommand(cfg.SSHHost, cfg.SSHUser, cfg.SSHKeyPath, cfg.ShutdownCommand)
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
		threshold := machineState.Config.InactivityThreshold
		if threshold == 0 {
			continue
		}

		// Skip machines that are not healthy (already down)
		machineState.mu.RLock()
		isHealthy := machineState.IsHealthy
		lastActivity := machineState.LastActivity
		openConns := machineState.openConns
		machineState.mu.RUnlock()

		if !isHealthy {
			continue
		}

		if openConns > 0 {
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
		p.config.Routes,
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
			route.Name, route.Machine.Name, route.Destination)
	}

	// Bind every TCP route before serving anything, so a port clash is reported at
	// startup rather than leaving the proxy half up.
	errs := make(chan error, len(p.config.Routes)+1)
	for _, route := range p.config.Routes {
		if !route.IsTCP() {
			continue
		}

		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", route.ListenPort))
		if err != nil {
			return fmt.Errorf("could not listen on port %d for machine %s: %w",
				route.ListenPort, route.Machine.Name, err)
		}
		defer listener.Close()

		go func(listener net.Listener, route *Route) {
			errs <- p.serveTCPRoute(ctx, listener, route)
		}(listener, route)
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

	httpListener, err := net.Listen("tcp", p.config.Port)
	if err != nil {
		return fmt.Errorf("could not listen on %s: %w", p.config.Port, err)
	}

	go func() { errs <- p.serveHTTP(ctx, server, httpListener) }()

	return <-errs
}

// serveHTTP serves until the context is cancelled, then drains in-flight requests
// before returning. A clean shutdown is not an error.
//
// server.Shutdown closes the listener first, which unblocks server.Serve() with
// http.ErrServerClosed while Shutdown is still waiting on active handlers.
// Returning on ErrServerClosed alone would let main exit before the grace window
// finishes and cut every in-flight response, so wait for the shutdown goroutine
// too.
func (p *ProxyService) serveHTTP(ctx context.Context, server *http.Server, listener net.Listener) error {
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			server.Close()
		}
	}()

	err := p.serveOn(server, listener)
	if errors.Is(err, http.ErrServerClosed) {
		<-shutdownDone
		return nil
	}
	return err
}

func (p *ProxyService) serveOn(server *http.Server, listener net.Listener) error {
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

		p.logger.Info("HTTPS server listening on %s with SSL certificates", listener.Addr())
		//The files in these methods are ignored since there is already a certificate in the config.
		return server.ServeTLS(listener, "", "")
	} else {
		p.logger.Info("HTTP server listening on %s", listener.Addr())
		return server.Serve(listener)
	}
}

// clientAddr describes where a request came from, for the log. RemoteAddr is the
// peer that actually opened the connection, which is the fronting reverse proxy
// when there is one, so an X-Forwarded-For it set is reported alongside RemoteAddr
// rather than in place of it. That header is written by the caller and is only as
// trustworthy as the hop that wrote it — fine for reading logs, not for decisions.
func clientAddr(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return fmt.Sprintf("%s (forwarded for %s)", r.RemoteAddr, forwarded)
	}
	return r.RemoteAddr
}

func (p *ProxyService) handleRequest(w http.ResponseWriter, r *http.Request) {
	route := p.routeForRequest(r)

	if route == nil {
		p.logger.Error("No route found for hostname: %s", r.Host)
		http.Error(w, "No route configured for this hostname", http.StatusNotFound)
		return
	}

	machineState := route.Machine
	machineName := machineState.Name

	p.logger.Info("Incoming request for hostname: %s -> machine: %s, path: %s, client: %s",
		r.Host, machineName, r.URL.Path, clientAddr(r))

	// Check if we have fresh health data
	cached, reason := p.healthCacheStatus(machineState)
	if cached {
		p.logger.Info("Machine %s is healthy, proxying immediately", machineName)
		p.serveWhenReady(w, r, route)
		return
	}

	// Need to wake up the server
	p.logger.Info("Machine %s appears down (%s), waking for %s", machineName, reason, route.Name)
	p.healthChecker.CloseIdleConnections()
	if err := p.wakeAndWait(r.Context(), machineState); err != nil {
		p.logger.Error("Failed to wake machine %s: %v", machineName, err)
		http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}

	p.logger.Info("Machine %s is now healthy, proxying request", machineName)
	p.serveWhenReady(w, r, route)
}

// serveWhenReady gates forwarding on the route's own readiness. A machine can be
// awake seconds before the service behind a route accepts connections, and
// forwarding into that gap turns a successful wake into a 502.
func (p *ProxyService) serveWhenReady(w http.ResponseWriter, r *http.Request, route *Route) {
	cached, reason := p.readyCacheStatus(route)
	if cached {
		p.proxyRequest(w, r, route)
		return
	}

	p.logger.Info("Route %s not ready (%s), waiting", route.Name, reason)
	if err := p.waitForReady(r.Context(), route); err != nil {
		p.logger.Error("Route %s did not become ready: %v", route.Name, err)
		http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}

	p.proxyRequest(w, r, route)
}

func (p *ProxyService) readyCacheStatus(route *Route) (cached bool, reason string) {
	route.mu.RLock()
	defer route.mu.RUnlock()

	if !route.IsReady {
		if route.LastCheck.IsZero() {
			return false, "no prior readiness check"
		}
		return false, fmt.Sprintf("marked unready (last check %v ago)",
			p.clock.Now().Sub(route.LastCheck).Round(time.Second))
	}

	age := p.clock.Now().Sub(route.LastCheck)
	if age > p.config.HealthCacheDuration {
		return false, fmt.Sprintf("cached readiness expired (last check %v ago)", age.Round(time.Second))
	}

	return true, ""
}

func (p *ProxyService) waitForReady(ctx context.Context, route *Route) error {
	// Check before waiting on a tick. A cached readiness result expires well before
	// the next background sweep refreshes it, so most requests that land here are for
	// routes that are in fact ready and should not pay a poll interval of latency.
	if p.markReadyIfHealthy(ctx, route) {
		return nil
	}

	timeout := p.clock.After(p.config.Timeout)
	ticker := p.clock.NewTicker(p.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout waiting for route %s to become ready after %v",
				route.Name, p.config.Timeout)
		case <-ticker.C():
			if p.markReadyIfHealthy(ctx, route) {
				return nil
			}
		}
	}
}

func (p *ProxyService) markReadyIfHealthy(ctx context.Context, route *Route) bool {
	if !p.healthChecker.Check(ctx, route.HealthCheck, "readiness") {
		return false
	}

	route.mu.Lock()
	route.IsReady = true
	route.LastCheck = p.clock.Now()
	route.mu.Unlock()
	return true
}

func (p *ProxyService) routeForRequest(r *http.Request) *Route {
	// Remove port from host if present
	host := r.Host
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	return p.config.RoutesByHostname[host]
}

func (p *ProxyService) healthCacheStatus(machine *Machine) (cached bool, reason string) {
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

func (p *ProxyService) wakeAndWait(ctx context.Context, machine *Machine) error {
	machine.mu.Lock()
	if machine.IsWaking {
		machine.mu.Unlock()
		p.logger.Info("Machine %s wake already in progress, joining existing wait",
			machine.Name)
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
		machine.Config.MacAddress,
		machine.Config.BroadcastIP,
		machine.Config.WolPort,
	)

	machine.mu.Lock()
	machine.LastActivity = p.clock.Now()
	machine.mu.Unlock()

	if err != nil {
		return fmt.Errorf("failed to send WOL: %w", err)
	}

	p.logger.Info("WOL packet sent to %s, waiting for server to wake",
		machine.Name)

	return p.waitForWake(ctx, machine)
}

func (p *ProxyService) waitForWake(ctx context.Context, machine *Machine) error {
	timeout := p.clock.After(p.config.Timeout)
	healthCheckTicker := p.clock.NewTicker(p.config.PollInterval)
	defer healthCheckTicker.Stop()

	wolTicker := p.clock.NewTicker(500 * time.Millisecond)
	defer wolTicker.Stop()

	wakeStartTime := p.clock.Now()
	p.logger.Info("Waiting for %s to wake (poll interval %v, timeout %v)",
		machine.Name, p.config.PollInterval, p.config.Timeout)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout waiting for %s to wake up after %v",
				machine.Name, p.config.Timeout)
		case <-wolTicker.C():
			// Send additional WOL packets while waiting
			err := p.wolSender.SendWOL(
				machine.Config.MacAddress,
				machine.Config.BroadcastIP,
				machine.Config.WolPort,
			)
			if err != nil {
				p.logger.Error("Failed to send additional WOL packet: %v", err)
				// Continue waiting even if a packet fails to send
			} else {
				p.logger.Info("Sent additional WOL packet to %s",
					machine.Name)
			}
		case <-healthCheckTicker.C():
			if p.healthChecker.Check(ctx, machine.Config.HealthCheck, "wake") {
				machine.mu.Lock()
				machine.IsHealthy = true
				machine.LastCheck = p.clock.Now()
				machine.mu.Unlock()

				wakeDuration := p.clock.Now().Sub(wakeStartTime)
				p.logger.Info("Machine %s woke up after %v",
					machine.Name, wakeDuration)
				return nil
			}
		}
	}
}

// serveTCPRoute accepts connections on listener and forwards each to the route's
// destination, waking the machine first if it is asleep. It returns when ctx is
// cancelled or the listener stops accepting.
func (p *ProxyService) serveTCPRoute(ctx context.Context, listener net.Listener, route *Route) error {
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	p.logger.Info("Listening on %s for machine %s -> %s",
		listener.Addr(), route.Machine.Name, route.Destination)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept on %s failed: %w", listener.Addr(), err)
		}
		go p.forwardTCPConn(ctx, conn, route)
	}
}

// forwardTCPConn wakes the machine if needed, then splices the accepted connection
// to the destination. The client is already connected while we wake, so it waits on
// the upstream's protocol banner rather than on connect — an ssh client with a short
// ConnectTimeout still gets through a slow wake.
func (p *ProxyService) forwardTCPConn(ctx context.Context, client net.Conn, route *Route) {
	defer client.Close()

	machine := route.Machine
	if cached, reason := p.healthCacheStatus(machine); !cached {
		p.logger.Info("Machine %s appears down (%s), waking for %s", machine.Name, reason, route.Name)
		if err := p.wakeAndWait(ctx, machine); err != nil {
			p.logger.Error("Failed to wake machine %s for %s: %v", machine.Name, route.Name, err)
			return
		}
	}

	if cached, reason := p.readyCacheStatus(route); !cached {
		p.logger.Info("Route %s not ready (%s), waiting before forwarding", route.Name, reason)
		if err := p.waitForReady(ctx, route); err != nil {
			p.logger.Error("Route %s did not become ready: %v", route.Name, err)
			return
		}
	}

	dialer := net.Dialer{Timeout: p.config.Timeout}
	upstream, err := dialer.DialContext(ctx, "tcp", route.Destination)
	if err != nil {
		p.logger.Error("Could not reach %s for route %s: %v", route.Destination, route.Name, err)
		return
	}
	defer upstream.Close()

	machine.mu.Lock()
	machine.LastActivity = p.clock.Now()
	machine.mu.Unlock()

	machine.holdConnection()
	defer func() { machine.releaseConnection(p.clock.Now()) }()

	// Both directions must finish before the deferred closes run. A client that
	// half-closes its write side — ssh and scp both do, once the request is sent —
	// ends one direction while the response is still streaming back on the other.
	var copies sync.WaitGroup
	copies.Add(2)
	splice := func(dst, src net.Conn) {
		defer copies.Done()
		io.Copy(dst, src)
		// Half-close so the peer sees EOF while the other direction still drains.
		if conn, ok := dst.(*net.TCPConn); ok {
			conn.CloseWrite()
		}
	}
	go splice(upstream, client)
	go splice(client, upstream)

	done := make(chan struct{})
	go func() {
		copies.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (p *ProxyService) proxyRequest(w http.ResponseWriter, r *http.Request, route *Route) {
	machineState := route.Machine
	machineState.mu.Lock()
	machineState.LastActivity = p.clock.Now()
	machineState.mu.Unlock()

	// A slow upload or download can outlast the inactivity threshold; hold the
	// machine for as long as the request is in flight.
	machineState.holdConnection()
	defer func() { machineState.releaseConnection(p.clock.Now()) }()

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
		p.logger.Error("Proxy error for %s (%s): %v", route.Machine.Name, route.Hostname, err)
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

	if len(config.Targets) > 0 && (len(config.Machines) > 0 || len(config.Routes) > 0) {
		return nil, fmt.Errorf("config mixes the legacy [[targets]] format with [[machines]]/[[routes]]; use one or the other")
	}

	machineEntries, routeEntries := config.Machines, config.Routes
	if len(config.Targets) > 0 {
		machineEntries, routeEntries = migrateLegacyTargets(config.Targets)
	}

	model, err := buildMachinesAndRoutes(machineEntries, routeEntries, clock)
	if err != nil {
		return nil, err
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
		Machines:              model.machines,
		Routes:                model.routes,
		RoutesByHostname:      model.byHostname,
		RoutesByListenPort:    model.byListenPort,
	}, nil
}

// defaultHealthCheckForDestination derives a route's readiness check from where it
// forwards to: dialing the destination is free, since the proxy is about to connect
// there anyway. HTTP destinations are URLs and may leave the port implicit; TCP
// destinations are already host:port.
func defaultHealthCheckForDestination(destination string) (string, error) {
	if !strings.Contains(destination, "://") {
		if _, _, err := net.SplitHostPort(destination); err != nil {
			return "", fmt.Errorf("destination %q must be host:port or a URL: %w", destination, err)
		}
		return tcpScheme + destination, nil
	}

	parsed, err := url.Parse(destination)
	if err != nil {
		return "", fmt.Errorf("invalid destination %q: %w", destination, err)
	}

	host, port := parsed.Hostname(), parsed.Port()
	if host == "" {
		return "", fmt.Errorf("destination %q has no host", destination)
	}
	if port == "" {
		switch parsed.Scheme {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}

	return tcpScheme + net.JoinHostPort(host, port), nil
}

// MigrateConfigFile writes the machines + routes translation of a legacy config
// next to the original, so an operator can adopt it with a single mv. The original
// is never touched: it is often bind-mounted read-only or checked into a config
// repo, and rewriting it would silently drop every comment. If the sidecar cannot
// be written, the translation is logged instead so nothing is lost.
func MigrateConfigFile(path string, logger Logger) {
	var config Config
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return
	}
	if len(config.Targets) == 0 {
		return
	}

	config.Machines, config.Routes = migrateLegacyTargets(config.Targets)
	config.Targets = nil

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(config); err != nil {
		logger.Error("Could not translate the legacy config: %v", err)
		return
	}
	migrated := dropUnsetIntKeys(buf.String())

	ext := filepath.Ext(path)
	migratedPath := strings.TrimSuffix(path, ext) + ".migrated" + ext

	if err := os.WriteFile(migratedPath, []byte(migrated), 0o600); err != nil {
		logger.Info("This config uses the legacy [[targets]] format. Could not write %s (%v); "+
			"the migrated config follows — save it yourself:\n%s", migratedPath, err, migrated)
		return
	}

	logger.Info("This config uses the legacy [[targets]] format, which will be removed in a future "+
		"release. A migrated copy was written to %s — review it and replace your config with it.", migratedPath)
}

// dropUnsetIntKeys removes "key = 0" lines from encoded TOML. The toml encoder
// honours omitempty for strings but not for ints, and every int key in this config
// means "unset" at zero — emitting them would litter a migrated config with keys
// the operator never wrote.
func dropUnsetIntKeys(encoded string) string {
	lines := strings.Split(encoded, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasSuffix(strings.TrimSpace(line), "= 0") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// migrateLegacyTargets translates [[targets]] blocks into the machines + routes
// form. Each legacy target was a machine and a route rolled into one, so it
// becomes exactly one of each.
func migrateLegacyTargets(targets []Target) ([]MachineEntry, []RouteEntry) {
	machines := make([]MachineEntry, 0, len(targets))
	routes := make([]RouteEntry, 0, len(targets))

	for _, target := range targets {
		machines = append(machines, MachineEntry{
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
			InactivityThreshold:  target.InactivityThreshold,
		})
		routes = append(routes, RouteEntry{
			Machine:     target.Name,
			Hostname:    target.Hostname,
			Destination: target.Destination,
			// A legacy health_endpoint gated both waking and forwarding, so it
			// becomes the machine's liveness check and this route's readiness check.
			HealthCheck: target.HealthEndpoint,
		})
	}

	return machines, routes
}

// buildMachinesAndRoutes turns the machine and route blocks of a config file into
// the runtime model: one Machine per machine block, shared by every route that
// names it.
func buildMachinesAndRoutes(machineEntries []MachineEntry, routeEntries []RouteEntry, clock Clock) (routing, error) {
	machines := make(map[string]*Machine)
	routes := make([]*Route, 0, len(routeEntries))
	routesByHostname := make(map[string]*Route)
	routesByListenPort := make(map[int]*Route)
	var err error

	for _, entry := range machineEntries {
		if entry.Name == "" {
			return routing{}, fmt.Errorf("every machine needs a name")
		}
		if _, exists := machines[entry.Name]; exists {
			return routing{}, fmt.Errorf("duplicate machine name %q", entry.Name)
		}

		// Disallow using both SSH shutdown command and HTTP shutdown URL
		if strings.TrimSpace(entry.ShutdownHTTPUrl) != "" && strings.TrimSpace(entry.ShutdownCommand) != "" {
			return routing{}, fmt.Errorf("machine %s: cannot define both shutdown_http_url and shutdown_command; choose one", entry.Name)
		}

		// Disallow http method/ok status without URL
		if strings.TrimSpace(entry.ShutdownHTTPUrl) == "" && (strings.TrimSpace(entry.ShutdownHTTPMethod) != "" || entry.ShutdownHTTPOKStatus != 0) {
			return routing{}, fmt.Errorf("machine %s: shutdown_http_method and/or shutdown_http_ok_status require shutdown_http_url to be set", entry.Name)
		}

		var inactivityThreshold time.Duration
		if entry.InactivityThreshold != "" {
			inactivityThreshold, err = time.ParseDuration(entry.InactivityThreshold)
			if err != nil {
				return routing{}, fmt.Errorf("invalid inactivity_threshold for machine %s: %w", entry.Name, err)
			}
		}

		machines[entry.Name] = &Machine{
			Name: entry.Name,
			Config: &MachineConfig{
				MacAddress:           entry.MacAddress,
				BroadcastIP:          entry.BroadcastIP,
				WolPort:              entry.WolPort,
				HealthCheck:          entry.HealthCheck,
				SSHHost:              entry.SSHHost,
				SSHUser:              entry.SSHUser,
				SSHKeyPath:           entry.SSHKeyPath,
				ShutdownCommand:      entry.ShutdownCommand,
				ShutdownHTTPUrl:      entry.ShutdownHTTPUrl,
				ShutdownHTTPMethod:   entry.ShutdownHTTPMethod,
				ShutdownHTTPOKStatus: entry.ShutdownHTTPOKStatus,
				InactivityThreshold:  inactivityThreshold,
			},
			LastActivity: clock.Now(),
		}
	}

	for _, entry := range routeEntries {
		name := entry.Hostname
		if name == "" {
			name = fmt.Sprintf(":%d", entry.ListenPort)
		}

		switch {
		case entry.Hostname == "" && entry.ListenPort == 0:
			return routing{}, fmt.Errorf("route for machine %q needs either a hostname or a listen_port", entry.Machine)
		case entry.Hostname != "" && entry.ListenPort != 0:
			return routing{}, fmt.Errorf("route %s sets both hostname and listen_port; a route is reached one way or the other", name)
		}

		if existing, exists := routesByHostname[entry.Hostname]; exists {
			return routing{}, fmt.Errorf("duplicate hostname %s for routes to machines %s and %s",
				entry.Hostname, existing.Machine.Name, entry.Machine)
		}
		if existing, exists := routesByListenPort[entry.ListenPort]; exists {
			return routing{}, fmt.Errorf("duplicate listen_port %d for routes to machines %s and %s",
				entry.ListenPort, existing.Machine.Name, entry.Machine)
		}

		machine, exists := machines[entry.Machine]
		if !exists {
			return routing{}, fmt.Errorf("route %s references undefined machine %q", name, entry.Machine)
		}

		healthCheck := entry.HealthCheck
		if healthCheck == "" {
			healthCheck, err = defaultHealthCheckForDestination(entry.Destination)
			if err != nil {
				return routing{}, fmt.Errorf("route %s: %w", name, err)
			}
		}

		route := &Route{
			Name:        name,
			Machine:     machine,
			Hostname:    entry.Hostname,
			ListenPort:  entry.ListenPort,
			Destination: entry.Destination,
			HealthCheck: healthCheck,
		}
		routes = append(routes, route)
		if route.IsTCP() {
			routesByListenPort[route.ListenPort] = route
		} else {
			routesByHostname[route.Hostname] = route
		}
	}

	return routing{machines: machines, routes: routes, byHostname: routesByHostname, byListenPort: routesByListenPort}, nil
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
	logger := &StdLogger{}

	MigrateConfigFile(configFile, logger)

	config, err := LoadConfig(configFile, clock)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize dependencies
	healthChecker := NewEndpointHealthChecker(logger, clock)
	wolSender := NewUDPWOLSender(logger)
	sshExecutor := NewDefaultSSHExecutor(logger)

	// Create proxy service
	proxy := NewProxyService(config, healthChecker, wolSender, sshExecutor, logger, clock)

	// Start the service, shutting down cleanly on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := proxy.Start(ctx); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}

	logger.Info("Shut down cleanly")
}
