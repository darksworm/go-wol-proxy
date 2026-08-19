package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// ManualClock — controllable clock for tests
// ---------------------------------------------------------------------------

type ManualClock struct {
	mu      sync.Mutex
	cond    *sync.Cond
	now     time.Time
	tickers []*manualTicker
	timers  []*manualTimer
	// Counts every ticker and timer ever created. Advance prunes fired timers,
	// so a live count would let BlockUntil's target move backwards.
	registered int
}

type manualTicker struct {
	mu      sync.Mutex
	d       time.Duration
	nextAt  time.Time
	ch      chan time.Time
	stopped bool
}

func (t *manualTicker) C() <-chan time.Time { return t.ch }
func (t *manualTicker) Stop() {
	t.mu.Lock()
	t.stopped = true
	t.mu.Unlock()
}

type manualTimer struct {
	fireAt time.Time
	ch     chan time.Time
	fired  bool
}

func newManualClock(start time.Time) *ManualClock {
	c := &ManualClock{now: start}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *ManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *ManualClock) NewTicker(d time.Duration) Ticker {
	c.mu.Lock()
	t := &manualTicker{
		d:      d,
		nextAt: c.now.Add(d),
		ch:     make(chan time.Time, 1),
	}
	c.tickers = append(c.tickers, t)
	c.registered++
	c.cond.Broadcast()
	c.mu.Unlock()
	return t
}

func (c *ManualClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	timer := &manualTimer{
		fireAt: c.now.Add(d),
		ch:     make(chan time.Time, 1),
	}
	c.timers = append(c.timers, timer)
	c.registered++
	c.cond.Broadcast()
	c.mu.Unlock()
	return timer.ch
}

// BlockUntil blocks until at least n tickers+timers have been registered.
// Always call this before Advance to avoid racing ahead of goroutines registering their time objects.
func (c *ManualClock) BlockUntil(n int) {
	c.mu.Lock()
	for c.registered < n {
		c.cond.Wait()
	}
	c.mu.Unlock()
}

// Advance moves the clock forward and fires all due tickers/timers.
// Channel sends happen outside the lock to avoid deadlock with receivers that call BlockUntil.
func (c *ManualClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now

	// Collect channels to send on.
	var sends []chan time.Time

	for _, t := range c.tickers {
		t.mu.Lock()
		if !t.stopped && !t.nextAt.After(now) {
			sends = append(sends, t.ch)
			// Advance nextAt by d intervals to keep period correct.
			for !t.nextAt.After(now) {
				t.nextAt = t.nextAt.Add(t.d)
			}
		}
		t.mu.Unlock()
	}

	remaining := c.timers[:0]
	for _, tm := range c.timers {
		if !tm.fired && !tm.fireAt.After(now) {
			sends = append(sends, tm.ch)
			tm.fired = true
		} else {
			remaining = append(remaining, tm)
		}
	}
	c.timers = remaining

	c.mu.Unlock()

	for _, ch := range sends {
		select {
		case ch <- now:
		default:
		}
	}
}

func TestManualClock_BlockUntilCountSurvivesFiredTimers(t *testing.T) {
	// Advance prunes fired timers, so BlockUntil must count registrations rather
	// than live objects — otherwise a cumulative wait blocks forever.
	c := newManualClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))
	c.After(time.Second)
	c.NewTicker(time.Second)
	c.Advance(2 * time.Second)

	done := make(chan struct{})
	go func() {
		c.BlockUntil(2)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("BlockUntil(2) blocked after a timer fired: the registration count went backwards")
	}
}

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

type mockHealthChecker struct {
	mu         sync.Mutex
	result     bool
	checkCount int
}

func (m *mockHealthChecker) setResult(v bool) {
	m.mu.Lock()
	m.result = v
	m.mu.Unlock()
}

func (m *mockHealthChecker) checks() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.checkCount
}

func (m *mockHealthChecker) Check(_ context.Context, _, _ string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkCount++
	return m.result
}

func (m *mockHealthChecker) StartBackgroundChecks(_ context.Context, _ map[string]*Machine, _ time.Duration) {
}
func (m *mockHealthChecker) WaitForInitialChecks(_ context.Context) error { return nil }
func (m *mockHealthChecker) CloseIdleConnections()                        {}

type wolCall struct {
	mac, ip string
	port    int
}

type mockWOLSender struct {
	mu     sync.Mutex
	calls  []wolCall
	err    error
	signal chan struct{} // receives on each call, for synchronisation
}

func newMockWOLSender() *mockWOLSender {
	return &mockWOLSender{signal: make(chan struct{}, 100)}
}

func (m *mockWOLSender) SendWOL(mac, ip string, port int) error {
	m.mu.Lock()
	m.calls = append(m.calls, wolCall{mac, ip, port})
	m.mu.Unlock()
	select {
	case m.signal <- struct{}{}:
	default:
	}
	return m.err
}

func (m *mockWOLSender) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// waitFor polls cond until it holds, for synchronising on mock side effects that
// have no dedicated signal. Uses real time: this is harness scheduling, not logic under test.
func waitFor(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", desc)
}

// waitForCalls blocks until at least n WOL calls have been recorded, or timeout elapses.
func (m *mockWOLSender) waitForCalls(t *testing.T, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		if m.callCount() >= n {
			return
		}
		select {
		case <-m.signal:
		case <-deadline:
			t.Fatalf("timed out waiting for %d WOL calls, got %d", n, m.callCount())
		}
	}
}

type mockSSHExecutor struct {
	mu   sync.Mutex
	done chan struct{}
	err  error
	once sync.Once
}

func newMockSSHExecutor() *mockSSHExecutor {
	return &mockSSHExecutor{done: make(chan struct{})}
}

func (m *mockSSHExecutor) ExecuteCommand(_, _, _, _ string) error {
	m.once.Do(func() { close(m.done) })
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.err
}

type noopLogger struct{}

func (noopLogger) Info(_ string, _ ...interface{})  {}
func (noopLogger) Error(_ string, _ ...interface{}) {}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

type testProxy struct {
	svc     *ProxyService
	clock   *ManualClock
	health  *mockHealthChecker
	wol     *mockWOLSender
	ssh     *mockSSHExecutor
	machine *Machine
	route   *Route
	backend *httptest.Server
}

const testHostname = "server.local"
const testMachineName = "server"

// newTestProxy builds a ProxyService with one machine and one route pointing at
// it, all mocks, and optionally a real httptest backend. Pass backendHandler=nil
// for tests that don't proxy.
func newTestProxy(t *testing.T, backendHandler http.Handler) *testProxy {
	t.Helper()

	clock := newManualClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))
	health := &mockHealthChecker{}
	wol := newMockWOLSender()
	ssh := newMockSSHExecutor()

	var backendURL string
	var backend *httptest.Server
	if backendHandler != nil {
		backend = httptest.NewServer(backendHandler)
		t.Cleanup(backend.Close)
		backendURL = backend.URL
	} else {
		backendURL = "http://127.0.0.1:19999" // unused port
	}

	machineState := &Machine{
		Name: testMachineName,
		Config: &MachineConfig{
			HealthCheck:     backendURL + "/health",
			MacAddress:      "AA:BB:CC:DD:EE:FF",
			BroadcastIP:     "255.255.255.255",
			WolPort:         9,
			SSHHost:         "server.local",
			SSHUser:         "admin",
			SSHKeyPath:      "/home/admin/.ssh/id_rsa",
			ShutdownCommand: "shutdown -h now",
		},
		LastActivity: clock.Now(),
	}

	route := &Route{
		Name:        testMachineName,
		Machine:     machineState,
		Hostname:    testHostname,
		Destination: backendURL,
	}

	cfg := &ProxyConfig{
		Port:                ":0",
		Timeout:             5 * time.Second,
		PollInterval:        1 * time.Second,
		HealthCheckInterval: 30 * time.Second,
		HealthCacheDuration: 10 * time.Second,
		Machines:            map[string]*Machine{testMachineName: machineState},
		Routes:              []*Route{route},
		RoutesByHostname:    map[string]*Route{testHostname: route},
	}

	svc := NewProxyService(cfg, health, wol, ssh, noopLogger{}, clock)

	return &testProxy{svc: svc, clock: clock, health: health, wol: wol, ssh: ssh, machine: machineState, route: route, backend: backend}
}

// ---------------------------------------------------------------------------
// Unit tests — pure logic
// ---------------------------------------------------------------------------

func TestRouteForRequest(t *testing.T) {
	tp := newTestProxy(t, nil)

	tests := []struct {
		host      string
		wantRoute bool
	}{
		{testHostname, true},
		{testHostname + ":8080", true},
		{"unknown.host", false},
		{"", false},
	}
	for _, tc := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = tc.host
		got := tp.svc.routeForRequest(r)
		if tc.wantRoute {
			if got != tp.route {
				t.Errorf("routeForRequest(%q) = %v, want the configured route", tc.host, got)
			}
			continue
		}
		if got != nil {
			t.Errorf("routeForRequest(%q) = %v, want no route", tc.host, got)
		}
	}
}

func TestHealthCacheStatus_HealthyFresh(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now().Add(-5 * time.Second) // 5s ago, cache=10s

	cached, reason := tp.svc.healthCacheStatus(tp.machine)
	if !cached {
		t.Errorf("expected cached=true, got false; reason: %s", reason)
	}
}

func TestHealthCacheStatus_HealthyExpired(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now().Add(-15 * time.Second) // 15s ago, cache=10s

	cached, _ := tp.svc.healthCacheStatus(tp.machine)
	if cached {
		t.Error("expected cached=false for expired cache")
	}
}

func TestHealthCacheStatus_Unhealthy(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.machine.IsHealthy = false
	tp.machine.LastCheck = tp.clock.Now().Add(-2 * time.Second)

	cached, reason := tp.svc.healthCacheStatus(tp.machine)
	if cached {
		t.Errorf("expected cached=false for unhealthy target, reason: %s", reason)
	}
}

func TestHealthCacheStatus_NoCheck(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.machine.IsHealthy = false
	// LastCheck is zero value

	cached, reason := tp.svc.healthCacheStatus(tp.machine)
	if cached {
		t.Error("expected cached=false when no prior health check")
	}
	if !strings.Contains(reason, "no prior") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestCheckInactiveTargets_InactiveHealthy_TriggersShutdown(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.machine.Config.InactivityThreshold = 30 * time.Minute

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastActivity = tp.clock.Now().Add(-1 * time.Hour)
	tp.machine.mu.Unlock()

	tp.svc.checkInactiveMachines()

	select {
	case <-tp.ssh.done:
	default:
		t.Error("expected SSH shutdown to be called for inactive healthy target")
	}
}

func TestCheckInactiveTargets_InactiveUnhealthy_NoShutdown(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.machine.Config.InactivityThreshold = 30 * time.Minute

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = false
	tp.machine.LastActivity = tp.clock.Now().Add(-1 * time.Hour)
	tp.machine.mu.Unlock()

	tp.svc.checkInactiveMachines()

	select {
	case <-tp.ssh.done:
		t.Error("shutdown must not be called for an unhealthy target")
	default:
	}
}

func TestCheckInactiveTargets_Active_NoShutdown(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.machine.Config.InactivityThreshold = 30 * time.Minute

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastActivity = tp.clock.Now().Add(-5 * time.Minute) // well within threshold
	tp.machine.mu.Unlock()

	tp.svc.checkInactiveMachines()

	select {
	case <-tp.ssh.done:
		t.Error("shutdown must not be called for an active target")
	default:
	}
}

func TestCheckInactiveTargets_NoThreshold_NoShutdown(t *testing.T) {
	tp := newTestProxy(t, nil)
	// InactivityThreshold is unset by default in newTestProxy

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastActivity = tp.clock.Now().Add(-48 * time.Hour)
	tp.machine.mu.Unlock()

	tp.svc.checkInactiveMachines()

	select {
	case <-tp.ssh.done:
		t.Error("shutdown must not be called when no inactivity threshold is set")
	default:
	}
}

func TestShutdownTarget_SSH(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.machine.IsHealthy = true

	err := tp.svc.shutdownMachine(testMachineName)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case <-tp.ssh.done:
	default:
		t.Error("expected SSH executor to be called")
	}

	tp.machine.mu.RLock()
	healthy := tp.machine.IsHealthy
	tp.machine.mu.RUnlock()
	if healthy {
		t.Error("expected IsHealthy=false after shutdown")
	}
}

func TestShutdownTarget_SSH_Error(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.ssh.err = fmt.Errorf("connection refused")
	tp.machine.IsHealthy = true

	err := tp.svc.shutdownMachine(testMachineName)
	if err == nil {
		t.Fatal("expected error from SSH executor, got nil")
	}
}

func TestShutdownTarget_HTTP_Success(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()

	tp := newTestProxy(t, nil)
	tp.machine.Config.SSHHost = "" // clear SSH config
	tp.machine.Config.SSHUser = ""
	tp.machine.Config.SSHKeyPath = ""
	tp.machine.Config.ShutdownCommand = ""
	tp.machine.Config.ShutdownHTTPUrl = backend.URL + "/shutdown"
	tp.machine.IsHealthy = true

	err := tp.svc.shutdownMachine(testMachineName)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tp.machine.mu.RLock()
	healthy := tp.machine.IsHealthy
	tp.machine.mu.RUnlock()
	if healthy {
		t.Error("expected IsHealthy=false after HTTP shutdown")
	}
}

func TestShutdownTarget_HTTP_NonSuccess(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer backend.Close()

	tp := newTestProxy(t, nil)
	tp.machine.Config.SSHHost = ""
	tp.machine.Config.SSHUser = ""
	tp.machine.Config.SSHKeyPath = ""
	tp.machine.Config.ShutdownCommand = ""
	tp.machine.Config.ShutdownHTTPUrl = backend.URL + "/shutdown"

	err := tp.svc.shutdownMachine(testMachineName)
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

func TestShutdownTarget_HTTP_CustomOKStatus(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(202)
	}))
	defer backend.Close()

	tp := newTestProxy(t, nil)
	tp.machine.Config.SSHHost = ""
	tp.machine.Config.SSHUser = ""
	tp.machine.Config.SSHKeyPath = ""
	tp.machine.Config.ShutdownCommand = ""
	tp.machine.Config.ShutdownHTTPUrl = backend.URL + "/shutdown"
	tp.machine.Config.ShutdownHTTPOKStatus = 202

	err := tp.svc.shutdownMachine(testMachineName)
	if err != nil {
		t.Fatalf("expected success for 202 with custom ok_status=202, got: %v", err)
	}
}

func TestShutdownTarget_HTTP_CustomOKStatus_Mismatch(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()

	tp := newTestProxy(t, nil)
	tp.machine.Config.SSHHost = ""
	tp.machine.Config.SSHUser = ""
	tp.machine.Config.SSHKeyPath = ""
	tp.machine.Config.ShutdownCommand = ""
	tp.machine.Config.ShutdownHTTPUrl = backend.URL + "/shutdown"
	tp.machine.Config.ShutdownHTTPOKStatus = 202 // expects 202, gets 200

	err := tp.svc.shutdownMachine(testMachineName)
	if err == nil {
		t.Fatal("expected error when status doesn't match custom ok_status")
	}
}

func TestShutdownTarget_NoConfig(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.machine.Config.SSHHost = ""
	tp.machine.Config.SSHUser = ""
	tp.machine.Config.SSHKeyPath = ""
	tp.machine.Config.ShutdownCommand = ""
	tp.machine.Config.ShutdownHTTPUrl = ""

	err := tp.svc.shutdownMachine(testMachineName)
	if err == nil {
		t.Fatal("expected error when no shutdown config, got nil")
	}
}

// ---------------------------------------------------------------------------
// LoadConfig tests
// ---------------------------------------------------------------------------

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wol-proxy-test.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validConfig = `
port = "8080"
timeout = "1m"
poll_interval = "5s"
health_check_interval = "30s"
health_cache_duration = "10s"

[[targets]]
name = "server"
hostname = "server.local"
destination = "http://192.168.1.10:80"
health_endpoint = "http://192.168.1.10:80/health"
mac_address = "AA:BB:CC:DD:EE:FF"
broadcast_ip = "255.255.255.255"
wol_port = 9
`

func TestLoadConfig_Valid(t *testing.T) {
	cfg, err := LoadConfig(writeTempConfig(t, validConfig), RealClock{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != ":8080" {
		t.Errorf("Port = %q, want :8080", cfg.Port)
	}
	if cfg.Timeout != time.Minute {
		t.Errorf("Timeout = %v, want 1m", cfg.Timeout)
	}
	if _, ok := cfg.Machines["server"]; !ok {
		t.Error("expected machine 'server' in map")
	}
	route, ok := cfg.RoutesByHostname["server.local"]
	if !ok {
		t.Fatal("expected a route for hostname server.local")
	}
	if route.Machine != cfg.Machines["server"] {
		t.Error("route server.local should point at machine 'server'")
	}
}

const twoTargetConfig = `
port = "8080"
timeout = "1m"
poll_interval = "5s"
health_check_interval = "30s"
health_cache_duration = "10s"

[[targets]]
name = "alpha"
hostname = "alpha.local"
destination = "http://192.168.1.10:80"
health_endpoint = "http://192.168.1.10:80/health"
mac_address = "AA:BB:CC:DD:EE:FF"
broadcast_ip = "255.255.255.255"
wol_port = 9

[[targets]]
name = "beta"
hostname = "beta.local"
destination = "http://192.168.1.11:80"
health_endpoint = "http://192.168.1.11:80/health"
mac_address = "11:22:33:44:55:66"
broadcast_ip = "255.255.255.255"
wol_port = 9
`

func TestLoadConfig_EachLegacyTargetBecomesItsOwnMachineAndRoute(t *testing.T) {
	cfg, err := LoadConfig(writeTempConfig(t, twoTargetConfig), RealClock{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Machines) != 2 {
		t.Errorf("Machines = %d, want 2", len(cfg.Machines))
	}
	if len(cfg.Routes) != 2 {
		t.Errorf("Routes = %d, want 2", len(cfg.Routes))
	}

	for hostname, wantMachine := range map[string]string{"alpha.local": "alpha", "beta.local": "beta"} {
		route, ok := cfg.RoutesByHostname[hostname]
		if !ok {
			t.Fatalf("no route for hostname %s", hostname)
		}
		if route.Machine.Name != wantMachine {
			t.Errorf("route %s points at machine %q, want %q", hostname, route.Machine.Name, wantMachine)
		}
		if route.Machine != cfg.Machines[wantMachine] {
			t.Errorf("route %s does not share the Machine held in cfg.Machines[%q]", hostname, wantMachine)
		}
	}

	if cfg.Machines["alpha"].Config.MacAddress == cfg.Machines["beta"].Config.MacAddress {
		t.Error("machines should keep their own MAC addresses")
	}
}

func TestLoadConfig_DefaultPort(t *testing.T) {
	cfg, err := LoadConfig(writeTempConfig(t, strings.ReplaceAll(validConfig, `port = "8080"`, "")), RealClock{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != ":8080" {
		t.Errorf("Port = %q, want :8080 (default)", cfg.Port)
	}
}

func TestLoadConfig_MissingHostname(t *testing.T) {
	cfg := strings.ReplaceAll(validConfig, `hostname = "server.local"`, "")
	_, err := LoadConfig(writeTempConfig(t, cfg), RealClock{})
	if err == nil {
		t.Fatal("expected error for missing hostname")
	}
}

func TestLoadConfig_DuplicateHostname(t *testing.T) {
	extra := `
[[targets]]
name = "server2"
hostname = "server.local"
destination = "http://192.168.1.11:80"
health_endpoint = "http://192.168.1.11:80/health"
mac_address = "11:22:33:44:55:66"
`
	_, err := LoadConfig(writeTempConfig(t, validConfig+extra), RealClock{})
	if err == nil {
		t.Fatal("expected error for duplicate hostname")
	}
}

func TestLoadConfig_BothShutdownMethods(t *testing.T) {
	extra := `
shutdown_command = "shutdown -h now"
shutdown_http_url = "http://server.local/shutdown"
`
	cfg := strings.Replace(validConfig, "wol_port = 9", "wol_port = 9\n"+extra, 1)
	_, err := LoadConfig(writeTempConfig(t, cfg), RealClock{})
	if err == nil {
		t.Fatal("expected error when both shutdown_command and shutdown_http_url are set")
	}
}

func TestLoadConfig_HTTPMethodWithoutURL(t *testing.T) {
	extra := `shutdown_http_method = "DELETE"`
	cfg := strings.Replace(validConfig, "wol_port = 9", "wol_port = 9\n"+extra, 1)
	_, err := LoadConfig(writeTempConfig(t, cfg), RealClock{})
	if err == nil {
		t.Fatal("expected error when shutdown_http_method set without shutdown_http_url")
	}
}

func TestLoadConfig_BadDuration(t *testing.T) {
	cfg := strings.ReplaceAll(validConfig, `timeout = "1m"`, `timeout = "notaduration"`)
	_, err := LoadConfig(writeTempConfig(t, cfg), RealClock{})
	if err == nil {
		t.Fatal("expected error for bad timeout duration")
	}
}

func TestLoadConfig_InactivityThreshold(t *testing.T) {
	extra := `inactivity_threshold = "2h"`
	cfg := strings.Replace(validConfig, "wol_port = 9", "wol_port = 9\n"+extra, 1)
	result, err := LoadConfig(writeTempConfig(t, cfg), RealClock{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := result.Machines["server"].Config.InactivityThreshold; got != 2*time.Hour {
		t.Errorf("machine server InactivityThreshold = %v, want 2h", got)
	}
}

// ---------------------------------------------------------------------------
// HTTPHealthChecker tests
// ---------------------------------------------------------------------------

func TestHTTPHealthChecker_Check_Healthy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()

	hc := NewHTTPHealthChecker(noopLogger{}, RealClock{})
	result := hc.Check(context.Background(), backend.URL+"/health", "test")
	if !result {
		t.Error("expected Check to return true for 200 response")
	}
}

func TestHTTPHealthChecker_Check_Unhealthy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer backend.Close()

	hc := NewHTTPHealthChecker(noopLogger{}, RealClock{})
	result := hc.Check(context.Background(), backend.URL+"/health", "test")
	if result {
		t.Error("expected Check to return false for 500 response")
	}
}

func TestHTTPHealthChecker_Check_ConnectionRefused(t *testing.T) {
	hc := NewHTTPHealthChecker(noopLogger{}, RealClock{})
	result := hc.Check(context.Background(), "http://127.0.0.1:19998/health", "test")
	if result {
		t.Error("expected Check to return false for refused connection")
	}
}

// ---------------------------------------------------------------------------
// Goroutine-driven unit tests (ManualClock + BlockUntil)
// ---------------------------------------------------------------------------

func TestWaitForWake_ContextCancel(t *testing.T) {
	tp := newTestProxy(t, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	err := tp.svc.waitForWake(ctx, tp.machine)
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
}

func TestWaitForWake_Success(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.health.setResult(false)

	result := make(chan error, 1)
	go func() {
		result <- tp.svc.waitForWake(context.Background(), tp.machine)
	}()

	// 2 tickers (wol + healthCheck) + 1 After (timeout) = 3
	tp.clock.BlockUntil(3)

	// Step 1: fire the wol ticker (500ms) and wait until the goroutine sends the packet.
	// This avoids the race where the health ticker and wol ticker fire at the same Advance
	// and select non-deterministically picks health before wol.
	tp.clock.Advance(500 * time.Millisecond)
	tp.wol.waitForCalls(t, 1, 5*time.Second)

	// Step 2: flip health and fire the health ticker (now at 1s total).
	tp.health.setResult(true)
	tp.clock.Advance(500 * time.Millisecond)

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("expected nil error on wake success, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("test timed out waiting for waitForWake to return")
	}

	if tp.wol.callCount() == 0 {
		t.Error("expected at least one WOL call")
	}

	tp.machine.mu.RLock()
	defer tp.machine.mu.RUnlock()
	if !tp.machine.IsHealthy {
		t.Error("expected target marked healthy after wake")
	}
	if !tp.machine.LastCheck.Equal(tp.clock.Now()) {
		t.Errorf("expected LastCheck primed to %v, got %v", tp.clock.Now(), tp.machine.LastCheck)
	}
}

func TestWaitForWake_Timeout(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.health.setResult(false)

	result := make(chan error, 1)
	go func() {
		result <- tp.svc.waitForWake(context.Background(), tp.machine)
	}()

	tp.clock.BlockUntil(3)
	tp.clock.Advance(tp.svc.config.Timeout + time.Millisecond)

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected timeout error, got nil")
		}
		if !strings.Contains(err.Error(), "timeout") {
			t.Errorf("expected 'timeout' in error message, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("test timed out waiting for waitForWake to return")
	}
}

func TestWaitForWake_WOLRetransmission(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.health.setResult(false)

	result := make(chan error, 1)
	go func() {
		result <- tp.svc.waitForWake(context.Background(), tp.machine)
	}()

	tp.clock.BlockUntil(3)

	// Advance to fire wol ticker twice, synchronising on each via waitForCalls.
	// wol ticker = 500ms; health returns false so the loop continues.
	tp.clock.Advance(500 * time.Millisecond)
	tp.wol.waitForCalls(t, 1, 5*time.Second)

	tp.clock.Advance(500 * time.Millisecond)
	tp.wol.waitForCalls(t, 2, 5*time.Second)

	if tp.wol.callCount() < 2 {
		t.Errorf("expected at least 2 WOL calls for retransmission, got %d", tp.wol.callCount())
	}

	// Let it timeout so the goroutine exits cleanly.
	tp.clock.Advance(tp.svc.config.Timeout + time.Millisecond)
	<-result
}

func TestStartInactivityMonitor_TriggersShutdown(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.machine.Config.InactivityThreshold = 30 * time.Minute

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastActivity = tp.clock.Now().Add(-1 * time.Hour)
	tp.machine.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go tp.svc.startInactivityMonitor(ctx)

	tp.clock.BlockUntil(1)
	tp.clock.Advance(10 * time.Second)

	select {
	case <-tp.ssh.done:
	case <-time.After(5 * time.Second):
		t.Fatal("test timed out waiting for shutdown to be triggered")
	}
}

// ---------------------------------------------------------------------------
// E2E tests — httptest.NewServer wrapping handleRequest
// ---------------------------------------------------------------------------

// doRequest sends a GET to the proxy with the configured test hostname.
func doRequest(t *testing.T, proxyURL string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", proxyURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = testHostname
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

func TestHandleRequest_HealthyTarget(t *testing.T) {
	tp := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "hello")
	}))

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now()
	tp.machine.LastActivity = tp.clock.Now().Add(-time.Hour)
	tp.machine.mu.Unlock()

	proxy := httptest.NewServer(http.HandlerFunc(tp.svc.handleRequest))
	defer proxy.Close()

	resp := doRequest(t, proxy.URL)
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Errorf("expected body 'hello', got %q", body)
	}

	tp.machine.mu.RLock()
	activity := tp.machine.LastActivity
	tp.machine.mu.RUnlock()
	if !activity.Equal(tp.clock.Now()) {
		t.Errorf("expected LastActivity refreshed to %v, got %v", tp.clock.Now(), activity)
	}
}

func TestHandleRequest_UnknownHostname(t *testing.T) {
	tp := newTestProxy(t, nil)

	proxy := httptest.NewServer(http.HandlerFunc(tp.svc.handleRequest))
	defer proxy.Close()

	req, err := http.NewRequest("GET", proxy.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "unknown.host"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestHandleRequest_WakeTimeout(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.machine.mu.Lock()
	tp.machine.IsHealthy = false
	tp.machine.mu.Unlock()
	tp.health.setResult(false)

	proxy := httptest.NewServer(http.HandlerFunc(tp.svc.handleRequest))
	defer proxy.Close()

	result := make(chan int, 1)
	go func() {
		resp := doRequest(t, proxy.URL)
		resp.Body.Close()
		result <- resp.StatusCode
	}()

	tp.clock.BlockUntil(3)
	tp.clock.Advance(tp.svc.config.Timeout + time.Millisecond)

	select {
	case code := <-result:
		if code != http.StatusServiceUnavailable {
			t.Errorf("expected 503, got %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("test timed out")
	}
}

func TestHandleRequest_WakeSuccess(t *testing.T) {
	tp := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	tp.machine.mu.Lock()
	tp.machine.IsHealthy = false
	tp.machine.mu.Unlock()
	tp.health.setResult(false)

	proxy := httptest.NewServer(http.HandlerFunc(tp.svc.handleRequest))
	defer proxy.Close()

	result := make(chan int, 1)
	go func() {
		resp := doRequest(t, proxy.URL)
		resp.Body.Close()
		result <- resp.StatusCode
	}()

	tp.clock.BlockUntil(3)
	tp.health.setResult(true)
	tp.clock.Advance(tp.svc.config.PollInterval)

	select {
	case code := <-result:
		if code != 200 {
			t.Errorf("expected 200 after wake, got %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("test timed out")
	}
}

func TestHandleRequest_ExpiredCache_WakesSuccessfully(t *testing.T) {
	// A target that was healthy but has a stale cache hits the wake path.
	// When the health check in waitForWake returns true, the request is proxied.
	tp := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now().Add(-15 * time.Second) // stale cache
	tp.machine.mu.Unlock()
	tp.health.setResult(true)

	proxy := httptest.NewServer(http.HandlerFunc(tp.svc.handleRequest))
	defer proxy.Close()

	result := make(chan int, 1)
	go func() {
		resp := doRequest(t, proxy.URL)
		resp.Body.Close()
		result <- resp.StatusCode
	}()

	tp.clock.BlockUntil(3)
	tp.clock.Advance(tp.svc.config.PollInterval)

	select {
	case code := <-result:
		if code != 200 {
			t.Errorf("expected 200 after expired cache + healthy check, got %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("test timed out")
	}
}

func TestHandleRequest_BackendError(t *testing.T) {
	// Create backend, close it immediately so any proxy connection fails.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	backendURL := backend.URL
	backend.Close()

	tp := newTestProxy(t, nil)
	tp.route.Destination = backendURL
	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now()
	tp.machine.mu.Unlock()

	proxy := httptest.NewServer(http.HandlerFunc(tp.svc.handleRequest))
	defer proxy.Close()

	resp := doRequest(t, proxy.URL)
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 for backend error, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// E2E scenario tests — two complete flows that document the app's purpose.
// ---------------------------------------------------------------------------

// TestE2E_ProxyToHealthyTarget verifies the golden path: a request arrives for
// a healthy, cached target and is proxied transparently to the backend. The
// response body, status, and LastActivity update are all checked.
func TestE2E_ProxyToHealthyTarget(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/data" {
			t.Errorf("backend got path %q, want /api/data", r.URL.Path)
		}
		w.Header().Set("X-Backend", "yes")
		w.WriteHeader(200)
		fmt.Fprint(w, "backend response")
	}))
	defer backend.Close()

	tp := newTestProxy(t, nil)
	tp.route.Destination = backend.URL
	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now()
	tp.machine.mu.Unlock()

	proxy := httptest.NewServer(http.HandlerFunc(tp.svc.handleRequest))
	defer proxy.Close()

	req, _ := http.NewRequest("GET", proxy.URL+"/api/data", nil)
	req.Host = testHostname
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("X-Backend") != "yes" {
		t.Error("response header X-Backend not forwarded from backend")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend response" {
		t.Errorf("body = %q, want %q", body, "backend response")
	}

	// LastActivity must be updated after a proxied request.
	before := tp.clock.Now().Add(-time.Hour)
	tp.machine.mu.RLock()
	activity := tp.machine.LastActivity
	tp.machine.mu.RUnlock()
	if !activity.After(before) {
		t.Error("LastActivity was not updated after proxied request")
	}
}

// TestE2E_WakeOnDemandAndProxy verifies the signature feature: a request
// arrives for a target that is down; the proxy sends WOL magic packets and
// polls until the target comes up, then proxies the original request.
func TestE2E_WakeOnDemandAndProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "awake")
	}))
	defer backend.Close()

	tp := newTestProxy(t, nil)
	tp.route.Destination = backend.URL
	tp.machine.mu.Lock()
	tp.machine.IsHealthy = false
	tp.machine.mu.Unlock()
	tp.health.setResult(false)

	proxy := httptest.NewServer(http.HandlerFunc(tp.svc.handleRequest))
	defer proxy.Close()

	result := make(chan *http.Response, 1)
	go func() {
		req, _ := http.NewRequest("GET", proxy.URL+"/wake-me", nil)
		req.Host = testHostname
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("request failed: %v", err)
			return
		}
		result <- resp
	}()

	// Wait for waitForWake to register its tickers/timer before advancing time.
	tp.clock.BlockUntil(3)

	// WOL packet must be sent with the configured MAC and broadcast address.
	tp.clock.Advance(500 * time.Millisecond)
	tp.wol.waitForCalls(t, 1, 5*time.Second)

	tp.wol.mu.Lock()
	call := tp.wol.calls[0]
	tp.wol.mu.Unlock()
	if call.mac != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("WOL MAC = %q, want AA:BB:CC:DD:EE:FF", call.mac)
	}
	if call.ip != "255.255.255.255" {
		t.Errorf("WOL broadcast IP = %q, want 255.255.255.255", call.ip)
	}

	// Simulate the target coming online; next health-check tick resolves the wait.
	tp.health.setResult(true)
	tp.clock.Advance(500 * time.Millisecond)

	select {
	case resp := <-result:
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("status = %d, want 200 after wake", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "awake" {
			t.Errorf("body = %q, want %q", body, "awake")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for wake-and-proxy to complete")
	}
}

// ---------------------------------------------------------------------------
// Boundary tests — kill CONDITIONALS_BOUNDARY mutants on >= 300 checks,
// method-default logic, and inactivity/cache duration thresholds.
// ---------------------------------------------------------------------------

func TestHTTPHealthChecker_Check_Status300(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(300)
	}))
	defer backend.Close()
	hc := NewHTTPHealthChecker(noopLogger{}, RealClock{})
	if hc.Check(context.Background(), backend.URL+"/health", "test") {
		t.Error("expected Check to return false for status 300 (>= 300 is unhealthy)")
	}
}

func TestShutdownTarget_HTTP_Status300(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(300)
	}))
	defer backend.Close()
	tp := newTestProxy(t, nil)
	tp.machine.Config.SSHHost = ""
	tp.machine.Config.SSHUser = ""
	tp.machine.Config.SSHKeyPath = ""
	tp.machine.Config.ShutdownCommand = ""
	tp.machine.Config.ShutdownHTTPUrl = backend.URL + "/shutdown"
	if err := tp.svc.shutdownMachine(testMachineName); err == nil {
		t.Fatal("expected error for status 300 (>= 300 is failure)")
	}
}

func TestShutdownTarget_HTTP_CustomMethodHonored(t *testing.T) {
	var gotMethod string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(200)
	}))
	defer backend.Close()
	tp := newTestProxy(t, nil)
	tp.machine.Config.SSHHost = ""
	tp.machine.Config.SSHUser = ""
	tp.machine.Config.SSHKeyPath = ""
	tp.machine.Config.ShutdownCommand = ""
	tp.machine.Config.ShutdownHTTPUrl = backend.URL + "/shutdown"
	tp.machine.Config.ShutdownHTTPMethod = "DELETE"
	if err := tp.svc.shutdownMachine(testMachineName); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != "DELETE" {
		t.Errorf("expected method DELETE, got %q (custom method must not be overwritten with POST)", gotMethod)
	}
}

func TestCheckInactiveTargets_ExactThreshold_NoShutdown(t *testing.T) {
	tp := newTestProxy(t, nil)
	threshold := 30 * time.Minute
	tp.machine.Config.InactivityThreshold = threshold
	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastActivity = tp.clock.Now().Add(-threshold) // exactly at threshold, not over
	tp.machine.mu.Unlock()
	tp.svc.checkInactiveMachines()
	select {
	case <-tp.ssh.done:
		t.Error("shutdown must not trigger when inactiveDuration == threshold (> not >=)")
	default:
	}
}

func TestHealthCacheStatus_ExactBoundary_Cached(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now().Add(-tp.svc.config.HealthCacheDuration) // age == duration exactly
	cached, reason := tp.svc.healthCacheStatus(tp.machine)
	if !cached {
		t.Errorf("expected cache still valid when age == HealthCacheDuration (> not >=), reason: %s", reason)
	}
}

func TestRealClock_ProvidesWorkingTimeSources(t *testing.T) {
	c := RealClock{}

	if c.Now().IsZero() {
		t.Error("Now returned the zero time")
	}
	if c.After(time.Millisecond) == nil {
		t.Error("After returned a nil channel")
	}

	ticker := c.NewTicker(time.Millisecond)
	defer ticker.Stop()
	select {
	case <-ticker.C():
	case <-time.After(5 * time.Second):
		t.Fatal("real ticker never fired")
	}
}

func TestWakeAndWait_ConcurrentRequests_JoinSingleWake(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.health.setResult(false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { tp.svc.wakeAndWait(ctx, tp.machine) }()
	// 1 After (timeout) + 2 tickers (poll, wol) registered once waitForWake is entered.
	tp.clock.BlockUntil(3)

	go func() { tp.svc.wakeAndWait(ctx, tp.machine) }()
	// The joiner reaches waitForWake too, registering a second set of 3.
	// Its SendWOL, if any, is recorded before those registrations.
	tp.clock.BlockUntil(6)

	if got := tp.wol.callCount(); got != 1 {
		t.Errorf("expected the second request to join the in-progress wake (1 WOL packet), got %d", got)
	}
}

func TestWakeAndWait_FailedPollCycle_KeepsWakeHeld(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.health.setResult(false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { tp.svc.wakeAndWait(ctx, tp.machine) }()
	tp.clock.BlockUntil(3)

	// Drive a full poll cycle that finds the target still down. Both the WOL and
	// poll tickers come due; waiting for both to be consumed guarantees the wake
	// loop completed at least one iteration.
	tp.clock.Advance(tp.svc.config.PollInterval)
	waitFor(t, 5*time.Second, "the wake loop to consume both ticks", func() bool {
		return tp.wol.callCount() >= 2 && tp.health.checks() >= 1
	})
	before := tp.wol.callCount()

	go func() { tp.svc.wakeAndWait(ctx, tp.machine) }()
	tp.clock.BlockUntil(6)

	if got := tp.wol.callCount(); got != before {
		t.Errorf("expected the later request to join the in-progress wake, got %d extra WOL packet(s)", got-before)
	}
}

func TestBackgroundCheck_StampsLastCheckFromInjectedClock(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()

	clock := newManualClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))
	hc := NewHTTPHealthChecker(noopLogger{}, clock)

	machine := &Machine{
		Name:   testMachineName,
		Config: &MachineConfig{HealthCheck: backend.URL},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hc.StartBackgroundChecks(ctx, map[string]*Machine{testMachineName: machine}, time.Minute)
	if err := hc.WaitForInitialChecks(ctx); err != nil {
		t.Fatalf("initial checks did not complete: %v", err)
	}

	machine.mu.RLock()
	defer machine.mu.RUnlock()
	if !machine.IsHealthy {
		t.Error("expected machine healthy after a 200 background check")
	}
	if !machine.LastCheck.Equal(clock.Now()) {
		t.Errorf("expected LastCheck stamped from the injected clock (%v), got %v", clock.Now(), machine.LastCheck)
	}
}

func TestLoadConfig_SeedsLastActivityFromInjectedClock(t *testing.T) {
	clock := newManualClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	cfg, err := LoadConfig(writeTempConfig(t, validConfig), clock)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	for name, machine := range cfg.Machines {
		if !machine.LastActivity.Equal(clock.Now()) {
			t.Errorf("machine %s: expected LastActivity seeded from the injected clock (%v), got %v",
				name, clock.Now(), machine.LastActivity)
		}
	}
}

func TestBackgroundCheck_PeriodicTick_DowngradesToUnhealthy(t *testing.T) {
	var mu sync.Mutex
	healthy := true
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if healthy {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(500)
	}))
	defer backend.Close()

	clock := newManualClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))
	hc := NewHTTPHealthChecker(noopLogger{}, clock)

	machine := &Machine{
		Name:   testMachineName,
		Config: &MachineConfig{HealthCheck: backend.URL},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const interval = time.Minute
	hc.StartBackgroundChecks(ctx, map[string]*Machine{testMachineName: machine}, interval)
	if err := hc.WaitForInitialChecks(ctx); err != nil {
		t.Fatalf("initial checks did not complete: %v", err)
	}
	// The interval ticker is registered only after the initial check completes.
	clock.BlockUntil(1)

	mu.Lock()
	healthy = false
	mu.Unlock()

	clock.Advance(interval)

	waitFor(t, 5*time.Second, "the periodic check to mark the machine unhealthy", func() bool {
		machine.mu.RLock()
		defer machine.mu.RUnlock()
		return !machine.IsHealthy
	})

	machine.mu.RLock()
	defer machine.mu.RUnlock()
	if !machine.LastCheck.Equal(clock.Now()) {
		t.Errorf("expected LastCheck advanced to %v, got %v", clock.Now(), machine.LastCheck)
	}
}
