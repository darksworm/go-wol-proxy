package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

func (m *mockHealthChecker) StartBackgroundChecks(_ context.Context, _ map[string]*Machine, _ []*Route, _ time.Duration) {
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
	mu       sync.Mutex
	done     chan struct{}
	err      error
	once     sync.Once
	executed int
}

func newMockSSHExecutor() *mockSSHExecutor {
	return &mockSSHExecutor{done: make(chan struct{})}
}

func (m *mockSSHExecutor) ExecuteCommand(_, _, _, _ string) error {
	m.once.Do(func() { close(m.done) })
	m.mu.Lock()
	defer m.mu.Unlock()
	m.executed++
	return m.err
}

func (m *mockSSHExecutor) calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.executed
}

type recordingLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *recordingLogger) Info(msg string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(msg, args...))
}

func (l *recordingLogger) Error(msg string, args ...interface{}) { l.Info(msg, args...) }

func (l *recordingLogger) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
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
		Name:        testHostname,
		Machine:     machineState,
		Hostname:    testHostname,
		Destination: backendURL,
		HealthCheck: backendURL + "/health",
		IsReady:     true,
		LastCheck:   clock.Now(),
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

func TestCheckInactiveMachines_TrafficOnOneRouteKeepsTheMachineAlive(t *testing.T) {
	// Two routes to one box used to mean two targets with the same MAC, each with
	// its own inactivity clock. The quiet clock would suspend the machine while the
	// busy one was still serving.
	tp := newTestProxy(t, nil)
	tp.machine.Config.InactivityThreshold = 30 * time.Minute

	quiet := &Route{
		Name:        "quiet.local",
		Machine:     tp.machine,
		Hostname:    "quiet.local",
		Destination: tp.route.Destination,
	}
	tp.svc.config.Routes = append(tp.svc.config.Routes, quiet)
	tp.svc.config.RoutesByHostname["quiet.local"] = quiet

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.mu.Unlock()

	// An hour passes with traffic arriving only on the busy route.
	for i := 0; i < 4; i++ {
		tp.clock.Advance(15 * time.Minute)
		tp.machine.mu.Lock()
		tp.machine.LastActivity = tp.clock.Now()
		tp.machine.mu.Unlock()
		tp.svc.checkInactiveMachines()
	}

	if got := tp.ssh.calls(); got != 0 {
		t.Errorf("machine was shut down %d time(s) despite continuous traffic on one of its routes", got)
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
	path := filepath.Join(t.TempDir(), "doormouse-test.toml")
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

// mustContain fails unless err is non-nil and mentions each fragment. Config errors
// are read by an operator at startup, so what they say is the feature.
func mustContain(t *testing.T, err error, fragments ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a config error, got nil")
	}
	for _, fragment := range fragments {
		if !strings.Contains(err.Error(), fragment) {
			t.Errorf("error %q does not mention %q", err, fragment)
		}
	}
}

const machineAndRouteHeader = `
port = "8080"
timeout = "1m"
poll_interval = "5s"
health_check_interval = "30s"
health_cache_duration = "10s"
`

func TestLoadConfig_MachineNeedsAHealthCheck(t *testing.T) {
	// Without it every Check hits checkHTTP with an empty endpoint, fails with
	// `unsupported protocol scheme ""`, and leaves the machine permanently unhealthy:
	// every request then wakes it, spraying WOL for the whole timeout before a 503.
	_, err := LoadConfig(writeTempConfig(t, machineAndRouteHeader+`
[[machines]]
name = "nas"
mac_address = "AA:BB:CC:DD:EE:FF"

[[routes]]
machine = "nas"
hostname = "files.home.com"
destination = "http://nas.local"
`), RealClock{})

	mustContain(t, err, "nas", "health_check")
}

func TestLoadConfig_TCPRouteDestinationMustCarryAPort(t *testing.T) {
	// An explicit health_check skipped the only code path that validated destination,
	// so this used to load and then fail per connection — after the client had been
	// accepted and the machine woken.
	_, err := LoadConfig(writeTempConfig(t, machineAndRouteHeader+`
[[machines]]
name = "nas"
health_check = "tcp://nas.local:22"

[[routes]]
machine = "nas"
listen_port = 2222
destination = "nas.local"
health_check = "tcp://nas.local:22"
`), RealClock{})

	mustContain(t, err, "nas.local", "host:port")
}

func TestLoadConfig_HTTPRouteDestinationMustBeAnHTTPURL(t *testing.T) {
	// url.Parse accepts "nas.local:2342" happily — as scheme "nas.local" with opaque
	// body "2342", since dots are legal in scheme names. The reverse proxy is then
	// built on nonsense and 502s every request with nothing explaining why.
	_, err := LoadConfig(writeTempConfig(t, machineAndRouteHeader+`
[[machines]]
name = "nas"
health_check = "tcp://nas.local:22"

[[routes]]
machine = "nas"
hostname = "photos.home.com"
destination = "nas.local:2342"
health_check = "tcp://nas.local:2342"
`), RealClock{})

	mustContain(t, err, "nas.local:2342", "http")
}

func TestLoadConfig_RejectsUnknownKeys(t *testing.T) {
	// BurntSushi reports unmatched keys through MetaData.Undecoded, which LoadConfig
	// used to discard. A misspelling therefore decoded silently into a zero value,
	// which is how an empty health_check gets into a config in the first place.
	_, err := LoadConfig(writeTempConfig(t, machineAndRouteHeader+`
[[machines]]
name = "nas"
health_chek = "tcp://nas.local:22"

[[routes]]
machine = "nas"
hostname = "files.home.com"
destination = "http://nas.local"
`), RealClock{})

	mustContain(t, err, "health_chek")
}

func TestLoadConfig_MachineHealthCheckMustCarryAUsableScheme(t *testing.T) {
	// Requiring the key to be non-empty is not enough: Check routes tcp:// to a dialer
	// and everything else to an HTTP client, so a bare "nas.local:22" is parsed as a
	// URL with scheme "nas.local" and fails every single check. That is the same
	// permanently-unhealthy machine as an empty value, reached a different way.
	_, err := LoadConfig(writeTempConfig(t, machineAndRouteHeader+`
[[machines]]
name = "nas"
health_check = "nas.local:22"

[[routes]]
machine = "nas"
hostname = "files.home.com"
destination = "http://nas.local"
`), RealClock{})

	mustContain(t, err, "nas.local:22", "tcp://")
}

func TestLoadConfig_RouteHealthCheckMustCarryAUsableScheme(t *testing.T) {
	// A derived route check is always tcp://host:port, so only an explicit one can be
	// malformed — and an explicit one is exactly what skips the derivation path.
	_, err := LoadConfig(writeTempConfig(t, machineAndRouteHeader+`
[[machines]]
name = "nas"
health_check = "tcp://nas.local:22"

[[routes]]
machine = "nas"
hostname = "photos.home.com"
destination = "http://nas.local:2342"
health_check = "nas.local:2342/ping"
`), RealClock{})

	mustContain(t, err, "nas.local:2342/ping")
}

func TestLoadConfig_TCPHealthCheckMustCarryAPort(t *testing.T) {
	// tcp:// goes straight to SplitHostPort at dial time; catch a missing port here.
	_, err := LoadConfig(writeTempConfig(t, machineAndRouteHeader+`
[[machines]]
name = "nas"
health_check = "tcp://nas.local"

[[routes]]
machine = "nas"
hostname = "files.home.com"
destination = "http://nas.local"
`), RealClock{})

	mustContain(t, err, "tcp://nas.local", "host:port")
}

func TestLoadConfig_AcceptsEveryUsableHealthCheckScheme(t *testing.T) {
	// The three forms the checker actually understands must keep loading.
	for _, check := range []string{
		"tcp://nas.local:22",
		"http://nas.local/ping",
		"https://nas.local:8007/api2/json/ping",
	} {
		if _, err := LoadConfig(writeTempConfig(t, machineAndRouteHeader+`
[[machines]]
name = "nas"
health_check = "`+check+`"

[[routes]]
machine = "nas"
hostname = "files.home.com"
destination = "http://nas.local"
`), RealClock{}); err != nil {
			t.Errorf("health_check %q should load, got %v", check, err)
		}
	}
}

func TestLoadConfig_AcceptsTheShippedExampleConfig(t *testing.T) {
	// The documented example must survive every rule added here, or the rules are
	// wrong. Guards the strict unknown-key check against the config we ship.
	if _, err := LoadConfig("config.toml", RealClock{}); err != nil {
		t.Fatalf("the shipped config.toml no longer loads: %v", err)
	}
}

func TestMigrateConfigFile_OutputLoadsUnderTheSameRules(t *testing.T) {
	// The sidecar is offered to operators as a drop-in replacement, so it has to pass
	// the validation the loader now applies. A migration that emits a config the
	// loader rejects is worse than no migration at all.
	path := writeTempConfig(t, validConfig)
	MigrateConfigFile(path, &recordingLogger{})

	migrated := strings.TrimSuffix(path, ".toml") + ".migrated.toml"
	if _, err := os.Stat(migrated); err != nil {
		t.Fatalf("migration wrote no sidecar: %v", err)
	}

	if _, err := LoadConfig(migrated, RealClock{}); err != nil {
		t.Fatalf("the migrated config does not load: %v", err)
	}
}

func TestLoadConfig_LegacyTargetWithoutHealthEndpointIsRejected(t *testing.T) {
	// A legacy target with no health_endpoint migrates to a machine with no
	// health_check, which is exactly the permanently-unhealthy case above. It should
	// fail at load, and the message should name the key the operator actually wrote.
	_, err := LoadConfig(writeTempConfig(t, machineAndRouteHeader+`
[[targets]]
name = "server"
hostname = "server.local"
destination = "http://192.168.1.10:80"
mac_address = "AA:BB:CC:DD:EE:FF"
`), RealClock{})

	mustContain(t, err, "server", "health_endpoint")
}

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

const machinesRoutesConfig = `
port = "8080"
timeout = "1m"
poll_interval = "5s"
health_check_interval = "30s"
health_cache_duration = "10s"

[[machines]]
name = "nas"
mac_address = "AA:BB:CC:DD:EE:FF"
broadcast_ip = "255.255.255.255"
wol_port = 9
health_check = "tcp://nas.local:22"
inactivity_threshold = "1h"
ssh_host = "nas.local:22"
ssh_user = "doormouse"
ssh_key_path = "/app/private_key"
shutdown_command = "sudo systemctl suspend"

[[routes]]
machine = "nas"
hostname = "files.home.com"
destination = "http://nas.local"
`

func TestLoadConfig_MachinesAndRoutes(t *testing.T) {
	cfg, err := LoadConfig(writeTempConfig(t, machinesRoutesConfig), RealClock{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	machine, ok := cfg.Machines["nas"]
	if !ok {
		t.Fatalf("expected machine 'nas', got %v", cfg.Machines)
	}
	if machine.Config.MacAddress != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("MacAddress = %q", machine.Config.MacAddress)
	}
	if machine.Config.HealthCheck != "tcp://nas.local:22" {
		t.Errorf("HealthCheck = %q", machine.Config.HealthCheck)
	}
	if machine.Config.InactivityThreshold != time.Hour {
		t.Errorf("InactivityThreshold = %v, want 1h", machine.Config.InactivityThreshold)
	}
	if machine.Config.ShutdownCommand != "sudo systemctl suspend" {
		t.Errorf("ShutdownCommand = %q", machine.Config.ShutdownCommand)
	}

	route, ok := cfg.RoutesByHostname["files.home.com"]
	if !ok {
		t.Fatalf("expected a route for files.home.com, got %v", cfg.RoutesByHostname)
	}
	if route.Destination != "http://nas.local" {
		t.Errorf("Destination = %q", route.Destination)
	}
	if route.Machine != machine {
		t.Error("route should point at the 'nas' machine")
	}
}

func TestLoadConfig_ManyRoutesShareOneMachine(t *testing.T) {
	cfg := machinesRoutesConfig + `
[[routes]]
machine = "nas"
hostname = "photos.home.com"
destination = "http://nas.local:2342"

[[routes]]
machine = "nas"
listen_port = 2222
destination = "nas.local:22"
`
	result, err := LoadConfig(writeTempConfig(t, cfg), RealClock{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Machines) != 1 {
		t.Errorf("Machines = %d, want 1", len(result.Machines))
	}
	if len(result.Routes) != 3 {
		t.Fatalf("Routes = %d, want 3", len(result.Routes))
	}

	machine := result.Machines["nas"]
	for _, route := range result.Routes {
		if route.Machine != machine {
			t.Errorf("route %s points at a different Machine value; all three must share one", route.Name)
		}
	}

	tcpRoutes := 0
	for _, route := range result.Routes {
		if route.IsTCP() {
			tcpRoutes++
			if route.ListenPort != 2222 {
				t.Errorf("TCP route ListenPort = %d, want 2222", route.ListenPort)
			}
			if route.Destination != "nas.local:22" {
				t.Errorf("TCP route Destination = %q", route.Destination)
			}
		}
	}
	if tcpRoutes != 1 {
		t.Errorf("TCP routes = %d, want 1", tcpRoutes)
	}
}

func TestLoadConfig_RouteReferencingUnknownMachine(t *testing.T) {
	cfg := machinesRoutesConfig + `
[[routes]]
machine = "typo"
hostname = "other.home.com"
destination = "http://nas.local"
`
	_, err := LoadConfig(writeTempConfig(t, cfg), RealClock{})
	if err == nil {
		t.Fatal("expected an error for a route referencing an undefined machine")
	}
	if !strings.Contains(err.Error(), "typo") {
		t.Errorf("error should name the unknown machine, got: %v", err)
	}
}

func TestLoadConfig_DuplicateMachineName(t *testing.T) {
	cfg := machinesRoutesConfig + `
[[machines]]
name = "nas"
mac_address = "11:22:33:44:55:66"
health_check = "tcp://other.local:22"
`
	_, err := LoadConfig(writeTempConfig(t, cfg), RealClock{})
	if err == nil {
		t.Fatal("expected an error for two machines sharing a name")
	}
	if !strings.Contains(err.Error(), "nas") {
		t.Errorf("error should name the duplicated machine, got: %v", err)
	}
}

func TestLoadConfig_MachineWithoutName(t *testing.T) {
	// No routes, so the only thing that can fail is the missing machine name.
	cfg := `
port = "8080"
timeout = "1m"
poll_interval = "5s"
health_check_interval = "30s"
health_cache_duration = "10s"

[[machines]]
mac_address = "AA:BB:CC:DD:EE:FF"
health_check = "tcp://nas.local:22"
`
	_, err := LoadConfig(writeTempConfig(t, cfg), RealClock{})
	if err == nil {
		t.Fatal("expected an error for a machine with no name")
	}
	if !strings.Contains(err.Error(), "name") {
		t.Errorf("error should point at the missing name, got: %v", err)
	}
}

func TestLoadConfig_DuplicateHostnameAcrossRoutes(t *testing.T) {
	cfg := machinesRoutesConfig + `
[[routes]]
machine = "nas"
hostname = "files.home.com"
destination = "http://nas.local:9999"
`
	_, err := LoadConfig(writeTempConfig(t, cfg), RealClock{})
	if err == nil {
		t.Fatal("expected an error for two routes sharing a hostname")
	}
	if !strings.Contains(err.Error(), "files.home.com") {
		t.Errorf("error should name the duplicated hostname, got: %v", err)
	}
}

func TestLoadConfig_DuplicateListenPortAcrossRoutes(t *testing.T) {
	cfg := machinesRoutesConfig + `
[[routes]]
machine = "nas"
listen_port = 2222
destination = "nas.local:22"

[[routes]]
machine = "nas"
listen_port = 2222
destination = "nas.local:23"
`
	_, err := LoadConfig(writeTempConfig(t, cfg), RealClock{})
	if err == nil {
		t.Fatal("expected an error for two routes sharing a listen port")
	}
	if !strings.Contains(err.Error(), "2222") {
		t.Errorf("error should name the duplicated port, got: %v", err)
	}
}

func TestLoadConfig_RouteMustHaveExactlyOneOfHostnameOrListenPort(t *testing.T) {
	tests := []struct {
		name  string
		route string
	}{
		{"neither", `
[[routes]]
machine = "nas"
destination = "http://nas.local"
`},
		{"both", `
[[routes]]
machine = "nas"
hostname = "both.home.com"
listen_port = 3333
destination = "http://nas.local"
`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadConfig(writeTempConfig(t, machinesRoutesConfig+tc.route), RealClock{})
			if err == nil {
				t.Fatal("expected an error: a route is reached by hostname or by listen port, never neither or both")
			}
		})
	}
}

func TestLoadConfig_LegacyAndNewFormatTogether(t *testing.T) {
	cfg := machinesRoutesConfig + `
[[targets]]
name = "old"
hostname = "old.home.com"
destination = "http://old.local"
health_endpoint = "http://old.local/ping"
mac_address = "99:88:77:66:55:44"
`
	_, err := LoadConfig(writeTempConfig(t, cfg), RealClock{})
	if err == nil {
		t.Fatal("expected an error when a config mixes [[targets]] with [[machines]]")
	}
}

func TestLoadConfig_MachineShutdownValidation(t *testing.T) {
	tests := []struct {
		name  string
		extra string
	}{
		{"both ssh and http shutdown", `shutdown_command = "sudo systemctl suspend"
shutdown_http_url = "http://nas.local/api/shutdown"`},
		{"http method without url", `shutdown_http_method = "PUT"`},
		{"http ok status without url", `shutdown_http_ok_status = 202`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := strings.Replace(machinesRoutesConfig,
				`shutdown_command = "sudo systemctl suspend"`, tc.extra, 1)
			_, err := LoadConfig(writeTempConfig(t, cfg), RealClock{})
			if err == nil {
				t.Fatal("expected a validation error")
			}
			if !strings.Contains(err.Error(), "nas") {
				t.Errorf("error should name the machine, got: %v", err)
			}
		})
	}
}

func TestLoadConfig_RouteHealthCheckExplicitOrDerived(t *testing.T) {
	cfg := machinesRoutesConfig + `
[[routes]]
machine = "nas"
hostname = "photos.home.com"
destination = "http://nas.local:2342"
health_check = "http://nas.local:2342/ping"

[[routes]]
machine = "nas"
listen_port = 2222
destination = "nas.local:22"
`
	result, err := LoadConfig(writeTempConfig(t, cfg), RealClock{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	explicit := result.RoutesByHostname["photos.home.com"]
	if explicit.HealthCheck != "http://nas.local:2342/ping" {
		t.Errorf("an explicit health_check should win, got %q", explicit.HealthCheck)
	}

	derived := result.RoutesByHostname["files.home.com"]
	if derived.HealthCheck != "tcp://nas.local:80" {
		t.Errorf("HTTP route without health_check should dial its destination, got %q", derived.HealthCheck)
	}

	tcpRoute := result.RoutesByListenPort[2222]
	if tcpRoute.HealthCheck != "tcp://nas.local:22" {
		t.Errorf("TCP route without health_check should dial its destination, got %q", tcpRoute.HealthCheck)
	}
}

func TestLoadConfig_RouteWithUndialableDestination(t *testing.T) {
	cfg := strings.Replace(machinesRoutesConfig,
		`destination = "http://nas.local"`, `destination = "nas.local"`, 1)
	_, err := LoadConfig(writeTempConfig(t, cfg), RealClock{})
	if err == nil {
		t.Fatal("expected an error for a destination that is neither a URL nor host:port")
	}
}

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

// writeSelfSignedCert writes a throwaway cert/key pair for 127.0.0.1 and returns
// their paths, so the TLS branch is exercised through LoadX509KeyPair as configured.
func writeSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestServeHTTP_ServesTLSWhenCertificatesAreConfigured(t *testing.T) {
	tp := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	tp.svc.config.SSLCertificate, tp.svc.config.SSLCertificateKey = writeSelfSignedCert(t)

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now()
	tp.machine.mu.Unlock()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	served := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/", tp.svc.handleRequest)
	go func() { served <- tp.svc.serveHTTP(ctx, &http.Server{Handler: mux}, listener) }()

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	url := "https://" + listener.Addr().String() + "/"

	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", url, nil)
		req.Host = testHostname
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if resp.TLS == nil {
		t.Error("expected the connection to be TLS")
	}

	// A cancelled context must shut the server down cleanly, not surface an error.
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("serveHTTP returned %v on shutdown, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveHTTP did not return after the context was cancelled")
	}
}

func TestServeHTTP_MissingCertificateIsReported(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.svc.config.SSLCertificate = filepath.Join(t.TempDir(), "absent.pem")
	tp.svc.config.SSLCertificateKey = filepath.Join(t.TempDir(), "absent.key")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	err = tp.svc.serveHTTP(context.Background(), &http.Server{}, listener)
	if err == nil {
		t.Fatal("expected an error when the configured certificate cannot be loaded")
	}
}

// ---------------------------------------------------------------------------
// TCP routes
// ---------------------------------------------------------------------------

// startEchoBackend returns the address of a TCP server that echoes what it reads.
func startEchoBackend(t *testing.T) string {
	t.Helper()
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backend.Close() })

	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(conn, conn)
				conn.Close()
			}()
		}
	}()
	return backend.Addr().String()
}

// newTCPTestProxy wires a TCP route on the shared test machine and starts serving
// it on an ephemeral port. Pass destination="" for an echo backend. It returns the
// proxy and the address to dial. The route must be fully configured before serving
// starts, so callers that need their own upstream pass it here.
func newTCPTestProxy(t *testing.T, destination string) (*testProxy, *Route, string) {
	t.Helper()
	tp := newTestProxy(t, nil)
	backendAddr := destination
	if backendAddr == "" {
		backendAddr = startEchoBackend(t)
	}

	route := &Route{
		Name:        ":0",
		Machine:     tp.machine,
		ListenPort:  1,
		Destination: backendAddr,
		HealthCheck: tcpScheme + backendAddr,
		IsReady:     true,
		LastCheck:   tp.clock.Now(),
	}
	tp.svc.config.Routes = []*Route{route}
	tp.svc.config.RoutesByHostname = map[string]*Route{}
	tp.svc.config.RoutesByListenPort = map[int]*Route{1: route}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go tp.svc.serveTCPRoute(ctx, listener, route)

	return tp, route, listener.Addr().String()
}

func TestTCPRoute_LiveMachineButUnreadyRoute_DoesNotDialUpstream(t *testing.T) {
	// Liveness says the box is up (sshd answers); this route's service has not
	// started yet. Dialing now would hand the client a closed connection.
	var dialed int32
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&dialed, 1)
			conn.Close()
		}
	}()

	tp, route, proxyAddr := newTCPTestProxy(t, upstream.Addr().String())

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now()
	tp.machine.mu.Unlock()

	route.mu.Lock()
	route.IsReady = false
	route.LastCheck = time.Time{}
	route.mu.Unlock()

	tp.health.setResult(false)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Drive the readiness poll past its timeout.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		tp.clock.Advance(tp.svc.config.Timeout + time.Second)
		time.Sleep(5 * time.Millisecond)
		if atomic.LoadInt32(&dialed) > 0 {
			break
		}
	}

	if got := atomic.LoadInt32(&dialed); got != 0 {
		t.Errorf("upstream was dialled %d time(s); an unready route must not be forwarded to", got)
	}
}

func TestTCPRoute_ClientHalfCloseStillReceivesTheFullResponse(t *testing.T) {
	// `ssh host 'cat bigfile' > out` and scp both half-close the client write side
	// once the request is sent. Tearing the pair down when that direction ends would
	// truncate the response still streaming back.
	const payload = 256 * 1024

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(io.Discard, conn) // drain until the client half-closes
				time.Sleep(50 * time.Millisecond)
				conn.Write(bytes.Repeat([]byte("y"), payload))
			}()
		}
	}()

	tp, _, proxyAddr := newTCPTestProxy(t, upstream.Addr().String())
	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now()
	tp.machine.mu.Unlock()

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("give me the file\n")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading the response failed: %v", err)
	}
	if len(got) != payload {
		t.Errorf("received %d bytes, want %d; the response was cut short when the client half-closed", len(got), payload)
	}
}

func TestTCPRoute_ForwardsBytesBothWays(t *testing.T) {
	tp, _, proxyAddr := newTCPTestProxy(t, "")

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now()
	tp.machine.LastActivity = tp.clock.Now().Add(-time.Hour)
	tp.machine.mu.Unlock()

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("could not connect to the TCP route: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello sshd\n")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if got != "hello sshd\n" {
		t.Errorf("got %q, want the echoed payload", got)
	}

	tp.machine.mu.RLock()
	lastActivity := tp.machine.LastActivity
	tp.machine.mu.RUnlock()
	if !lastActivity.Equal(tp.clock.Now()) {
		t.Errorf("LastActivity = %v, want it bumped to %v by the TCP connection", lastActivity, tp.clock.Now())
	}

	if tp.wol.callCount() != 0 {
		t.Error("a live machine should not be sent WOL packets")
	}
}

func TestTCPRoute_WakesMachineBeforeForwarding(t *testing.T) {
	tp, _, proxyAddr := newTCPTestProxy(t, "")

	// The box is asleep; the health checker reports it up as soon as it is polled.
	tp.health.setResult(true)

	connErr := make(chan error, 1)
	payload := make(chan string, 1)
	go func() {
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			connErr <- err
			return
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("wake me\n")); err != nil {
			connErr <- err
			return
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			connErr <- err
			return
		}
		payload <- line
	}()

	tp.wol.waitForCalls(t, 1, 5*time.Second)

	// Let the wake poll fire.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		tp.clock.Advance(tp.svc.config.PollInterval)
		select {
		case line := <-payload:
			if line != "wake me\n" {
				t.Errorf("got %q, want the echoed payload", line)
			}
			return
		case err := <-connErr:
			t.Fatalf("connection failed: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("connection was never forwarded after the machine woke")
}

func TestCheckInactiveMachines_OpenConnectionBlocksShutdown(t *testing.T) {
	// An SSH session is idle by nature: hours can pass with no bytes moving. Timing
	// out on LastActivity alone would suspend the box under a logged-in user.
	tp, _, proxyAddr := newTCPTestProxy(t, "")
	tp.machine.Config.InactivityThreshold = 30 * time.Minute

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now()
	tp.machine.mu.Unlock()

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hi\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 5*time.Second, "the forwarded connection to be counted", func() bool {
		return tp.machine.openConnections() == 1
	})

	// Go quiet for well past the threshold while the connection stays open.
	tp.clock.Advance(2 * time.Hour)
	tp.svc.checkInactiveMachines()

	if got := tp.ssh.calls(); got != 0 {
		t.Errorf("machine was shut down %d time(s) with a connection still open", got)
	}

	conn.Close()
	waitFor(t, 5*time.Second, "the closed connection to be released", func() bool {
		return tp.machine.openConnections() == 0
	})

	tp.clock.Advance(2 * time.Hour)
	tp.svc.checkInactiveMachines()
	if got := tp.ssh.calls(); got != 1 {
		t.Errorf("shutdowns after the connection closed = %d, want 1", got)
	}
}

func TestCheckInactiveMachines_InactivityCountdownRestartsOnDisconnect(t *testing.T) {
	// A long-lived TCP session — an ssh login left open past the inactivity threshold
	// is the motivating case — must not carry a stale LastActivity from when it began.
	// Without a refresh on release, the very next inactivity tick after logout would
	// see (now - session start) > threshold and shut the machine down instantly.
	tp, _, proxyAddr := newTCPTestProxy(t, "")
	tp.machine.Config.InactivityThreshold = 30 * time.Minute

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now()
	tp.machine.mu.Unlock()

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("hi\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "the forwarded connection to be counted", func() bool {
		return tp.machine.openConnections() == 1
	})

	// Hold the session open well past the threshold, then disconnect.
	tp.clock.Advance(2 * time.Hour)
	conn.Close()
	waitFor(t, 5*time.Second, "the closed connection to be released", func() bool {
		return tp.machine.openConnections() == 0
	})

	// Immediately after logout the box must stay up: the countdown just restarted.
	tp.svc.checkInactiveMachines()
	if got := tp.ssh.calls(); got != 0 {
		t.Errorf("machine was shut down %d time(s) right after disconnect; countdown must restart on release", got)
	}

	// Stay quiet past the threshold: now the shutdown should fire.
	tp.clock.Advance(31 * time.Minute)
	tp.svc.checkInactiveMachines()
	if got := tp.ssh.calls(); got != 1 {
		t.Errorf("shutdowns after threshold elapsed post-disconnect = %d, want 1", got)
	}
}

func TestCheckInactiveMachines_InFlightHTTPRequestBlocksShutdown(t *testing.T) {
	// A slow upload can outlast the inactivity threshold. LastActivity is stamped when
	// the request starts, so without holding the connection the box would suspend
	// mid-transfer.
	release := make(chan struct{})
	tp := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	tp.machine.Config.InactivityThreshold = 30 * time.Minute

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now()
	tp.machine.mu.Unlock()

	r := httptest.NewRequest("GET", "/", nil)
	r.Host = testHostname
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		tp.svc.handleRequest(w, r)
		close(done)
	}()

	waitFor(t, 5*time.Second, "the in-flight request to be counted", func() bool {
		return tp.machine.openConnections() == 1
	})

	tp.clock.Advance(2 * time.Hour)
	tp.svc.checkInactiveMachines()
	if got := tp.ssh.calls(); got != 0 {
		t.Errorf("machine was shut down %d time(s) during an in-flight request", got)
	}

	close(release)
	<-done
	waitFor(t, 5*time.Second, "the finished request to be released", func() bool {
		return tp.machine.openConnections() == 0
	})
}

func TestCheckInactiveMachines_HTTPInactivityCountdownRestartsOnRequestEnd(t *testing.T) {
	// Same shape as the TCP disconnect test, on the HTTP path. A slow upload or
	// long download that outlasts the inactivity threshold must not trigger a
	// shutdown the moment the response finishes: the countdown restarts at the
	// end of the request, not at its start.
	release := make(chan struct{})
	tp := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	tp.machine.Config.InactivityThreshold = 30 * time.Minute

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now()
	tp.machine.mu.Unlock()

	r := httptest.NewRequest("GET", "/", nil)
	r.Host = testHostname
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		tp.svc.handleRequest(w, r)
		close(done)
	}()
	waitFor(t, 5*time.Second, "the in-flight request to be counted", func() bool {
		return tp.machine.openConnections() == 1
	})

	// Hold the request open well past the threshold, then finish it.
	tp.clock.Advance(2 * time.Hour)
	close(release)
	<-done
	waitFor(t, 5*time.Second, "the finished request to be released", func() bool {
		return tp.machine.openConnections() == 0
	})

	// Immediately after the response the box must stay up: the countdown restarted.
	tp.svc.checkInactiveMachines()
	if got := tp.ssh.calls(); got != 0 {
		t.Errorf("machine was shut down %d time(s) right after the request finished; countdown must restart on release", got)
	}

	// Stay quiet past the threshold: now the shutdown should fire.
	tp.clock.Advance(31 * time.Minute)
	tp.svc.checkInactiveMachines()
	if got := tp.ssh.calls(); got != 1 {
		t.Errorf("shutdowns after threshold elapsed post-response = %d, want 1", got)
	}
}

func TestServeHTTP_WaitsForInFlightRequestsBeforeReturning(t *testing.T) {
	// server.Shutdown() closes the listener first, which unblocks server.Serve() with
	// http.ErrServerClosed while Shutdown is still draining active handlers. If
	// serveHTTP returns on that signal, Start returns, main logs a clean shutdown and
	// exits — killing every in-flight response mid-write. The docstring on serveHTTP
	// promises the opposite; this test pins it.
	tp := newTestProxy(t, nil)

	release := make(chan struct{})
	handlerStarted := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		close(handlerStarted)
		<-release
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("drained"))
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()

	server := &http.Server{Handler: mux}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	served := make(chan error, 1)
	go func() { served <- tp.svc.serveHTTP(ctx, server, listener) }()

	// Fire the in-flight request against the real listener.
	responded := make(chan *http.Response, 1)
	reqErr := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/")
		if err != nil {
			reqErr <- err
			return
		}
		responded <- resp
	}()

	select {
	case <-handlerStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("handler never received the request")
	}

	// Ask the server to shut down while the handler is still blocked.
	cancel()

	// serveHTTP must not return while a handler is still running.
	select {
	case err := <-served:
		t.Fatalf("serveHTTP returned before the in-flight request drained: err=%v", err)
	case <-time.After(200 * time.Millisecond):
	}

	// Release the handler; the response must reach the client.
	close(release)

	select {
	case resp := <-responded:
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "drained" {
			t.Errorf("body = %q, want %q — in-flight response was cut off", body, "drained")
		}
	case err := <-reqErr:
		t.Fatalf("in-flight request was dropped by the shutdown: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("request never completed after the handler was released")
	}

	select {
	case err := <-served:
		if err != nil {
			t.Errorf("serveHTTP returned %v after graceful shutdown, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveHTTP did not return after the handler finished")
	}
}

// freePort reserves an ephemeral port and releases it, so a server can bind it by
// number. Inherently racy, but the window is tiny and it is the only way to know a
// port before Start binds it.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func TestStart_WaitsForHTTPDrainWhenTCPRoutesAreConfigured(t *testing.T) {
	// Start returns the first value sent on errs. A TCP route's serve goroutine
	// returns nil within microseconds of cancellation — long before serveHTTP has
	// finished draining — so whenever any TCP route exists that nil is what Start
	// returns, main logs a clean shutdown and exits mid-response. The drain added to
	// serveHTTP is correct on its own and completely bypassed here.
	release := make(chan struct{})
	handlerStarted := make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }

	tp := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(handlerStarted)
		<-release
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("drained"))
	}))
	// Registered after newTestProxy so it runs before that helper's backend.Close,
	// which would otherwise block forever on a still-parked handler when this test
	// fails early.
	t.Cleanup(releaseHandler)

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now()
	tp.machine.mu.Unlock()

	httpPort := freePort(t)
	tcpPort := freePort(t)

	tcpRoute := &Route{
		Name:        fmt.Sprintf(":%d", tcpPort),
		Machine:     tp.machine,
		ListenPort:  tcpPort,
		Destination: "127.0.0.1:1",
		HealthCheck: "tcp://127.0.0.1:1",
	}
	tp.svc.config.Routes = []*Route{tp.route, tcpRoute}
	tp.svc.config.RoutesByListenPort = map[int]*Route{tcpPort: tcpRoute}
	tp.svc.config.Port = fmt.Sprintf("127.0.0.1:%d", httpPort)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan error, 1)
	go func() { started <- tp.svc.Start(ctx) }()

	// Wait for the HTTP listener to come up, then send a request that blocks.
	waitFor(t, 5*time.Second, "the HTTP listener to accept", func() bool {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort))
		if err != nil {
			return false
		}
		c.Close()
		return true
	})

	responded := make(chan string, 1)
	reqErr := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", httpPort), nil)
		req.Host = testHostname
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			reqErr <- err
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		responded <- string(body)
	}()

	select {
	case <-handlerStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("backend never received the request")
	}

	cancel()

	// Start must not return while an HTTP handler is still running, however fast the
	// TCP route's goroutine unwinds.
	select {
	case err := <-started:
		t.Fatalf("Start returned before the in-flight request drained: err=%v", err)
	case <-time.After(300 * time.Millisecond):
	}

	releaseHandler()

	select {
	case body := <-responded:
		if body != "drained" {
			t.Errorf("body = %q, want %q — the response was cut off by shutdown", body, "drained")
		}
	case err := <-reqErr:
		t.Fatalf("in-flight request was dropped by the shutdown: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("request never completed")
	}

	select {
	case err := <-started:
		if err != nil {
			t.Errorf("Start returned %v on a cancelled context, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after the handler finished")
	}
}

func TestStart_CancelledContextShutsDownWithoutError(t *testing.T) {
	// main() treats a non-nil return as fatal, so a clean shutdown must return nil.
	tp := newTestProxy(t, nil)

	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()

	route := &Route{
		Name:        fmt.Sprintf(":%d", port),
		Machine:     tp.machine,
		ListenPort:  port,
		Destination: "127.0.0.1:1",
		HealthCheck: "tcp://127.0.0.1:1",
	}
	tp.svc.config.Routes = []*Route{route}
	tp.svc.config.RoutesByHostname = map[string]*Route{}
	tp.svc.config.RoutesByListenPort = map[int]*Route{port: route}
	tp.svc.config.Port = "127.0.0.1:0"

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- tp.svc.Start(ctx) }()

	// Give the listeners a moment to come up, then ask for shutdown.
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-result:
		if err != nil {
			t.Errorf("Start returned %v on a cancelled context, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after the context was cancelled")
	}

	// The TCP port must be released, or a restart would fail to bind.
	reclaimed, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Errorf("TCP route port %d was not released on shutdown: %v", port, err)
	} else {
		reclaimed.Close()
	}
}

func TestStart_ReportsWhichTCPPortCouldNotBeBound(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port

	tp := newTestProxy(t, nil)
	route := &Route{
		Name:        fmt.Sprintf(":%d", port),
		Machine:     tp.machine,
		ListenPort:  port,
		Destination: "127.0.0.1:1",
		HealthCheck: "tcp://127.0.0.1:1",
	}
	tp.svc.config.Routes = []*Route{route}
	tp.svc.config.RoutesByHostname = map[string]*Route{}
	tp.svc.config.RoutesByListenPort = map[int]*Route{port: route}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result := make(chan error, 1)
	go func() { result <- tp.svc.Start(ctx) }()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected Start to fail when a TCP route's port is already in use")
		}
		if !strings.Contains(err.Error(), fmt.Sprint(port)) {
			t.Errorf("error should name the port that could not be bound, got: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not report the unbindable TCP port; it kept running instead")
	}
}

// ---------------------------------------------------------------------------
// Legacy config migration
// ---------------------------------------------------------------------------

func TestMigrateLegacyTargets_CarriesMachineAndRouteFields(t *testing.T) {
	targets := []Target{{
		Name:                 "server",
		Hostname:             "server.local",
		Destination:          "http://192.168.1.10:80",
		HealthEndpoint:       "http://192.168.1.10:80/health",
		MacAddress:           "AA:BB:CC:DD:EE:FF",
		BroadcastIP:          "255.255.255.255",
		WolPort:              9,
		SSHHost:              "server.local:22",
		SSHUser:              "admin",
		SSHKeyPath:           "/key",
		ShutdownCommand:      "suspend",
		ShutdownHTTPMethod:   "",
		ShutdownHTTPOKStatus: 0,
		InactivityThreshold:  "1h",
	}}

	machines, routes := migrateLegacyTargets(targets)

	if len(machines) != 1 || len(routes) != 1 {
		t.Fatalf("got %d machines and %d routes, want 1 and 1", len(machines), len(routes))
	}

	m := machines[0]
	if m.Name != "server" {
		t.Errorf("machine Name = %q", m.Name)
	}
	if m.MacAddress != "AA:BB:CC:DD:EE:FF" || m.BroadcastIP != "255.255.255.255" || m.WolPort != 9 {
		t.Errorf("WOL fields not carried: %+v", m)
	}
	if m.SSHHost != "server.local:22" || m.SSHUser != "admin" || m.SSHKeyPath != "/key" || m.ShutdownCommand != "suspend" {
		t.Errorf("shutdown fields not carried: %+v", m)
	}
	if m.InactivityThreshold != "1h" {
		t.Errorf("InactivityThreshold = %q, want 1h", m.InactivityThreshold)
	}
	if m.HealthCheck != "http://192.168.1.10:80/health" {
		t.Errorf("machine HealthCheck should come from health_endpoint, got %q", m.HealthCheck)
	}

	r := routes[0]
	if r.Machine != "server" {
		t.Errorf("route Machine = %q, want server", r.Machine)
	}
	if r.Hostname != "server.local" {
		t.Errorf("route Hostname = %q", r.Hostname)
	}
	if r.Destination != "http://192.168.1.10:80" {
		t.Errorf("route Destination = %q", r.Destination)
	}
	if r.ListenPort != 0 {
		t.Errorf("a migrated legacy target is an HTTP route, got ListenPort %d", r.ListenPort)
	}
}

func TestMigrateLegacyTargets_HealthEndpointGatesBothLivenessAndReadiness(t *testing.T) {
	// A legacy health_endpoint did double duty: it decided whether the box was up
	// and whether the proxy could forward. Migration must preserve both, or a
	// migrated config starts forwarding to a service that has not finished booting.
	machines, routes := migrateLegacyTargets([]Target{{
		Name:           "server",
		Hostname:       "server.local",
		Destination:    "http://192.168.1.10:80",
		HealthEndpoint: "http://192.168.1.10:80/health",
	}})

	if machines[0].HealthCheck != "http://192.168.1.10:80/health" {
		t.Errorf("machine liveness = %q, want the legacy health_endpoint", machines[0].HealthCheck)
	}
	if routes[0].HealthCheck != "http://192.168.1.10:80/health" {
		t.Errorf("route readiness = %q, want the legacy health_endpoint", routes[0].HealthCheck)
	}
}

func TestMigrateConfigFile_WritesAdoptableSidecar(t *testing.T) {
	path := writeTempConfig(t, validConfig)
	logger := &recordingLogger{}

	MigrateConfigFile(path, logger)

	sidecar := filepath.Join(filepath.Dir(path), "doormouse-test.migrated.toml")
	written, err := os.ReadFile(sidecar)
	if err != nil {
		t.Fatalf("expected a migrated config beside the original: %v", err)
	}
	if !strings.Contains(string(written), "[[machines]]") || !strings.Contains(string(written), "[[routes]]") {
		t.Errorf("sidecar should be in the new format, got:\n%s", written)
	}
	if strings.Contains(string(written), "[[targets]]") {
		t.Errorf("sidecar should not carry the legacy format, got:\n%s", written)
	}
	// An adoptable config carries only keys the operator actually set.
	for _, unset := range []string{"= 0", `= ""`, "listen_port"} {
		if strings.Contains(string(written), unset) {
			t.Errorf("sidecar should omit unset keys but contains %q:\n%s", unset, written)
		}
	}
	if !strings.Contains(logger.all(), sidecar) {
		t.Errorf("operator should be told where the migrated config went, got: %s", logger.all())
	}

	// The whole point: the sidecar loads to the same model as the legacy original.
	fromLegacy, err := LoadConfig(path, RealClock{})
	if err != nil {
		t.Fatalf("legacy config failed to load: %v", err)
	}
	fromSidecar, err := LoadConfig(sidecar, RealClock{})
	if err != nil {
		t.Fatalf("migrated config failed to load: %v", err)
	}
	if len(fromSidecar.Machines) != len(fromLegacy.Machines) || len(fromSidecar.Routes) != len(fromLegacy.Routes) {
		t.Fatalf("migrated model differs: %d machines/%d routes vs %d/%d",
			len(fromSidecar.Machines), len(fromSidecar.Routes), len(fromLegacy.Machines), len(fromLegacy.Routes))
	}
	legacyRoute := fromLegacy.RoutesByHostname["server.local"]
	sidecarRoute := fromSidecar.RoutesByHostname["server.local"]
	if sidecarRoute == nil {
		t.Fatal("migrated config lost the server.local route")
	}
	if sidecarRoute.Destination != legacyRoute.Destination {
		t.Errorf("Destination %q != %q", sidecarRoute.Destination, legacyRoute.Destination)
	}
	if sidecarRoute.Machine.Config.HealthCheck != legacyRoute.Machine.Config.HealthCheck {
		t.Errorf("HealthCheck %q != %q", sidecarRoute.Machine.Config.HealthCheck, legacyRoute.Machine.Config.HealthCheck)
	}
	if sidecarRoute.Machine.Config.MacAddress != legacyRoute.Machine.Config.MacAddress {
		t.Errorf("MacAddress %q != %q", sidecarRoute.Machine.Config.MacAddress, legacyRoute.Machine.Config.MacAddress)
	}
}

func TestMigrateConfigFile_LeavesNewFormatAlone(t *testing.T) {
	path := writeTempConfig(t, machinesRoutesConfig)

	MigrateConfigFile(path, &recordingLogger{})

	sidecar := filepath.Join(filepath.Dir(path), "doormouse-test.migrated.toml")
	if _, err := os.Stat(sidecar); !os.IsNotExist(err) {
		t.Errorf("no sidecar should be written for a config already in the new format (stat err: %v)", err)
	}
}

func TestMigrateConfigFile_UnwritableDirectoryLogsTheConfigInstead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	// A root process ignores the directory mode, so there would be nothing to fall
	// back from.
	if probe := filepath.Join(dir, ".probe"); os.WriteFile(probe, []byte("x"), 0o600) == nil {
		os.Remove(probe)
		t.Skip("this user can write to a read-only directory; the fallback path is unreachable here")
	}

	logger := &recordingLogger{}
	MigrateConfigFile(path, logger)

	logged := logger.all()
	if !strings.Contains(logged, "[[machines]]") {
		t.Errorf("when the sidecar cannot be written the migrated config should be logged, got: %s", logged)
	}
}

func TestWarnUnreadableSSHKeys_WarnsWhenTheKeyCannotBeRead(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "ssh_key")
	if err := os.WriteFile(key, []byte("not-a-real-key"), 0o000); err != nil {
		t.Fatal(err)
	}

	// A root process ignores the file mode, so there would be nothing to warn about.
	if _, err := os.ReadFile(key); err == nil {
		t.Skip("this user can read a 0000 file; the warning is unreachable here")
	}

	logger := &recordingLogger{}
	warnUnreadableSSHKeys(sshKeyConfig(key), logger)

	if !strings.Contains(logger.all(), "cannot read ssh_key_path") {
		t.Errorf("an unreadable key should be reported at startup, got: %s", logger.all())
	}
}

func TestWarnUnreadableSSHKeys_SaysNothingWhenTheKeyIsReadable(t *testing.T) {
	key := filepath.Join(t.TempDir(), "ssh_key")
	if err := os.WriteFile(key, []byte("not-a-real-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	logger := &recordingLogger{}
	warnUnreadableSSHKeys(sshKeyConfig(key), logger)

	if logged := logger.all(); logged != "" {
		t.Errorf("a readable key should log nothing, got: %s", logged)
	}
}

func TestWarnUnreadableSSHKeys_SkipsMachinesWithoutAKey(t *testing.T) {
	logger := &recordingLogger{}
	warnUnreadableSSHKeys(sshKeyConfig(""), logger)

	if logged := logger.all(); logged != "" {
		t.Errorf("a machine that shuts down over HTTP has no key to check, got: %s", logged)
	}
}

func sshKeyConfig(keyPath string) *ProxyConfig {
	return &ProxyConfig{Machines: map[string]*Machine{
		"nas": {Name: "nas", Config: &MachineConfig{SSHKeyPath: keyPath}},
	}}
}

// ---------------------------------------------------------------------------
// HTTPHealthChecker tests
// ---------------------------------------------------------------------------

func TestEndpointHealthChecker_Check_Healthy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()

	hc := NewEndpointHealthChecker(noopLogger{}, RealClock{})
	result := hc.Check(context.Background(), backend.URL+"/health", "test")
	if !result {
		t.Error("expected Check to return true for 200 response")
	}
}

func TestEndpointHealthChecker_Check_Unhealthy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer backend.Close()

	hc := NewEndpointHealthChecker(noopLogger{}, RealClock{})
	result := hc.Check(context.Background(), backend.URL+"/health", "test")
	if result {
		t.Error("expected Check to return false for 500 response")
	}
}

func TestEndpointHealthChecker_Check_ConnectionRefused(t *testing.T) {
	hc := NewEndpointHealthChecker(noopLogger{}, RealClock{})
	result := hc.Check(context.Background(), "http://127.0.0.1:19998/health", "test")
	if result {
		t.Error("expected Check to return false for refused connection")
	}
}

// ---------------------------------------------------------------------------
// Goroutine-driven unit tests (ManualClock + BlockUntil)
// ---------------------------------------------------------------------------

func TestHealthChecker_Check_TCPScheme(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	t.Cleanup(func() { listener.Close() })

	hc := NewEndpointHealthChecker(noopLogger{}, RealClock{})

	if !hc.Check(context.Background(), "tcp://"+listener.Addr().String(), "test") {
		t.Error("expected a listening socket to be reported healthy")
	}

	listener.Close()
	if hc.Check(context.Background(), "tcp://"+listener.Addr().String(), "test") {
		t.Error("expected a closed socket to be reported unhealthy")
	}
}

func TestHealthChecker_Check_TCPSchemeRejectsGarbageAddress(t *testing.T) {
	hc := NewEndpointHealthChecker(noopLogger{}, RealClock{})
	if hc.Check(context.Background(), "tcp://", "test") {
		t.Error("expected an empty tcp address to be unhealthy")
	}
}

func TestDefaultHealthCheckForDestination(t *testing.T) {
	tests := []struct {
		destination string
		want        string
	}{
		{"http://nas.local", "tcp://nas.local:80"},
		{"https://nas.local", "tcp://nas.local:443"},
		{"http://nas.local:2342", "tcp://nas.local:2342"},
		{"https://nas.local:8443/base", "tcp://nas.local:8443"},
		{"nas.local:22", "tcp://nas.local:22"},
	}
	for _, tc := range tests {
		got, err := defaultHealthCheckForDestination(tc.destination)
		if err != nil {
			t.Errorf("defaultHealthCheckForDestination(%q) errored: %v", tc.destination, err)
			continue
		}
		if got != tc.want {
			t.Errorf("defaultHealthCheckForDestination(%q) = %q, want %q", tc.destination, got, tc.want)
		}
	}
}

func TestDefaultHealthCheckForDestination_RejectsHostWithoutPort(t *testing.T) {
	if _, err := defaultHealthCheckForDestination("nas.local"); err == nil {
		t.Error("a non-URL destination must carry a port; expected an error")
	}
}

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

// scriptedListener returns a canned sequence of Accept errors, then parks until it
// is closed. It stands in for a kernel that is transiently refusing to hand over
// connections — out of file descriptors, or a client that reset during the handshake.
type scriptedListener struct {
	mu     sync.Mutex
	calls  int
	errs   []error
	closed chan struct{}
	once   sync.Once
}

func newScriptedListener(errs ...error) *scriptedListener {
	return &scriptedListener{errs: errs, closed: make(chan struct{})}
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	i := l.calls
	l.calls++
	l.mu.Unlock()

	if i < len(l.errs) {
		return nil, l.errs[i]
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *scriptedListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *scriptedListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2222}
}

func (l *scriptedListener) acceptCalls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

func TestServeTCPRoute_RetriesTransientAcceptErrors(t *testing.T) {
	// Any Accept error used to end serveTCPRoute, which propagates through errs to
	// Start and then to log.Fatalf in main. A transient ECONNABORTED — a client that
	// resets during the handshake — would therefore take the whole proxy down,
	// including every HTTP route. net/http's own Serve retries these with backoff.
	listener := newScriptedListener(syscall.ECONNABORTED, syscall.ECONNABORTED, syscall.EMFILE)
	t.Cleanup(func() { listener.Close() })

	tp := newTestProxy(t, nil)
	tp.svc.clock = RealClock{} // the retry backoff sleeps; keep it real and tiny

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result := make(chan error, 1)
	go func() { result <- tp.svc.serveTCPRoute(ctx, listener, tp.route) }()

	// It must ride out every scripted error and still be accepting afterwards.
	waitFor(t, 5*time.Second, "the listener to be retried past its scripted errors", func() bool {
		return listener.acceptCalls() > len(listener.errs)
	})

	select {
	case err := <-result:
		t.Fatalf("serveTCPRoute gave up on a transient accept error: %v", err)
	default:
	}

	cancel()
	listener.Close()

	select {
	case err := <-result:
		if err != nil {
			t.Errorf("serveTCPRoute returned %v after cancellation, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveTCPRoute did not return after cancellation")
	}
}

func TestServeTCPRoute_GivesUpOnPermanentAcceptErrors(t *testing.T) {
	// Retrying must not swallow a genuinely broken listener: that error still has to
	// reach Start so the operator sees it instead of a silent hot loop.
	listener := newScriptedListener(errors.New("listener is broken beyond repair"))
	t.Cleanup(func() { listener.Close() })

	tp := newTestProxy(t, nil)
	tp.svc.clock = RealClock{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result := make(chan error, 1)
	go func() { result <- tp.svc.serveTCPRoute(ctx, listener, tp.route) }()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("serveTCPRoute returned nil on a permanent accept error")
		}
		if !strings.Contains(err.Error(), "beyond repair") {
			t.Errorf("error %v did not carry the underlying accept failure", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveTCPRoute hung on a permanent accept error instead of returning it")
	}
}

func TestCheckTCP_CapsTheDialItself(t *testing.T) {
	// The HTTP checks are capped by http.Client.Timeout, but a tcp:// check is bounded
	// only by whatever context reaches it — and waitForWake and markReadyIfHealthy
	// both pass the caller's context straight through with no deadline. Against a host
	// that drops SYNs rather than refusing them, one dial then blocks for the kernel's
	// full SYN-retry schedule (~130s on Linux), which is far longer than any configured
	// timeout and stalls the wake loop that is supposed to be retransmitting WOL.
	//
	// This asserts the cap is configured rather than timing a real blackhole: a
	// reliably-dropping address is not something a test can conjure portably.
	h := NewEndpointHealthChecker(noopLogger{}, RealClock{})

	if h.dialer.Timeout == 0 {
		t.Fatal("checkTCP dials with no timeout; a dropped SYN blocks for the kernel retry schedule")
	}
	if h.dialer.Timeout != healthCheckTimeout {
		t.Errorf("dial timeout = %v, want %v to match the HTTP check timeout",
			h.dialer.Timeout, healthCheckTimeout)
	}
	if h.client.Timeout != healthCheckTimeout {
		t.Errorf("HTTP check timeout = %v, want %v; the two checks should agree",
			h.client.Timeout, healthCheckTimeout)
	}
}

func TestHandleRequest_WakeLogNamesTheRoute(t *testing.T) {
	// The TCP path logs "waking for :2222", but the HTTP path logged a bare
	// "attempting to wake". With several HTTP routes on one machine, the logs could
	// not say which hostname pulled the box out of suspend.
	logger := &recordingLogger{}
	tp := newTestProxy(t, nil)
	tp.svc.logger = logger

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = false
	tp.machine.LastCheck = tp.clock.Now()
	tp.machine.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := httptest.NewRequest("GET", "/api/server/ping", nil).WithContext(ctx)
	r.Host = testHostname
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		tp.svc.handleRequest(w, r)
		close(done)
	}()

	// The wake itself never completes here; only the line it logs on the way in
	// matters. Cancelling the request context unwinds the goroutine afterwards.
	waitFor(t, 5*time.Second, "the wake log line to name the route", func() bool {
		return strings.Contains(logger.all(), "waking for "+testHostname)
	})

	cancel()
	<-done
}

// servesOneRequest drives handleRequest against a live, ready machine and returns
// everything that was logged. The backend is dead, so the request 502s — the log
// lines under test are written before any of that.
func servesOneRequest(t *testing.T, prepare func(*http.Request)) string {
	t.Helper()
	logger := &recordingLogger{}
	tp := newTestProxy(t, nil)
	tp.svc.logger = logger

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now()
	tp.machine.mu.Unlock()

	r := httptest.NewRequest("GET", "/api/server/ping", nil)
	r.Host = testHostname
	prepare(r)

	tp.svc.handleRequest(httptest.NewRecorder(), r)
	return logger.all()
}

func TestHandleRequest_LogsTheConnectingAddress(t *testing.T) {
	// "Which route woke the box" is only half the question; the other half is who
	// asked. Without the peer address the logs cannot tell a phone doing background
	// sync from a monitor polling a health endpoint.
	logged := servesOneRequest(t, func(r *http.Request) {
		r.RemoteAddr = "10.0.0.42:51234"
	})

	if !strings.Contains(logged, "10.0.0.42:51234") {
		t.Errorf("request log did not name the connecting address:\n%s", logged)
	}
}

func TestHandleRequest_LogsForwardedForAlongsideThePeer(t *testing.T) {
	// Behind a reverse proxy, RemoteAddr is that proxy and the original client is
	// only in X-Forwarded-For. Report both: the peer is what actually connected,
	// the header is a claim by whatever wrote it.
	logged := servesOneRequest(t, func(r *http.Request) {
		r.RemoteAddr = "10.0.0.1:443"
		r.Header.Set("X-Forwarded-For", "203.0.113.7")
	})

	if !strings.Contains(logged, "10.0.0.1:443") {
		t.Errorf("request log dropped the peer address:\n%s", logged)
	}
	if !strings.Contains(logged, "203.0.113.7") {
		t.Errorf("request log dropped the forwarded-for client:\n%s", logged)
	}
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

func TestHandleRequest_ExpiredReadinessCache_ServesWithoutWaitingForAPollTick(t *testing.T) {
	// Background checks refresh readiness every health_check_interval but the cache
	// only lasts health_cache_duration, so there is a window where readiness is stale
	// on a route that is perfectly fine. Requests in that window must not pay a full
	// poll interval of latency.
	tp := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now()
	tp.machine.mu.Unlock()

	tp.route.mu.Lock()
	tp.route.IsReady = true
	tp.route.LastCheck = tp.clock.Now().Add(-2 * tp.svc.config.HealthCacheDuration)
	tp.route.mu.Unlock()

	tp.health.setResult(true)

	r := httptest.NewRequest("GET", "/", nil)
	r.Host = testHostname
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		tp.svc.handleRequest(w, r)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleRequest waited for a poll tick instead of re-checking readiness immediately")
	}

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleRequest_LiveMachineButUnreadyRoute_WaitsInsteadOfForwarding(t *testing.T) {
	var served int32
	tp := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&served, 1)
		w.WriteHeader(http.StatusOK)
	}))

	// The box is up, but the service behind this route has not finished starting.
	tp.machine.mu.Lock()
	tp.machine.IsHealthy = true
	tp.machine.LastCheck = tp.clock.Now()
	tp.machine.mu.Unlock()

	tp.route.mu.Lock()
	tp.route.IsReady = false
	tp.route.LastCheck = time.Time{}
	tp.route.mu.Unlock()

	tp.health.setResult(false)

	r := httptest.NewRequest("GET", "/", nil)
	r.Host = testHostname
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		tp.svc.handleRequest(w, r)
		close(done)
	}()

	// Drive the clock forward until the handler returns, so a missing readiness gate
	// fails the assertions below instead of deadlocking the test.
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				tp.clock.Advance(tp.svc.config.Timeout + time.Second)
				time.Sleep(time.Millisecond)
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleRequest did not return")
	}

	if got := atomic.LoadInt32(&served); got != 0 {
		t.Errorf("backend served %d request(s); an unready route must not be forwarded to", got)
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
	if tp.wol.callCount() != 0 {
		t.Error("a live machine should not be sent WOL packets just because a route is unready")
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

func TestEndpointHealthChecker_Check_Status300(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(300)
	}))
	defer backend.Close()
	hc := NewEndpointHealthChecker(noopLogger{}, RealClock{})
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
	hc := NewEndpointHealthChecker(noopLogger{}, clock)

	machine := &Machine{
		Name:   testMachineName,
		Config: &MachineConfig{HealthCheck: backend.URL},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hc.StartBackgroundChecks(ctx, map[string]*Machine{testMachineName: machine}, nil, time.Minute)
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

func TestBackgroundChecks_RouteReadinessOnlyPolledWhileMachineIsLive(t *testing.T) {
	var mu sync.Mutex
	machineUp := false
	readinessHits := 0

	liveness := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		up := machineUp
		mu.Unlock()
		if !up {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer liveness.Close()

	readiness := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		readinessHits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer readiness.Close()

	clock := newManualClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))
	hc := NewEndpointHealthChecker(noopLogger{}, clock)

	machine := &Machine{Name: testMachineName, Config: &MachineConfig{HealthCheck: liveness.URL}}
	route := &Route{Name: testHostname, Machine: machine, Hostname: testHostname,
		Destination: readiness.URL, HealthCheck: readiness.URL}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const interval = time.Minute
	hc.StartBackgroundChecks(ctx, map[string]*Machine{testMachineName: machine}, []*Route{route}, interval)
	if err := hc.WaitForInitialChecks(ctx); err != nil {
		t.Fatalf("initial checks did not complete: %v", err)
	}

	mu.Lock()
	hitsWhileDown := readinessHits
	mu.Unlock()
	if hitsWhileDown != 0 {
		t.Errorf("route readiness was polled %d time(s) while the machine was down; a sleeping box should generate no per-route traffic", hitsWhileDown)
	}
	route.mu.RLock()
	ready := route.IsReady
	route.mu.RUnlock()
	if ready {
		t.Error("a route on a down machine must not be marked ready")
	}

	clock.BlockUntil(1)
	mu.Lock()
	machineUp = true
	mu.Unlock()
	clock.Advance(interval)

	waitFor(t, 5*time.Second, "route readiness to be polled once the machine is live", func() bool {
		route.mu.RLock()
		defer route.mu.RUnlock()
		return route.IsReady
	})
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
	hc := NewEndpointHealthChecker(noopLogger{}, clock)

	machine := &Machine{
		Name:   testMachineName,
		Config: &MachineConfig{HealthCheck: backend.URL},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const interval = time.Minute
	hc.StartBackgroundChecks(ctx, map[string]*Machine{testMachineName: machine}, nil, interval)
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
