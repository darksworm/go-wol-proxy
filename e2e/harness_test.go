package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	tc "github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"
)

var httpClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: &http.Transport{DisableKeepAlives: true},
}

type suite struct {
	image, backend string
	privateKey     []byte
	publicKey      string
}

func buildSuite(t *testing.T) suite {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Fatal("these bind-mount ownership tests require a local Linux Docker daemon")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir := t.TempDir()
	platform := "linux/" + runtime.GOARCH
	must(t, os.MkdirAll(filepath.Join(dir, platform), 0o755))
	compileGo(t, "..", ".", filepath.Join(dir, platform, "doormouse"))
	dockerfile, err := os.ReadFile("../Dockerfile.release")
	must(t, err)
	must(t, os.WriteFile(filepath.Join(dir, "Dockerfile"), dockerfile, 0o644))
	var buildLog bytes.Buffer
	// Create without starting to build the release image once. Keeping this
	// container until all subtests finish also gives Testcontainers ownership
	// of image cleanup, including when a test fails.
	image, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: tc.ContainerRequest{FromDockerfile: tc.FromDockerfile{
			Context: dir, BuildArgs: map[string]*string{"TARGETPLATFORM": &platform},
			BuildLogWriter: &buildLog,
		}},
	})
	tc.CleanupContainer(t, image)
	if err != nil {
		t.Fatalf("release image build: %v\n%s", err, &buildLog)
	}
	backend := filepath.Join(dir, "backend")
	compileGo(t, ".", "./testdata/backend", backend)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	key, err := ssh.MarshalPrivateKey(private, "doormouse e2e")
	must(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	must(t, err)
	return suite{
		image: image.(*tc.DockerContainer).Image, backend: backend,
		privateKey: pem.EncodeToMemory(key), publicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
	}
}

func compileGo(t *testing.T, dir, pkg, output string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", output, pkg)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile %s: %v\n%s", pkg, err, output)
	}
}

type machine struct {
	dir, network string
	backend      tc.Container
}

func (s suite) machine(t *testing.T, config string, configUID, keyUID int) machine {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "config.toml"), []byte(config), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "ssh_key"), s.privateKey, 0o600))
	net, err := network.New(ctx)
	must(t, err)
	tc.CleanupNetwork(t, net)
	backend := startContainer(t, s.image,
		tc.WithEntrypoint("/backend"), tc.WithCmd(),
		tc.WithConfigModifier(func(c *container.Config) { c.User = "0:0" }),
		tc.WithFiles(tc.ContainerFile{HostFilePath: s.backend, ContainerFilePath: "/backend", FileMode: 0o755}),
		tc.WithEnv(map[string]string{
			"CONFIG_UID": strconv.Itoa(configUID), "KEY_UID": strconv.Itoa(keyUID), "SSH_PUBLIC_KEY": s.publicKey,
		}),
		tc.WithHostConfigModifier(func(h *container.HostConfig) {
			h.Mounts = []mount.Mount{{Type: mount.TypeBind, Source: dir, Target: "/fixtures"}}
		}),
		network.WithNetwork([]string{"backend"}, net),
		tc.WithExposedPorts("18080/tcp"),
		tc.WithWaitStrategy(wait.ForHTTP("/state").WithPort("18080/tcp")),
	)
	// Restore ownership before Testcontainers removes the backend and before
	// TempDir cleanup runs. The host runner can have any UID, including 1001
	// on GitHub Actions. No sudo or host-wide permission changes are needed.
	t.Cleanup(func() {
		execIn(t, backend, "chown", "-R", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "/fixtures")
	})
	return machine{dir: dir, network: net.Name, backend: backend}
}

func (m machine) proxyOptions(readOnly bool, uid int) []tc.ContainerCustomizer {
	return []tc.ContainerCustomizer{
		tc.WithConfigModifier(func(c *container.Config) {
			if uid != 1000 {
				c.User = fmt.Sprintf("%d:%d", uid, uid)
			}
		}),
		tc.WithHostConfigModifier(func(h *container.HostConfig) {
			// Enforce the kernel boundary explicitly; Docker often defaults to
			// zero, which would let an image with no capability pass these tests.
			h.Sysctls = map[string]string{"net.ipv4.ip_unprivileged_port_start": "1024"}
			h.Mounts = []mount.Mount{{Type: mount.TypeBind, Source: m.dir, Target: "/app"}}
			if readOnly {
				h.Mounts = []mount.Mount{
					{Type: mount.TypeBind, Source: filepath.Join(m.dir, "config.toml"), Target: "/app/config.toml", ReadOnly: true},
					{Type: mount.TypeBind, Source: filepath.Join(m.dir, "ssh_key"), Target: "/app/ssh_key", ReadOnly: true},
				}
			}
			if uid != 1000 {
				h.CapDrop = []string{"ALL"}
				h.CapAdd = []string{"NET_BIND_SERVICE"}
			}
		}),
		network.WithNetworkName(nil, m.network),
		tc.WithExposedPorts("443/tcp", "993/tcp"),
		tc.WithWaitStrategy(wait.ForListeningPort("443/tcp")),
	}
}

func startContainer(t *testing.T, image string, options ...tc.ContainerCustomizer) *tc.DockerContainer {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := tc.Run(ctx, image, options...)
	tc.CleanupContainer(t, c)
	if c != nil {
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("container %s logs:\n%s", c.GetContainerID(), containerLogs(t, c))
			}
		})
	}
	must(t, err)
	return c
}

type machineState struct {
	Awake            bool
	Wakes, Shutdowns int
}

func (m machine) state(t *testing.T) machineState {
	t.Helper()
	url, err := m.backend.PortEndpoint(context.Background(), "18080/tcp", "http")
	must(t, err)
	response, err := httpClient.Get(url + "/state")
	must(t, err)
	defer response.Body.Close()
	var state machineState
	must(t, json.NewDecoder(response.Body).Decode(&state))
	return state
}

func eventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

func execIn(t *testing.T, c tc.Container, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	code, reader, err := c.Exec(ctx, args, tcexec.Multiplexed())
	must(t, err)
	output, err := io.ReadAll(reader)
	must(t, err)
	if code != 0 {
		t.Fatalf("container command %v exited %d: %s", args, code, output)
	}
	return string(output)
}

func containerLogs(t *testing.T, c tc.Container) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reader, err := c.Logs(ctx)
	must(t, err)
	defer reader.Close()
	output, err := io.ReadAll(reader)
	must(t, err)
	return string(output)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

const configHeader = `port = ":443"
timeout = "5s"
poll_interval = "100ms"
health_check_interval = "100ms"
health_cache_duration = "100ms"
`

const machineFields = `name = "backend"
mac_address = "02:00:00:00:00:01"
broadcast_ip = "backend"
wol_port = 9009
ssh_host = "backend:2222"
ssh_user = "doormouse"
ssh_key_path = "/app/ssh_key"
shutdown_command = "suspend"
`

const modernConfig = configHeader + "[[machines]]\n" + machineFields + `
health_check = "http://backend:18080/health"
inactivity_threshold = "1s"
[[routes]]
machine = "backend"
hostname = "service.test"
destination = "http://backend:18080"
[[routes]]
machine = "backend"
listen_port = 993
destination = "backend:19090"
`

const legacyConfig = configHeader + "[[targets]]\n" + machineFields + `
health_endpoint = "http://backend:18080/health"
hostname = "service.test"
destination = "http://backend:18080"
`
