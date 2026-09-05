package e2e

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/docker/docker/api/types/container"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestContainerImage(t *testing.T) {
	suite := buildSuite(t)

	t.Run("runtime", func(t *testing.T) {
		for _, uid := range []int{1000, 1001} {
			t.Run(strconv.Itoa(uid), func(t *testing.T) {
				t.Parallel()
				env := suite.machine(t, modernConfig, uid, uid)
				proxy := startContainer(t, suite.image, env.proxyOptions(false, uid)...)
				assertProcessUID(t, proxy, uid)
				if uid == 1000 && strings.TrimSpace(execIn(t, proxy, "id", "-un")) != "doormouse" {
					t.Fatal("UID 1000 must resolve to the dedicated doormouse account")
				}
				if state := env.state(t); state.Awake || state.Wakes != 0 {
					t.Fatalf("backend should initially be asleep: %+v", state)
				}

				// Start with HTTP for one UID and raw TCP for the other. Both wake
				// paths are covered without adding another container scenario.
				if uid == 1000 {
					assertHTTP(t, proxy)
					assertTCP(t, proxy)
				} else {
					assertTCP(t, proxy)
					assertHTTP(t, proxy)
				}
				if state := env.state(t); !state.Awake || state.Wakes == 0 {
					t.Fatalf("traffic did not wake the backend: %+v", state)
				}

				// Poll the backend directly so observing shutdown does not reset
				// the proxy's inactivity timer. Authentication accepts only the
				// public key paired with this test's mounted 0600 private key.
				eventually(t, 25*time.Second, func() bool {
					state := env.state(t)
					return !state.Awake && state.Shutdowns > 0
				})
				if logs := containerLogs(t, proxy); strings.Contains(logs, "cannot read ssh_key_path") {
					t.Fatalf("readable key was rejected: %s", logs)
				}
				grace := 3 * time.Second
				must(t, proxy.Stop(context.Background(), &grace))
				state, err := proxy.State(context.Background())
				must(t, err)
				if state.ExitCode != 0 {
					t.Fatalf("SIGTERM should shut down cleanly, exit code %d", state.ExitCode)
				}
			})
		}
	})

	t.Run("migration", func(t *testing.T) {
		for _, readOnly := range []bool{false, true} {
			name := "writable_directory"
			if readOnly {
				name = "read_only_file_and_unreadable_key"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				keyUID := 1000
				if readOnly {
					keyUID = 1001
				}
				env := suite.machine(t, legacyConfig, 1000, keyUID)
				proxy := startContainer(t, suite.image, env.proxyOptions(readOnly, 1000)...)
				assertHTTP(t, proxy)
				original, err := os.ReadFile(filepath.Join(env.dir, "config.toml"))
				must(t, err)
				if string(original) != legacyConfig {
					t.Fatal("migration modified the original config")
				}
				logs := containerLogs(t, proxy)
				if readOnly {
					if !strings.Contains(logs, "cannot read ssh_key_path /app/ssh_key") {
						t.Fatal("unreadable key must warn without preventing requests")
					}
					const marker = "the migrated config follows — save it yourself:\n"
					_, migrated, found := strings.Cut(logs, marker)
					if !found {
						t.Fatalf("missing migration fallback: %s", logs)
					}
					// The next timestamped log line ends the TOML block.
					lines := strings.Split(migrated, "\n")
					for i, line := range lines {
						if len(line) >= 5 && line[4] == '/' {
							lines = lines[:i]
							break
						}
					}
					assertMigratedConfig(t, strings.Join(lines, "\n"))
					if code, _, err := proxy.Exec(context.Background(), []string{"test", "!", "-e", "/app/config.migrated.toml"}); err != nil || code != 0 {
						t.Fatalf("unexpected sidecar in read-only setup: code=%d, error=%v", code, err)
					}
					return
				}
				file := filepath.Join(env.dir, "config.migrated.toml")
				info, err := os.Stat(file)
				must(t, err)
				stat := info.Sys().(*syscall.Stat_t)
				if info.Mode().Perm() != 0o600 || stat.Uid != 1000 || stat.Gid != 1000 {
					t.Fatalf("migration permissions: mode=%o owner=%d:%d", info.Mode().Perm(), stat.Uid, stat.Gid)
				}
				assertMigratedConfig(t, execIn(t, proxy, "cat", "/app/config.migrated.toml"))
			})
		}
	})

	t.Run("capability_required", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		proxy, err := tc.Run(ctx, suite.image, tc.WithHostConfigModifier(func(h *container.HostConfig) {
			h.CapDrop = []string{"ALL"}
		}))
		tc.CleanupContainer(t, proxy)
		// Runtimes may report exec failure from Start, or start the container
		// and report it through stderr and a nonzero process exit instead.
		var failure string
		if err != nil {
			failure = err.Error()
		} else {
			must(t, wait.ForExit().WaitUntilReady(ctx, proxy))
			state, err := proxy.State(ctx)
			must(t, err)
			failure = containerLogs(t, proxy)
			if state.ExitCode == 0 {
				t.Fatalf("missing capability should cause a nonzero exit: %s", failure)
			}
		}
		if !strings.Contains(strings.ToLower(failure), "operation not permitted") {
			t.Fatalf("exec must fail specifically because the file capability was dropped, got: %s", failure)
		}
	})
}

func assertProcessUID(t *testing.T, proxy tc.Container, uid int) {
	t.Helper()
	status := execIn(t, proxy, "cat", "/proc/1/status")
	seen := 0
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || (fields[0] != "Uid:" && fields[0] != "Gid:") {
			continue
		}
		seen++
		if len(fields) != 5 {
			t.Fatalf("malformed process identity: %s", line)
		}
		for _, value := range fields[1:] {
			if value != strconv.Itoa(uid) {
				t.Fatalf("process must run as %d:%d, got %s", uid, uid, line)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("missing UID/GID in process status: %s", status)
	}
}

func assertHTTP(t *testing.T, proxy tc.Container) {
	t.Helper()
	url, err := proxy.PortEndpoint(context.Background(), "443/tcp", "http")
	must(t, err)
	payload := "http request through " + t.Name()
	request, err := http.NewRequest(http.MethodPost, url+"/echo", strings.NewReader(payload))
	must(t, err)
	request.Host = "service.test"
	response, err := httpClient.Do(request)
	must(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	must(t, err)
	if response.StatusCode != http.StatusCreated || response.Header.Get("X-Backend") != "doormouse-e2e" || string(body) != payload {
		t.Fatalf("HTTP forwarding: status=%d headers=%v body=%q", response.StatusCode, response.Header, body)
	}
}

func assertTCP(t *testing.T, proxy tc.Container) {
	t.Helper()
	address, err := proxy.PortEndpoint(context.Background(), "993/tcp", "")
	must(t, err)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	must(t, err)
	defer conn.Close()
	must(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	payload := []byte("raw TCP\x00through " + t.Name())
	_, err = conn.Write(payload)
	must(t, err)
	must(t, conn.(*net.TCPConn).CloseWrite())
	body, err := io.ReadAll(conn)
	must(t, err)
	if !bytes.Equal(body, append([]byte("tcp:"), payload...)) {
		t.Fatalf("TCP forwarding after half-close: got %q", body)
	}
}

func assertMigratedConfig(t *testing.T, data string) {
	t.Helper()
	var config struct {
		Machines []struct{ Name, SSHKeyPath string }               `toml:"machines"`
		Routes   []struct{ Machine, Hostname, Destination string } `toml:"routes"`
		Targets  []any                                             `toml:"targets"`
	}
	_, err := toml.Decode(data, &config)
	must(t, err)
	if len(config.Targets) != 0 || len(config.Machines) != 1 || len(config.Routes) != 1 ||
		config.Machines[0].Name != "backend" || config.Routes[0].Machine != "backend" ||
		config.Routes[0].Hostname != "service.test" || config.Routes[0].Destination != "http://backend:18080" {
		t.Fatalf("incorrect migration: %s", data)
	}
}
