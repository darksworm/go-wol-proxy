# Container end-to-end tests

Run from the repository root with Go and a local Linux Docker daemon:

```console
go -C e2e test -race -count=1 -timeout=5m -v ./...
```

The suite compiles the application, builds `Dockerfile.release` once, and uses
Testcontainers to manage isolated containers and networks. No prebuilt application
image, shell script, privileged host ports, or root test runner is required.
Test dependencies live in this module; ordinary `go test ./...` stays Docker-free.

Five proxy runs cover three scenarios:

| Scenario | Cases | What a failure catches |
| --- | --- | --- |
| Runtime lifecycle | Default UID 1000; overridden UID 1001 with only `NET_BIND_SERVICE` | Wrong runtime user/account, broken HTTP or raw TCP forwarding on ports 443/993, missing WOL packets, unreadable `0600` keys, failed authenticated SSH shutdown, unclean SIGTERM exit |
| Legacy migration | Writable config directory; read-only config file with a key owned by another UID | Wrong migration location/ownership/mode, modified original config, incomplete log fallback, missing startup warning, proxy failing to serve the legacy config |
| Capability boundary | Drop all capabilities | Executable starts without its required file capability, or fails for an unrelated reason |

The runtime cases start with different protocols so both HTTP and TCP must wake
the backend. The kernel's privileged-port threshold is explicitly set to 1024
inside each proxy container, preventing Docker defaults from hiding a missing
capability. Idle shutdown is observed on the backend, using the real ten-second
monitor interval; tests do not change production timing or call application
internals. Container logs are attached to failed tests and resources are cleaned
up by Testcontainers and Go test cleanup hooks.

The Go backend fixture implements real HTTP, TCP, UDP and SSH sockets. It accepts
only the expected magic packet and the test's public key, and records an SSH
`suspend` request as a transition to asleep. This verifies the application's
network behavior; physical NIC wake support and LAN broadcast delivery remain
deployment checks.

Pure configuration and SSH-path edge cases stay in the application unit tests.
