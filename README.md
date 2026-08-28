# Go WOL Proxy

A Wake-on-LAN proxy service written in Go that automatically wakes up servers when requests are made to them.

## Features

- Proxies HTTP requests to configured target servers, routed by Host header
- :star: new :star: Forwards raw TCP too — ssh and anything else that isn't HTTP
- Automatically sends Wake-on-LAN packets to wake up offline servers
- Monitors server health with configurable intervals
- Caches health status to minimize latency for frequent requests
- Packaged as a Docker container for easy deployment
- :star: new :star: Supports graceful shutdown of servers after a period of inactivity

## Configuration

The service is configured using a TOML file. A **machine** is a host that gets woken
and shut down as one unit; a **route** is one way in to it. Many routes can point at
one machine, so a box you keep asleep is reachable however you like without
configuring it several times over.

```toml
port = ":8080"                  # Port to listen on for HTTP routes
timeout = "1m"                  # How long to wait for a machine to wake / a route to become ready
response_header_timeout = "1m"  # How long to wait for a response header, e.g. during slow or long-running requests/uploads
poll_interval = "5s"            # How often to check health while waiting
health_check_interval = "30s"   # Background health check frequency
health_cache_duration = "10s"   # How long to trust a cached health result

# Optional SSL configuration. Do not add these values unless you plan to use TLS/HTTPS
#ssl_certificate = "/path/to/cert.pem"
#ssl_certificate_key = "/path/to/key.pem"

[[machines]]
name = "nas"
mac_address = "7c:8b:ad:da:be:51"
broadcast_ip = "10.0.0.255"
wol_port = 9
health_check = "tcp://nas.local:22"   # liveness: is the box up?
inactivity_threshold = "1h"           # optional; omit to never shut it down

ssh_host = "nas.local:22"
ssh_user = "wol-proxy"
ssh_key_path = "/app/private_key"
shutdown_command = "sudo systemctl suspend"

# HTTP routes are matched on the Host header, so they share `port`.
[[routes]]
machine = "nas"
hostname = "files.home.com"
destination = "http://nas.local"

[[routes]]
machine = "nas"
hostname = "photos.home.com"
destination = "http://nas.local:2342"
health_check = "http://nas.local:2342/ping"   # readiness: can this route serve?

# A TCP route has no Host header to match on, so it gets its own port. This is how
# you put ssh — or anything else that isn't HTTP — behind the proxy.
[[routes]]
machine = "nas"
listen_port = 2222
destination = "nas.local:22"
```

See [config.toml](config.toml) for a fully commented example.

### Routes: hostname or listen port

A route is reached one way or the other, never both:

| | matched on | `destination` | shares `port` |
|---|---|---|---|
| HTTP route | `hostname` (Host header) | a URL | yes |
| TCP route | `listen_port` (its own socket) | `host:port` | no |

TCP carries no Host header, so a TCP route cannot be multiplexed onto the shared
port — it needs one of its own. Setting both `hostname` and `listen_port` on a route,
or neither, is a config error.

Connections on a TCP route are spliced byte for byte, so ssh host keys pass through
untouched: no man-in-the-middle, and no `known_hosts` churn. The proxy accepts your
connection immediately and wakes the machine while you wait, so your client waits on
the SSH version banner rather than on connect. If your box is slow to wake, raise
`timeout` here and `ConnectTimeout` in your `ssh_config`.

If you configure only TCP routes, `port` is still bound and answers 404 to
everything. That is expected.

> **A TCP route is a new way in to that service.** `listen_port = 2222` forwarding to
> `nas.local:22` makes that sshd reachable by anything that can reach the proxy, on
> every interface the proxy listens on. Authentication is unaffected — sshd still
> authenticates every connection — but a service that was previously only reachable
> on your LAN now depends on where the proxy is exposed. Bind the proxy somewhere you
> trust, and think before putting a TCP route in front of something that was relying
> on being hard to reach.

> [!TIP]
> **Let sshd close idle sessions so the proxy can suspend the box.** A forwarded ssh
> connection holds the machine awake for as long as the client stays connected, so a
> terminal left open all day keeps the box awake all day. Have sshd close idle
> sessions on its side and the proxy's `inactivity_threshold` will do the rest — for
> example, in `sshd_config` (requires OpenSSH 9.3 or later):
>
> ```text
> ChannelTimeout *=10m
> UnusedConnectionTimeout 1m
> ```
>
> Once sshd closes the connection, the proxy releases its hold and the inactivity
> countdown starts.

### Liveness vs readiness

There are two `health_check` fields and they answer different questions:

- **`machines[].health_check`** — *liveness*: is the box up? This drives Wake-on-LAN
  and the wake wait. It must not depend on any single service, or a crashed service
  would have the proxy firing magic packets at a machine that is already awake. A TCP
  dial to something always-on, like `tcp://nas.local:22`, is usually right.
- **`routes[].health_check`** — *readiness*: can this route serve? It gates forwarding
  for that route alone. It defaults to dialling the route's `destination`, inferring
  `:80`/`:443` from a URL scheme when the port is implicit. Point it at a real health
  endpoint when a service takes noticeably longer to come up than the box does —
  otherwise a wake that succeeds can still hand you a 502.

A route's readiness is only polled while its machine is live, so a machine that is
asleep most of the time generates no per-route traffic.

### Inactivity and shutdown

Each machine has one inactivity clock, fed by every route that points at it. Traffic
on any route keeps the whole machine alive.

A machine is shut down when it has had no traffic for `inactivity_threshold` **and**
has no forwarded connection open. The second condition matters: an ssh session is
idle by nature, and a large upload can outlast the threshold — neither should be
suspended out from under you.

Omitting `inactivity_threshold`, or setting it to `"0s"`, means the machine is never
shut down.

### Migrating from `[[targets]]`

The old `[[targets]]` format still loads. On startup the proxy translates it, logs
what it did, and writes the converted config next to the original as
`<name>.migrated.toml` — review it and `mv` it into place. Your original file is
never modified: it is often bind-mounted read-only or checked into a config repo, and
rewriting it would drop every comment. If the sidecar cannot be written, the
converted config is logged instead.

A config may use one format or the other, not both.

## Docker Usage

### Pull the Docker Image

```bash
docker pull ghcr.io/darksworm/go-wol-proxy:latest
```

### Run the Docker Container

```bash
# Note: network mode "host" is required for Wake-on-LAN packets to be sent correctly
docker run --network host -v /path/to/config.toml:/app/config.toml ghcr.io/darksworm/go-wol-proxy:latest
```

With `network_mode: host` every `listen_port` you configure is reachable on the host
directly. Prefer high ports — `listen_port = 2222` rather than `22` — so a TCP route
does not collide with the host's own sshd.

### Build the Docker Image Locally

```bash
docker build -t go-wol-proxy .
```

### Run the Locally Built Image

```bash
# Note: network mode "host" is required for Wake-on-LAN packets to be sent correctly
docker run --network host -v /path/to/config.toml:/app/config.toml go-wol-proxy
```

### Docker Compose Usage

Create a `docker-compose.yml` file with the following content:

```yaml
version: '3'

services:
  go-wol-proxy:
    image: ghcr.io/darksworm/go-wol-proxy:latest
    # Note: network mode "host" is required for Wake-on-LAN packets to be sent correctly
    network_mode: host
    restart: unless-stopped
    volumes:
      - ./config.toml:/app/config.toml
      # Optional: SSH private key for graceful shutdown
      - ./private_key:/app/private_key
```

Run the container with Docker Compose:

```bash
docker-compose up -d
```

## Signals

`SIGINT`/`SIGTERM` shuts the proxy down cleanly: it stops accepting, gives in-flight
HTTP requests up to 15 seconds to finish, closes the TCP listeners and exits 0.
In-flight TCP connections are dropped rather than drained — a forwarded ssh session
ends when the proxy stops.

## Graceful Shutdown Options

- Trigger a shutdown after a period of inactivity using SSH or HTTP.
- Exactly one mechanism must be configured per machine: SSH or HTTP, not both.

### SSH-based Shutdown
- Use `ssh_host`, `ssh_user`, `ssh_key_path`, and `shutdown_command`.
- The proxy executes the command over SSH when the machine is inactive.

### HTTP-based Shutdown
- Use `shutdown_http_url` to enable HTTP shutdown.
- `shutdown_http_method` defaults to `POST` if not specified.
- By default, any 2xx status code counts as success; set `shutdown_http_ok_status` to require a specific code.
- The HTTP client follows redirects and validates the final response code.
- The shutdown HTTP request uses a 10s timeout.

### Validation Rules
- You cannot set both `shutdown_http_url` and `shutdown_command` for the same machine.
- If `shutdown_http_method` and/or `shutdown_http_ok_status` are set, `shutdown_http_url` must also be set.

### Similar projects:
1. traefik-wol: [traefiklabs](https://plugins.traefik.io/plugins/642498d26d4f66a5a8a59d25/wake-on-lan), [github](https://github.com/MarkusJx/traefik-wol)
2. caddy-wol: [github](https://github.com/dulli/caddy-wol)

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and commit conventions.
