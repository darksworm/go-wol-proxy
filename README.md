<h1 align="center">
  <img src="assets/doormouse.svg" alt="doormouse" width="400">
</h1>

<p align="center">
  <strong>A reverse proxy that wakes your servers when someone knocks.</strong>
</p>

Most homelabs grow one machine that costs real money to run: a NAS with a stack
of spinning disks, a box with a GPU in it for LLM inference or transcoding, an
old workstation kept around for backups. You need it a few hours a day. It draws
power for all twenty-four. Turning it off saves that power, but then the services
on it are gone exactly when you want them.

doormouse closes that gap. Run it on the small machine you already keep on all
the time — a Raspberry Pi, a mini PC, whatever hosts your lighter services — and
put it in front of the expensive one. When a request arrives for a sleeping
machine, doormouse sends a Wake-on-LAN magic packet, waits for the host to boot,
and forwards the request. The client sees one slow response instead of a
connection error. Once the machine has been idle long enough, doormouse suspends
it again.

It handles HTTP and raw TCP, so the same proxy can front a web app and `ssh`. A
few things it fronts well:

- **A NAS** serving photos, media or backups in bursts, idle the rest of the day.
- **A GPU box** for local LLMs or transcoding, awake only while you are asking it
  something.
- **A game server** that sleeps until the first player connects.
- **A build or CI machine** you hit a handful of times a week.

## Requirements

- **A target host with Wake-on-LAN enabled.** Most wired NICs support it, but it
  is usually off by default in the BIOS and sometimes in the OS as well.
- **An always-on host to run doormouse.** A Raspberry Pi is enough.
- **Both hosts in the same broadcast domain.** Magic packets do not route.

> [!NOTE]
> "Sleep" is whatever your `shutdown_command` does, so suspend, hibernate and
> full poweroff all work. Poweroff wakes the most reliably. Suspend is faster but
> some boards will not resume from it. Test yours before you depend on it.

## Quick start

Write `config.toml`:

```toml
port = ":8080"
timeout = "1m"
poll_interval = "5s"
health_check_interval = "30s"
health_cache_duration = "10s"

[[machines]]
name = "nas"
mac_address = "7c:8b:ad:da:be:51"
broadcast_ip = "10.0.0.255"
health_check = "tcp://nas.local:22"
inactivity_threshold = "1h"

ssh_host = "nas.local:22"
ssh_user = "doormouse"
ssh_key_path = "/app/ssh_key"
shutdown_command = "sudo systemctl suspend"

[[routes]]
machine = "nas"
hostname = "photos.example.com"
destination = "http://nas.local:2283"
```

Then bring it up:

```yaml
services:
  doormouse:
    image: ghcr.io/darksworm/doormouse:latest
    network_mode: host
    restart: unless-stopped
    volumes:
      - ./config.toml:/app/config.toml
      - ./ssh_key:/app/ssh_key
```

```bash
docker compose up -d
```

> [!NOTE]
> doormouse runs in the container as UID 1000, the first user on most Linux
> hosts. A `0600` key owned by you is therefore readable as it is. If `id -u`
> says you are not 1000, either `chown 1000:1000 ssh_key` or set `user:` on the
> service to your own IDs from `id -u` and `id -g`. doormouse warns at startup if
> it cannot read the key.

Point `photos.example.com` at the doormouse host, then open
`http://photos.example.com:8080`. The NAS wakes.

> [!IMPORTANT]
> Host networking is required. Wake-on-LAN needs to broadcast, which Docker's
> default bridge network will not carry.
>
> Because host networking does not remap ports, the proxy is reachable on
> whatever `port` says. Set `port = ":80"` if you want the URL without a port, or
> put doormouse behind a front proxy that terminates TLS.

## How it works

1. A request arrives for a configured hostname or listen port.
2. doormouse checks cached machine health. If the host is up, it forwards
   immediately.
3. Otherwise it sends magic packets every 500ms and polls until the host answers
   or `timeout` expires.
4. It then waits for the *route* to be ready, which is a separate check.
5. It forwards the request and streams the response back.
6. When no route has seen traffic for `inactivity_threshold` and no connection is
   open, it runs the shutdown command.

## Machines and routes

A **machine** is a host. doormouse wakes and suspends it as one unit.

A **route** is one way in to that machine. One machine can carry many routes: a
NAS might serve photos, files and `ssh`. That is one machine and three routes.
Traffic on any route keeps the whole machine awake.

### Route types

A route is reached one way or the other, never both.

| | Matched on | `destination` | Shares `port` |
|---|---|---|---|
| **HTTP** | `hostname` (Host header) | `http://nas.local:2283` | Yes |
| **TCP** | `listen_port` (own socket) | `nas.local:22` | No |

HTTP routes multiplex on the Host header, so any number of them share one port.
Raw TCP carries no such header. Each TCP route therefore needs its own listener.

```toml
# HTTP route, matched on the Host header.
[[routes]]
machine = "nas"
hostname = "photos.example.com"
destination = "http://nas.local:2283"

# TCP route, own port: ssh -p 2222 you@doormouse-host
[[routes]]
machine = "nas"
listen_port = 2222
destination = "nas.local:22"
```

TCP connections are spliced byte for byte. The upstream host key reaches your
client unmodified, so there is no man-in-the-middle and no key substitution.

> [!NOTE]
> Your client still sees a different address. It connects to
> `doormouse-host:2222`, not `nas.local:22`, so OpenSSH looks up a different
> `known_hosts` entry and prompts on first use. To keep one entry for both paths,
> set `HostKeyAlias`:
>
> ```text
> Host nas-via-doormouse
>     HostName doormouse-host
>     Port 2222
>     HostKeyAlias nas.local
> ```

> [!WARNING]
> A TCP route is a new way in to that service. The example above exposes the
> NAS's `sshd` on every interface the doormouse host listens on. Authentication
> is unaffected, since `sshd` still authenticates every connection. But a service
> that was previously reachable only from your LAN now depends on where you run
> the proxy. Bind it somewhere you trust.

## Names and DNS

doormouse deals with two kinds of name, resolved in two different places.

**A route's `hostname` is what the client asks for.** It has to resolve to the
doormouse host. Not to the machine you want woken, which is asleep and cannot
answer.

**A route's `destination` is what doormouse dials.** It resolves on the doormouse
host, on your LAN.

So `photos.example.com` points at your Raspberry Pi, and doormouse forwards to
`nas.local:2283` behind it.

### Pointing a hostname at doormouse

Use whichever you already run:

- **A local DNS server**, such as Pi-hole, AdGuard Home, dnsmasq or your router.
  Add an A record for the hostname with the doormouse host's IP. A wildcard like
  `*.home.example.com` saves you a record per route.
- **`/etc/hosts` on one client.** Enough to try it out, tedious past that.
- **Public DNS**, if you own the domain. Point the A record at the doormouse host.

TCP routes are matched on a port, not a name, so any name that reaches the
doormouse host will do, including the bare IP.

> [!WARNING]
> A public A record holding a private address such as `10.0.0.5` is dropped by
> some resolvers as DNS rebinding. Use a local override instead.

### Names on the far side

`destination` and `health_check` have to resolve while the machine is asleep. A
name that only exists while the host is up cannot be used to wake it. Give the
machine a DHCP reservation and a static DNS entry, or write the IP straight into
the config.

## Liveness and readiness

There are two `health_check` fields and they answer different questions.

**`machines[].health_check` is liveness: is the host up?** It drives Wake-on-LAN
and the wake wait. Point it at something that is always running:

```toml
health_check = "tcp://nas.local:22"
```

Do not point it at a single application. If that application crashes, doormouse
concludes the host is down and fires magic packets at a machine that is already
awake.

**`routes[].health_check` is readiness: can this route serve?** It gates
forwarding for that route alone. It defaults to dialling `destination`, inferring
`:80` or `:443` from the URL scheme when the port is implicit.

Point it at a real health endpoint when a service takes noticeably longer to come
up than the host does:

```toml
health_check = "http://nas.local:2283/api/server/ping"
```

Otherwise a successful wake still yields a 502, because the host is up but the
service is not yet listening.

Three forms are accepted: `tcp://host:port`, `http://...` and `https://...`.

> [!NOTE]
> Readiness is polled only while the machine is live. A machine that sleeps all
> day therefore generates no per-route traffic.

## Idle shutdown

```toml
inactivity_threshold = "1h"
```

doormouse suspends a machine when both conditions hold:

- No route has seen traffic for `inactivity_threshold`.
- No forwarded connection is still open.

The second condition matters. An `ssh` session is idle by nature, and a large
upload can outlast the threshold. Neither should be cut off mid-flight.

Omit the field, or set `"0s"`, to never shut the machine down.

> [!TIP]
> An open `ssh` session holds the machine awake even while nothing is typed, so a
> forgotten terminal keeps it up all night. Let `sshd` close idle sessions itself
> and the threshold can do its job. In `sshd_config` on the target:
>
> ```text
> ChannelTimeout *=10m
> UnusedConnectionTimeout 1m
> ```
>
> Requires OpenSSH 9.3 or newer.

## Shutdown mechanisms

Configure exactly one per machine.

**Over SSH:**

```toml
ssh_host = "nas.local:22"
ssh_user = "doormouse"
ssh_key_path = "/app/ssh_key"
shutdown_command = "sudo systemctl suspend"
```

The key has to be readable by the user doormouse runs as, which in the container
is UID 1000. doormouse checks the key at startup and warns if it cannot open it,
because the key itself is only used much later, when the machine goes idle.

**Over HTTP:**

```toml
shutdown_http_url = "http://nas.local/api/shutdown"
shutdown_http_method = "POST"   # optional, defaults to POST
shutdown_http_ok_status = 202   # optional, defaults to any 2xx
```

## Config validation

doormouse validates the config at startup and refuses to run on a bad one, rather
than starting and misbehaving later. It rejects:

- **A machine with no `health_check`.** Every check would fail, the machine would
  look permanently dead, and every request would try to wake it.
- **A `destination` that cannot work.** TCP routes need `host:port`. HTTP routes
  need an absolute `http://` or `https://` URL. A schemeless value such as
  `nas.local:2283` parses as a URL scheme named `nas.local` and would otherwise
  502 every request with nothing in the logs.
- **A `health_check` the checker cannot dispatch on.** It must start with
  `tcp://`, `http://` or `https://`.
- **Any unrecognised key.** Typos used to decode silently to a zero value, which
  is the usual route to a missing health check.

> [!CAUTION]
> The last rule can break an upgrade. A config carrying a key from an older
> version will now fail to start. Read the error, drop the key, restart.

## Signals

`SIGINT` and `SIGTERM` trigger a graceful shutdown. doormouse stops accepting,
gives in-flight HTTP requests up to 15 seconds to finish, closes the TCP
listeners and exits 0. In-flight TCP connections are dropped rather than drained,
so a forwarded `ssh` session ends when the proxy stops.

## Migrating from `[[targets]]`

Early versions used one `[[targets]]` block per server. That format still loads,
but it will be removed in a future release.

On startup doormouse translates an old config, logs what it did, and writes the
result beside the original as `<name>.migrated.toml`. Review that file, then swap
it in. Your original is never modified, since it is often bind-mounted read-only
or checked into a config repo.

A config may use one format or the other, never both.

For migration output on the host, create a config directory before starting
Compose and copy your existing config into it:

```bash
mkdir -p conf
cp config.toml conf/config.toml
```

Mount that directory in place of the single config file:

```yaml
volumes:
  - ./conf:/app
  - ./ssh_key:/app/ssh_key:ro
```

The directory must be writable and the config readable by the container user.
If your host UID is 1000, files created by the commands above already have the
right owner. Otherwise, set `user: "<UID>:<GID>"` on the service, replacing the
placeholders with `id -u` and `id -g`. Alternatively, use
`sudo chown 1000:1000 conf conf/config.toml` and ensure the directory has owner
write permission. The migrated file is mode `0600`, owned by the container UID;
using your own UID lets you read and replace it without `sudo`.

With the quick-start single-file mount, `/app` is not writable by the container
user. doormouse logs the complete migrated config instead; retrieve it with
`docker compose logs doormouse`. The same fallback applies if a mounted config
directory is read-only or lacks write permission.

## Container images

Every release publishes an image to `ghcr.io/darksworm/doormouse`, built for
`linux/amd64` and `linux/arm64`. Four tags point at it:

| Tag | Points at |
| --- | --- |
| `0.4.1` | that exact release, and never moves |
| `0.4` | the newest patch in the 0.4 line |
| `0` | the newest release in the 0.x line |
| `latest` | the newest release |

`latest` is fine for trying doormouse out. Once it is proxying something you
care about, pin the exact version or the minor line, so an upgrade happens when
you choose it.

The image runs as UID 1000, not root, so anything you mount in has to be readable
by that user. On most Linux hosts you are 1000 already. If not, `chown 1000:1000`
the file or set `user:` on the service to your own IDs.

Ports below 1024 still work, because the binary carries the
`CAP_NET_BIND_SERVICE` capability that Docker grants by default. If you drop
capabilities, keep that one or doormouse will not start.

The file capability cannot grant privileges when `no-new-privileges` is enabled
(see the [kernel documentation](https://www.kernel.org/doc/html/latest/userspace-api/no_new_privs.html)).
For that setup, use ports at or above 1024, or arrange for the runtime to grant
`NET_BIND_SERVICE` to the process before execution. This also applies to
Kubernetes configurations with
[`allowPrivilegeEscalation: false`](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

Images up to and including 1.0.0 ran as root, so check both of those when you
upgrade past it.

## Building from source

```bash
go build -o doormouse .
go test -race ./...
```

To build a local container image, use Go and Docker:

```bash
bash scripts/build-container.sh doormouse:local
```

The build script compiles for your native architecture and packages the binary
with `Dockerfile.release`, so local and published images share the same non-root
runtime. Set `GOARCH=arm64` or `GOARCH=amd64` to cross-build; executing image build
steps for another architecture requires QEMU/binfmt emulation.

To build both release architectures with [GoReleaser](https://goreleaser.com),
install Docker Buildx and configure QEMU/binfmt emulation first:

```bash
goreleaser release --config .goreleaser.release.yml --snapshot --clean
```

## Similar projects

- [traefik-wol](https://github.com/MarkusJx/traefik-wol), a Traefik plugin.
- [caddy-wol](https://github.com/dulli/caddy-wol), a Caddy plugin.

Prefer those if you already run Traefik or Caddy. doormouse runs standalone and
also forwards raw TCP.

## Contributing

Pull requests welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and
commit conventions.

Docs aim for a Flesch-Kincaid grade of 9 or below. Many readers do not speak
English as a first language, so short sentences and plain phrasing help. Keep
the technical vocabulary, though: `liveness`, `Host header` and `broadcast
domain` are shorter and clearer than talking around them.
