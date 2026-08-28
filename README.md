# doormouse

**The mouse that sleeps in front of the door.** A reverse proxy that wakes your
servers when someone knocks.

A home server spends most of its life idle, drawing power for nothing. Turning it
off saves that power, but then your services are gone when you actually want them.

doormouse closes that gap. It sits in front of a sleeping machine and listens.
When a request arrives, it sends a Wake-on-LAN magic packet, waits for the host to
boot, and forwards the request. The client sees one slow response instead of a
connection error. Once the machine has been idle long enough, doormouse suspends
it again.

It handles HTTP and raw TCP, so the same proxy can front a web app and `ssh`.

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

## Building from source

```bash
go build -o doormouse .
go test -race ./...
docker build -t doormouse .
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
