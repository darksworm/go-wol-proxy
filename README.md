# doormouse

**The mouse that sleeps in front of the door.** A reverse proxy that wakes your
servers when someone knocks.

Home servers spend most of their time doing nothing. They still draw power. You
could turn them off, but then your photos and files are gone when you want them.

doormouse fixes that. It sits in front of a sleeping machine and waits. When a
request arrives, it wakes the machine, waits for it to boot, and passes the
request on. The person waiting just sees one slow page load. When nobody has used
the machine for a while, doormouse puts it back to sleep.

It works for web apps and for plain TCP. So you can put Immich behind it, and
also `ssh`.

## What you need

- A machine that supports Wake-on-LAN. This lets you turn a computer on by
  sending it a network packet. Most wired network cards can do it, but you often
  have to switch it on in the BIOS first.
- A second machine that stays awake to run doormouse. A Raspberry Pi is plenty.
- Both machines on the same network, because the wake packet does not cross
  routers.

> [!NOTE]
> "Sleep" means whatever you tell it to mean. doormouse runs a command of your
> choice to put the machine down, so you can pick suspend, hibernate, or a full
> shutdown. Waking from a full shutdown is the most reliable. Waking from suspend
> is faster, but some machines refuse to come back. Test yours before you rely on
> it.

## Quick start

Create `config.toml`:

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

Then run it:

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

Point `photos.example.com` at the machine running doormouse. Open it. The NAS
wakes up.

> [!IMPORTANT]
> You need `network_mode: host`. Wake-on-LAN sends a broadcast packet, and
> Docker's default network cannot do that.

## How it works

1. A request arrives for one of your hostnames.
2. doormouse checks if the machine is awake. If it is, the request goes straight
   through.
3. If the machine is asleep, doormouse sends wake packets and waits.
4. Once the machine answers, doormouse checks that the app itself is ready.
5. The request is passed on. The reply goes back to the client.
6. When no traffic arrives for `inactivity_threshold`, doormouse puts the machine
   back to sleep.

## Machines and routes

A **machine** is a computer. doormouse wakes it and shuts it down as one unit.

A **route** is one way in to that machine. One machine can have many routes.
Your NAS might serve photos, files, and `ssh`. That is one machine and three
routes.

Traffic on any route keeps the whole machine awake.

### Two kinds of route

A route is reached one way or the other, never both.

| | Matched by | `destination` looks like | Shares `port` |
|---|---|---|---|
| **HTTP** | `hostname` | `http://nas.local:2283` | Yes |
| **TCP** | `listen_port` | `nas.local:22` | No |

An HTTP route reads the `Host` header, so many routes can share one port. Plain
TCP has no such header. Therefore each TCP route needs a port of its own.

```toml
# Web app. Matched on the hostname.
[[routes]]
machine = "nas"
hostname = "photos.example.com"
destination = "http://nas.local:2283"

# ssh. Gets its own port. Connect with: ssh -p 2222 you@doormouse-host
[[routes]]
machine = "nas"
listen_port = 2222
destination = "nas.local:22"
```

TCP traffic is copied byte for byte. Your `ssh` host keys pass through untouched,
so `known_hosts` does not complain.

> [!WARNING]
> A TCP route opens a new way in to that service. The example above makes your
> NAS `ssh` reachable through the doormouse host, on every network it listens on.
> Your login still needs a password or a key, because `sshd` checks that itself.
> But a service that only your home network could reach before now depends on
> where you run doormouse. Think about that before you expose something.

## Health checks

There are two `health_check` fields. They answer different questions.

**On a machine, it asks: is the box up?** This drives the wake. Point it at
something that is always running. Port 22 is a good choice:

```toml
health_check = "tcp://nas.local:22"
```

Do not point it at one app. If that app crashes, doormouse would think the whole
machine is off. It would then send wake packets to a machine that is already
awake.

**On a route, it asks: can this route serve traffic?** This holds a request back
until the app is ready. It defaults to opening a connection to `destination`,
which is usually enough.

Some apps take much longer to start than the machine does. For those, point the
route check at a real health page:

```toml
health_check = "http://nas.local:2283/api/server/ping"
```

Without this, a wake can succeed and the request can still fail. The machine is
up, but the app is not listening yet.

Three forms work: `tcp://host:port`, `http://...`, and `https://...`.

> [!NOTE]
> Route checks only run while the machine is awake. A machine that sleeps all day
> therefore creates no extra traffic.

## Going back to sleep

Set `inactivity_threshold` to say how long to wait:

```toml
inactivity_threshold = "1h"
```

doormouse puts a machine to sleep when both of these are true:

- No traffic on any of its routes for that long.
- No connection is still open.

The second rule matters. An `ssh` session can sit idle for hours while you read.
A large upload can take longer than the threshold. Neither should get cut off.

Leave the field out to never shut the machine down.

> [!TIP]
> An open `ssh` session keeps the machine awake, even when you are not typing. So
> a terminal you forgot about will keep it awake all night. Let `sshd` close idle
> sessions itself. Add this to `sshd_config` on the machine, then doormouse can
> do its job:
>
> ```text
> ChannelTimeout *=10m
> UnusedConnectionTimeout 1m
> ```
>
> This needs OpenSSH 9.3 or newer.

## Shutting down the machine

Pick one of two ways. You cannot use both on the same machine.

**Over `ssh`:**

```toml
ssh_host = "nas.local:22"
ssh_user = "doormouse"
ssh_key_path = "/app/ssh_key"
shutdown_command = "sudo systemctl suspend"
```

**Over HTTP:**

```toml
shutdown_http_url = "http://nas.local/api/shutdown"
shutdown_http_method = "POST"   # optional, POST by default
shutdown_http_ok_status = 202   # optional, any 2xx by default
```

## Bad config stops the proxy

doormouse checks your config at startup. If something is wrong, it refuses to
start and tells you why. It does not start up and then misbehave later.

It rejects:

- A machine with no `health_check`. Without one, every check fails. The machine
  then looks dead forever, so every request tries to wake it.
- A `destination` that cannot work. A TCP route needs `host:port`. An HTTP route
  needs a full URL that starts with `http://` or `https://`.
- A `health_check` that doormouse cannot run. It must start with `tcp://`,
  `http://`, or `https://`.
- Any key it does not know. A typo used to be ignored in silence, which is how
  configs ended up missing a health check.

> [!CAUTION]
> The last rule can break an upgrade. If your config has a key from an older
> version, doormouse will now refuse to start. Read the error, remove the key,
> and try again.

## Signals

`SIGINT` and `SIGTERM` shut doormouse down cleanly. It stops taking new
connections. Open HTTP requests get up to 15 seconds to finish. Open TCP
connections are dropped, so a forwarded `ssh` session ends when the proxy stops.

## Older config files

Early versions used one `[[targets]]` block per server. That still works, but it
will go away in a later release.

doormouse translates an old config at startup and writes the new version beside
it, as `<name>.migrated.toml`. Check that file, then use it instead of your old
one. Your original file is never changed.

A config can use one format or the other. It cannot mix them.

## Building it yourself

```bash
go build -o doormouse .
go test ./...
```

```bash
docker build -t doormouse .
```

## Similar projects

- [traefik-wol](https://github.com/MarkusJx/traefik-wol), a plugin for Traefik.
- [caddy-wol](https://github.com/dulli/caddy-wol), a plugin for Caddy.

Use one of those if you already run Traefik or Caddy. doormouse stands alone, and
it also forwards plain TCP.

## Contributing

Pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to set
up and how commit messages should look.

Readability of this file is checked with:

```bash
python3 scripts/flesch_kincaid.py README.md
```
