# Go WOL Proxy

A Wake-on-LAN proxy service written in Go that automatically wakes up servers when requests are made to them.

## Features

- Proxies HTTP requests to configured target servers
- Automatically sends Wake-on-LAN packets to wake up offline servers
- Monitors server health with configurable intervals
- Caches health status to minimize latency for frequent requests
- Packaged as a Docker container for easy deployment
- :star: new :star: Supports graceful shutdown of servers after a period of inactivity

## Configuration

The service is configured using a TOML file. Here's an example configuration:

```toml
port = ":8080"                 # Port to listen on
timeout = "1m"                 # How long to wait for server to wake up
poll_interval = "5s"           # How often to check health during wake-up
health_check_interval = "30s"  # Background health check frequency
health_cache_duration = "10s"  # How long to trust cached health status

# Optional SSL configuration Do not add these values unless you plan to use TLS/HTTPS
ssl_certificate = "/path/to/cert.pem"   # Path to your SSL certificate
ssl_certificate_key = "/path/to/key.pem" # Path to your SSL private key


[[targets]]
name = "service"
hostname = "service.host.com"                 # The "external" hostname - what this server receives as a Host header
destination = "http://service.local"          # The actual url to the server
health_endpoint = "http://service.local/ping" # url to check health
mac_address = "7c:8b:ad:da:be:51"             # MAC address for WOL
broadcast_ip = "10.0.0.255"                   # Broadcast IP for WOL
wol_port = 9                                  # Port for WOL packets
# Optional: Graceful shutdown configuration
inactivity_threshold = "1h"                   # Shut down after 1 hour of inactivity
ssh_host = "service.local:22"                 # SSH host:port for shutdown
ssh_user = "wol-proxy"                        # SSH username for shutdown
ssh_key_path = "/app/private_key"             # Path to SSH private key
shutdown_command = "sudo systemctl suspend"   # Command to execute for shutdown
# ^ take care - wake from suspend / shutdown can be flaky on some systems.
# if your machine doesnt wake from your chosen "sleep" mode, try another.

[[targets]]
name = "service2"
hostname = "service2.host.com"
destination = "http://service2.local"
health_endpoint = "http://service2.local/ping"
mac_address = "c9:69:45:d2:1e:12"
broadcast_ip = "10.0.0.255"
wol_port = 9
```

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

### Similar projects:
1. traefik-wol: [traefiklabs](https://plugins.traefik.io/plugins/642498d26d4f66a5a8a59d25/wake-on-lan), [github](https://github.com/MarkusJx/traefik-wol)
2. caddy-wol: [github](https://github.com/dulli/caddy-wol)

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and commit conventions.
