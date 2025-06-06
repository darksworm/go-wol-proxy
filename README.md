# Go WOL Proxy

A Wake-on-LAN proxy service written in Go that automatically wakes up servers when requests are made to them.

## Features

- Proxies HTTP requests to configured target servers
- Automatically sends Wake-on-LAN packets to wake up offline servers
- Monitors server health with configurable intervals
- Caches health status to minimize latency for frequent requests
- Packaged as a Docker container for easy deployment

## Configuration

The service is configured using a TOML file. Here's an example configuration:

```toml
port = ":8080"              # Port to listen on
timeout = "1m"              # How long to wait for server to wake up
poll_interval = "5s"        # How often to check health during wake-up
health_check_interval = "30s"  # Background health check frequency
health_cache_duration = "10s"  # How long to trust cached health status

[[targets]]
name = "server1"
hostname = "example.com"
destination = "http://internal-server.local"
health_endpoint = "http://internal-server.local/health"
mac_address = "00:11:22:33:44:55"
broadcast_ip = "192.168.1.255"
wol_port = 9
```

## Docker Usage

### Pull the Docker Image

```bash
docker pull ghcr.io/OWNER/go-wol-proxy:latest
```

Replace `OWNER` with your GitHub username or organization name.

### Run the Docker Container

```bash
docker run -p 8080:8080 -v /path/to/config.toml:/app/config.toml ghcr.io/OWNER/go-wol-proxy:latest
```

### Build the Docker Image Locally

```bash
docker build -t go-wol-proxy .
```

### Run the Locally Built Image

```bash
docker run -p 8080:8080 -v /path/to/config.toml:/app/config.toml go-wol-proxy
```

### Quick Start with Helper Script

For convenience, a helper script is provided to build and run the Docker image:

```bash
chmod +x run-docker.sh  # Make the script executable (first time only)
./run-docker.sh
```

This script builds the Docker image and runs it with the local config.toml file.

## GitHub Actions

This repository includes a GitHub Actions workflow that automatically builds and pushes the Docker image to GitHub Container Registry (GHCR) when changes are pushed to the main branch.

To use this workflow:

1. Ensure your repository has the appropriate permissions to create packages
2. Push changes to the main branch
3. The workflow will automatically build and push the Docker image to GHCR

## Running Without Docker

### Prerequisites

- Go 1.16 or higher

### Installation

```bash
go get github.com/OWNER/go-wol-proxy
```

### Running

```bash
go-wol-proxy /path/to/config.toml
```

## License

[MIT License](LICENSE)
