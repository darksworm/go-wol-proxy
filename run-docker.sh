#!/bin/bash

# Build the Docker image
echo "Building Docker image..."
docker build -t go-wol-proxy:local .

# Run the Docker container
echo "Running Docker container..."
docker run -p 8080:8080 -v "$(pwd)/config.toml:/app/config.toml" go-wol-proxy:local

# Exit with the container's exit code
exit $?
