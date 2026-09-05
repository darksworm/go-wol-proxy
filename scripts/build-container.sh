#!/usr/bin/env bash
# Build from source with the same runtime Dockerfile used by GoReleaser.
set -euo pipefail
cd "$(dirname "$0")/.."

image=${1:-doormouse:local}
arch=${GOARCH:-$(go env GOARCH)}
case "$arch" in
  amd64|arm64) ;;
  *) echo "Unsupported container architecture: $arch" >&2; exit 1 ;;
esac
context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT
mkdir -p "$context/linux/$arch"
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath \
  -o "$context/linux/$arch/doormouse" .
docker build --platform "linux/$arch" --build-arg "TARGETPLATFORM=linux/$arch" \
  -f Dockerfile.release -t "$image" "$context"
