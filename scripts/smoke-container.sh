#!/usr/bin/env bash
# Exercise the actual image: file capabilities and bind mounts cannot be
# checked by Go unit tests. Requires Go and Linux Docker; publishes no host ports.
set -euo pipefail
image=${1:-doormouse:local}
work=$(mktemp -d)
prefix="doormouse-smoke-$(basename "$work")"
backend="$prefix-backend"
proxy="$prefix-proxy"
negative="$prefix-negative"

cleanup() {
  status=$?
  if (( status != 0 )); then
    docker logs "$proxy" >&2 || true
    docker logs "$backend" >&2 || true
  fi
  docker rm -f "$proxy" "$backend" "$negative" >/dev/null 2>&1 || true
  # Fixtures can be owned by a different UID, just like real bind mounts.
  docker run --rm --user 0:0 --entrypoint sh -v "$work:/fixtures" "$image" \
    -c 'rm -rf /fixtures/*' >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

fail() { echo "$*" >&2; exit 1; }

wait_http() {
  local port=$1 response
  for ((attempt=0; attempt<50; attempt++)); do
    response=$(docker exec "$backend" wget -q -T 1 -O - \
      --header 'Host: smoke.local' "http://127.0.0.1:$port/" 2>/dev/null) || true
    if [[ "$response" == "doormouse-smoke-ok" ]]; then return; fi
    sleep 0.1
  done
  fail "No proxied response on port $port"
}

start_proxy() {
  docker run -d --name "$proxy" --network "container:$backend" \
    "$@" "$image" >/dev/null
  wait_http 443
}

stop_proxy() { docker rm -f "$proxy" >/dev/null; }

[[ $(docker image inspect -f '{{.Config.User}}' "$image") == '1000:1000' ]] || fail 'Wrong image user'
[[ $(docker image inspect -f '{{json .Config.Entrypoint}}' "$image") == \
  '["/usr/local/bin/doormouse","/app/config.toml"]' ]] || fail 'Wrong entrypoint'
[[ $(docker run --rm --entrypoint sh "$image" -c 'echo "$(id -u):$(id -g):$(id -un)"') == \
  '1000:1000:doormouse' ]] || fail 'Missing non-root account'

# Force privileged-port enforcement in this isolated network namespace, so
# Docker's usual ip_unprivileged_port_start=0 cannot mask a missing capability.
cat > "$work/backend.go" <<'EOF'
package main

import (
    "fmt"
    "log"
    "net/http"
)

func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintln(w, "doormouse-smoke-ok")
    })
    log.Fatal(http.ListenAndServe(":18080", nil))
}
EOF
CGO_ENABLED=0 GOOS=linux GOARCH=$(docker image inspect -f '{{.Architecture}}' "$image") \
  go build -o "$work/backend" "$work/backend.go"
docker run -d --name "$backend" --sysctl net.ipv4.ip_unprivileged_port_start=1024 \
  -v "$work/backend:/smoke-backend:ro" --entrypoint /smoke-backend "$image" >/dev/null
wait_http 18080

cat > "$work/config.toml" <<'EOF'
port = ":443"
timeout = "2s"
poll_interval = "100ms"
health_check_interval = "1s"
health_cache_duration = "100ms"
[[machines]]
name = "backend"
health_check = "tcp://127.0.0.1:18080"
inactivity_threshold = "24h"
ssh_host = "127.0.0.1:1"
ssh_user = "test"
ssh_key_path = "/app/ssh_key"
shutdown_command = "true"
[[routes]]
machine = "backend"
hostname = "smoke.local"
destination = "http://127.0.0.1:18080"
[[routes]]
machine = "backend"
listen_port = 993
destination = "127.0.0.1:18080"
EOF
cat > "$work/legacy.toml" <<'EOF'
port = ":443"
timeout = "2s"
poll_interval = "100ms"
health_check_interval = "1s"
health_cache_duration = "100ms"
[[targets]]
name = "backend"
hostname = "smoke.local"
destination = "http://127.0.0.1:18080"
health_endpoint = "tcp://127.0.0.1:18080"
inactivity_threshold = "24h"
EOF
# Populate real host bind mounts with both the default and an overridden UID.
docker run --rm --user 0:0 --entrypoint sh -v "$work:/fixtures" "$image" -c '
  for uid in 1000 1001; do
    mkdir "/fixtures/$uid"
    cp /fixtures/config.toml "/fixtures/$uid/config.toml"
    echo readable-key > "/fixtures/$uid/ssh_key"
    chmod 600 "/fixtures/$uid/ssh_key"
    chown -R "$uid:$uid" "/fixtures/$uid"
  done
  mkdir /fixtures/migration
  cp /fixtures/legacy.toml /fixtures/migration/config.toml
  chown -R 1000:1000 /fixtures/migration
  chmod 644 /fixtures/legacy.toml
'

for uid in 1000 1001; do
  user_args=()
  if [[ "$uid" != 1000 ]]; then
    user_args=(--user "$uid:$uid" --cap-drop ALL --cap-add NET_BIND_SERVICE)
  fi
  start_proxy "${user_args[@]}" -v "$work/$uid:/app:ro"
  wait_http 993
  docker exec "$proxy" awk -v uid="$uid" '
    /^Uid:|^Gid:/ { for (i=2; i<=5; i++) if ($i != uid) exit 1; seen++ }
    END { if (seen != 2) exit 1 }
  ' /proc/1/status || fail 'Proxy process has incorrect IDs'
  [[ $(docker exec "$proxy" cat /app/ssh_key) == readable-key ]] || fail 'Key is unreadable'
  if docker logs "$proxy" 2>&1 | grep -q 'cannot read ssh_key_path'; then fail 'Readable key warned'; fi
  stop_proxy
done
echo 'ok: runtime user, privileged HTTP/TCP forwarding, 0600 keys and user override'

start_proxy --user 1001:1001 -v "$work/1000:/app:ro"
docker logs "$proxy" 2>&1 | grep -q 'cannot read ssh_key_path' || fail 'Unreadable key did not warn'
stop_proxy
echo 'ok: unreadable key warns without preventing startup'

# Without the capability, exec itself must fail, even before opening config.
if timeout 10 docker run --name "$negative" --network "container:$backend" --cap-drop ALL \
  -v "$work/1000:/app:ro" "$image" > "$work/negative.log" 2>&1; then
  fail 'Container started without NET_BIND_SERVICE'
fi
grep -qi 'operation not permitted' "$work/negative.log" || fail 'Negative control failed for an unrelated reason'
echo 'ok: dropping NET_BIND_SERVICE prevents execution'

start_proxy -v "$work/migration:/app"
docker exec "$proxy" sh -c '
  test "$(stat -c %u:%g:%a /app/config.migrated.toml)" = 1000:1000:600 &&
  grep -q "\[\[machines\]\]" /app/config.migrated.toml &&
  grep -q "\[\[routes\]\]" /app/config.migrated.toml
' || fail 'Migrated config missing or has incorrect permissions'
docker exec "$proxy" cmp /app/config.toml /app/config.migrated.toml >/dev/null 2>&1 && fail 'Migration did not translate the config'
stop_proxy
cmp "$work/legacy.toml" "$work/migration/config.toml" || fail 'Original config was modified'

start_proxy -v "$work/legacy.toml:/app/config.toml:ro"
logs=$(docker logs "$proxy" 2>&1)
[[ "$logs" == *'the migrated config follows'* && "$logs" == *'[[machines]]'* && "$logs" == *'[[routes]]'* ]] || fail 'Missing migration fallback'
docker exec "$proxy" test ! -e /app/config.migrated.toml || fail 'Unexpected migration output'
stop_proxy
echo 'ok: writable-directory migration and read-only single-file fallback'
