#!/usr/bin/env bash
set -eux

echo "Starting tailscaled (userspace networking)..."

tailscaled \
  --tun=userspace-networking \
  --socks5-server=localhost:1055 \
  --outbound-http-proxy-listen=localhost:1055 \
  >ts_log.txt 2>&1 &

TS_PID=$!

# # Wait for tailscaled to start responding
# for i in {1..50}; do
#   if tailscale status >/dev/null 2>&1; then
#     echo "tailscaled is ready!"
#     break
#   fi
#   echo "tailscaled not ready yet..."
#   sleep 1
# done

# if ! kill -0 "$TS_PID" 2>/dev/null; then
#   echo "tailscaled appears to have died"
#   exit 1
# fi

sleep 20

# Run tailscale up -- ensure we have a valid auth key!
echo "Running tailscale up with auth key..."
tailscale up --auth-key="${TAILSCALE_AUTHKEY:-}" --hostname="${TAILSCALE_HOSTNAME:-}"

echo "tailscaled is running, logs below:"
tail -f ts_log.txt