#!/bin/bash
set -e

PROFILE="${HONEYPOT_PROFILE:-dev_tools}"
PORT="${HONEYPOT_PORT:-9001}"
API_URL="${NAVIL_CLOUD_API:-https://navil-cloud-api.onrender.com}"
API_KEY="${NAVIL_API_KEY:-}"
MACHINE="${MACHINE_ID:-honeypot-unknown}"

echo "Starting Navil honeypot: profile=$PROFILE port=$PORT machine=$MACHINE"

# Initialize navil config with API key and machine ID
mkdir -p ~/.navil
cat > ~/.navil/config.yaml << EOF
machine:
  id: $MACHINE
cloud:
  api_key: $API_KEY
  api_url: $API_URL
EOF

# Start the honeypot MCP server
exec navil honeypot start \
  --profile "$PROFILE" \
  --port "$PORT" \
  --foreground \
  --sync-to-cloud
