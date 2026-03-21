#!/bin/bash
set -e

PROFILE="${HONEYPOT_PROFILE:-dev_tools}"
PORT="${HONEYPOT_PORT:-9001}"
API_URL="${NAVIL_CLOUD_API:-https://navil-cloud-api.onrender.com}"
API_KEY="${NAVIL_API_KEY:-}"
MACHINE="${MACHINE_ID:-honeypot-unknown}"

echo "Starting Navil honeypot: profile=$PROFILE port=$PORT machine=$MACHINE"

# Initialize navil config
mkdir -p ~/.navil
cat > ~/.navil/config.yaml << EOF
machine:
  id: $MACHINE
cloud:
  api_key: $API_KEY
  api_url: $API_URL
EOF

# Run honeypot server directly via Python
exec python3 -c "
from navil.honeypot.server import HoneypotMCPServer
import signal, sys

server = HoneypotMCPServer(profile='$PROFILE', host='0.0.0.0', port=$PORT)

def shutdown(sig, frame):
    print('Shutting down honeypot...')
    server.stop()
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)

print(f'Honeypot ($PROFILE) listening on 0.0.0.0:$PORT')
print(f'Tools: {server.tool_names}')
server.start()

# Keep main thread alive
import time
while True:
    time.sleep(60)
"
