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

# Run honeypot server directly via Python with logging configured
exec python3 -u -c "
import logging, signal, sys, json, uuid, time, threading
from datetime import datetime, timezone

# Configure logging to stdout so Docker captures it
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(name)s %(levelname)s %(message)s',
    stream=sys.stdout,
)
logger = logging.getLogger('honeypot')

from navil.honeypot.server import HoneypotMCPServer

# Also log interactions as JSONL to a file for the sync script
LOG_FILE = '/tmp/honeypot-interactions.jsonl'

class LoggingServer(HoneypotMCPServer):
    def record_interaction(self, record):
        super().record_interaction(record)
        # Write structured log for sync script
        entry = {
            'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'tool_name': record.tool_name,
            'source_ip': record.source_ip,
            'user_agent': record.user_agent,
            'method': record.method,
            'arguments': str(record.arguments)[:500],
        }
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(entry) + '\n')
        logger.info('INTERACTION tool=%s source=%s agent=%s', record.tool_name, record.source_ip, record.user_agent)

server = LoggingServer(profile='$PROFILE', host='0.0.0.0', port=$PORT)

def shutdown(sig, frame):
    logger.info('Shutting down honeypot...')
    server.stop()
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)

logger.info('Honeypot (%s) listening on 0.0.0.0:%d', '$PROFILE', $PORT)
logger.info('Tools: %s', server.tool_names)
server.start()

# Keep main thread alive
while True:
    time.sleep(60)
"
