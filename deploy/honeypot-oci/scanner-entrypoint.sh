#!/bin/bash
set -e

mkdir -p /data/scans

echo "=== Navil Weekly Scanner ==="
echo "Running initial crawl + scan..."

# Run first scan immediately
navil crawl run-scan --output /data/scans/$(date +%Y%m%d)-initial.jsonl 2>&1 | tee /var/log/navil-scan.log

echo "Initial scan complete. Starting cron for weekly runs (Sunday 3am UTC)..."

# Start cron daemon in foreground
exec crond -f -d 8
