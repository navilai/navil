#!/bin/bash
# Navil Honeypot + Scanner — Oracle Cloud ARM Instance Setup
# Run this on a fresh OCI ARM instance (Ubuntu 22.04)
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/navilai/navil/main/deploy/honeypot-oci/setup-oci.sh | bash
#   OR
#   scp this file to the instance and run: bash setup-oci.sh
#
# Prerequisites:
#   - OCI ARM instance (Ampere A1, free tier)
#   - Ubuntu 22.04 minimal
#   - SSH access

set -euo pipefail

echo "============================================"
echo "  Navil Honeypot Infrastructure Setup"
echo "  Oracle Cloud ARM Instance"
echo "============================================"

# ── 1. System update ──
echo ""
echo "[1/6] Updating system..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq

# ── 2. Install Docker ──
echo ""
echo "[2/6] Installing Docker..."
if ! command -v docker &>/dev/null; then
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker $USER
  sudo systemctl enable docker
  sudo systemctl start docker
  echo "Docker installed. You may need to log out and back in for group changes."
else
  echo "Docker already installed: $(docker --version)"
fi

# ── 3. Install Docker Compose plugin ──
echo ""
echo "[3/6] Installing Docker Compose..."
if ! docker compose version &>/dev/null; then
  sudo apt-get install -y -qq docker-compose-plugin
fi
echo "Docker Compose: $(docker compose version)"

# ── 4. Clone Navil ──
echo ""
echo "[4/6] Cloning Navil repository..."
if [ ! -d ~/navil ]; then
  git clone https://github.com/navilai/navil.git ~/navil
else
  cd ~/navil && git pull origin main
fi

# ── 5. Configure environment ──
echo ""
echo "[5/6] Configuring environment..."
ENV_FILE=~/navil/deploy/honeypot-oci/.env

if [ ! -f "$ENV_FILE" ]; then
  echo ""
  echo "You need to set two environment variables:"
  echo ""
  read -p "  NAVIL_API_KEY (from navil.ai API Keys page): " NAVIL_API_KEY
  read -p "  CLOUDFLARE_TUNNEL_TOKEN (from Cloudflare Zero Trust dashboard): " CF_TOKEN

  cat > "$ENV_FILE" << EOF
NAVIL_API_KEY=$NAVIL_API_KEY
CLOUDFLARE_TUNNEL_TOKEN=$CF_TOKEN
EOF
  chmod 600 "$ENV_FILE"
  echo "Environment saved to $ENV_FILE"
else
  echo "Environment file already exists: $ENV_FILE"
fi

# ── 6. Open firewall ports ──
echo ""
echo "[6/6] Configuring firewall..."
sudo iptables -I INPUT -p tcp --dport 9001 -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT -p tcp --dport 9002 -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT -p tcp --dport 9003 -j ACCEPT 2>/dev/null || true

# Persist iptables rules
sudo apt-get install -y -qq iptables-persistent 2>/dev/null || true
sudo netfilter-persistent save 2>/dev/null || true

echo ""
echo "============================================"
echo "  Setup complete!"
echo ""
echo "  To start the honeypots:"
echo "    cd ~/navil/deploy/honeypot-oci"
echo "    docker compose up -d --build"
echo ""
echo "  To check status:"
echo "    docker compose ps"
echo "    docker compose logs -f"
echo ""
echo "  To stop:"
echo "    docker compose down"
echo ""
echo "  Honeypots will be accessible at:"
echo "    Dev Tools:    port 9001"
echo "    Cloud Creds:  port 9002"
echo "    DB Admin:     port 9003"
echo ""
echo "  Weekly scan runs Sunday 3am UTC"
echo "============================================"
