#!/usr/bin/env bash
# ============================================================================
# setup_vps.sh — Identity Network Proxy Server setup for VPS
#
# Run this on your VPS (Ubuntu/Debian):
#   bash setup_vps.sh
#
# What it does:
#   1. Installs Docker
#   2. Builds the Identity Network image
#   3. Generates server identity
#   4. Starts the proxy server
#   5. Prints the public key you need for the client
# ============================================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Identity Network — VPS Proxy Server Setup          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Detect OS ─────────────────────────────────────────────────────────────
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    err "Cannot detect OS"
fi

# ── Install Docker if not present ─────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    log "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
    ok "Docker installed"
else
    ok "Docker already installed: $(docker --version)"
fi

# ── Install docker compose plugin if needed ───────────────────────────────
if ! docker compose version &>/dev/null 2>&1; then
    log "Installing docker compose plugin..."
    apt-get install -y docker-compose-plugin 2>/dev/null || \
    curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
         -o /usr/local/bin/docker-compose && chmod +x /usr/local/bin/docker-compose
fi

# ── Find project directory ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f Dockerfile ]; then
    err "Dockerfile not found. Run this script from the identitynet project directory."
fi

# ── Build Docker image ─────────────────────────────────────────────────────
log "Building Identity Network Docker image (this takes ~2 minutes)..."
docker build --target runtime -t identitynet:latest .
ok "Image built successfully"

# ── Create data directory ─────────────────────────────────────────────────
mkdir -p /opt/identitynet/data
chmod 700 /opt/identitynet/data

# ── Generate server identity ───────────────────────────────────────────────
log "Generating proxy server identity..."
docker run --rm \
    -v /opt/identitynet/data:/data \
    identitynet:latest \
    identitynet-proxy-server init --key /data/proxy_server.key

ok "Identity generated"

# ── Open firewall port ────────────────────────────────────────────────────
PROXY_PORT=${PROXY_PORT:-7701}
log "Opening firewall port $PROXY_PORT..."
if command -v ufw &>/dev/null; then
    ufw allow "$PROXY_PORT/tcp" comment "IdentityNet proxy" 2>/dev/null || true
    ok "ufw: port $PROXY_PORT opened"
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port="$PROXY_PORT/tcp" 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    ok "firewalld: port $PROXY_PORT opened"
else
    warn "Could not detect firewall. Manually open TCP port $PROXY_PORT."
fi

# ── Write systemd service ─────────────────────────────────────────────────
log "Installing systemd service..."
cat > /etc/systemd/system/identitynet-proxy.service << SYSTEMD
[Unit]
Description=Identity Network Proxy Server
After=docker.service
Requires=docker.service

[Service]
Restart=always
RestartSec=5
ExecStart=docker run --rm --name idn-proxy-server \\
    -v /opt/identitynet/data:/data \\
    -p ${PROXY_PORT}:${PROXY_PORT} \\
    identitynet:latest \\
    identitynet-proxy-server run \\
    --key /data/proxy_server.key \\
    --port ${PROXY_PORT} \\
    --allow-all
ExecStop=docker stop idn-proxy-server

[Install]
WantedBy=multi-user.target
SYSTEMD

systemctl daemon-reload
systemctl enable identitynet-proxy
systemctl start identitynet-proxy
ok "Systemd service installed and started"

sleep 2

# ── Print connection info ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  VPS Proxy Server is running!${NC}"
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Get public key
PUBKEY=$(docker run --rm -v /opt/identitynet/data:/data \
    identitynet:latest \
    cat /data/proxy_server.key 2>/dev/null | grep "^public_key:" | awk '{print $2}')

NODE_ID=$(docker run --rm -v /opt/identitynet/data:/data \
    identitynet:latest \
    cat /data/proxy_server.key 2>/dev/null | grep "^node_id:" | awk '{print $2}')

VPS_IP=$(curl -4 -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo -e "${YELLOW}Save this information — you need it for the client:${NC}"
echo ""
echo -e "  VPS IP:      ${BOLD}${VPS_IP}${NC}"
echo -e "  Port:        ${BOLD}${PROXY_PORT}${NC}"
echo -e "  Node ID:     ${BOLD}${NODE_ID}${NC}"
echo -e "  Public Key:  ${BOLD}${PUBKEY}${NC}"
echo ""
echo -e "${CYAN}On your Windows machine, run:${NC}"
echo ""
echo -e "  ${BOLD}run.ps1 build${NC}"
echo -e "  ${BOLD}run.ps1 proxy-client ${VPS_IP} ${PROXY_PORT} \"${PUBKEY}\"${NC}"
echo ""
echo -e "${CYAN}Or with Docker directly:${NC}"
echo ""
echo -e "  docker run --rm -p 1080:1080 identitynet:latest \\"
echo -e "    identitynet-proxy-client run \\"
echo -e "    --server-host ${VPS_IP} \\"
echo -e "    --server-port ${PROXY_PORT} \\"
echo -e "    --pubkey \"${PUBKEY}\" \\"
echo -e "    --proxy-port 1080"
echo ""
echo -e "${GREEN}Then set browser SOCKS5 proxy: 127.0.0.1:1080${NC}"
echo ""

# ── Status check ──────────────────────────────────────────────────────────
log "Service status:"
systemctl status identitynet-proxy --no-pager | head -5
