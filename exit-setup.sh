#!/usr/bin/env bash
# telemt-panel: exit node (SOCKS5) for cascade
# Run as root on a FOREIGN VPS. Clients never connect here — only your RU entry does.
#
# Usage:
#   curl -fsSL ... | bash
#   OR: bash exit-setup.sh [port] [user] [password]
set -euo pipefail

PORT="${1:-1080}"
USER_NAME="${2:-telemt}"
PASS="${3:-}"
if [[ -z "$PASS" ]]; then
  PASS=$(openssl rand -base64 18 2>/dev/null | tr -d '/+=' | head -c 16 || head -c 16 /dev/urandom | xxd -p)
fi
NAME=telemt-exit-socks

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "[*] Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker || true
fi

docker rm -f "$NAME" 2>/dev/null || true
docker run -d --name "$NAME" --restart unless-stopped \
  -p "${PORT}:1080" \
  -e PROXY_USER="$USER_NAME" \
  -e PROXY_PASSWORD="$PASS" \
  serjs/go-socks5-proxy

if command -v ufw >/dev/null 2>&1; then
  ufw allow "${PORT}/tcp" || true
elif command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --add-port="${PORT}/tcp" --permanent || true
  firewall-cmd --reload || true
fi

PUB=$(curl -4 -fsS --max-time 5 ifconfig.me 2>/dev/null \
  || curl -4 -fsS --max-time 5 icanhazip.com 2>/dev/null \
  || echo "YOUR_EXIT_IP")

echo
echo "=== EXIT READY ==="
echo "upstream_host = $PUB"
echo "upstream_port = $PORT"
echo "upstream_user = $USER_NAME"
echo "upstream_pass = $PASS"
echo
echo "В панели (инстанс → Каскад) вставьте эти значения и сохраните."
echo "Ссылка tg://webproxy для клиентов НЕ меняется — только exit."
echo
echo "Смена exit: поднимите новый VPS этим скриптом, обновите host/pass в панели, Save."
