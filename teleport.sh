#!/bin/bash
# ============================================================
#  Teleport - Multi-instance Telemt Manager
#  Установка + удобное управление несколькими инстансами
#  Автор: на основе гайда assyoucandy + улучшения
# ============================================================

set -euo pipefail

# ----- Цвета -----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ----- Константы -----
INSTALL_DIR="/opt/teleport"
BIN_PATH="/usr/local/bin/teleport"
CONFIG_DIR="/etc/telemt"
TELEMT_BIN="/bin/telemt"
SERVICE_PREFIX="telemt"
API_BASE_PORT=9091
MAX_INSTANCES=20

# Хорошие пары порт + SNI (можно расширять)
declare -a PORT_SNI_LIST=(
  "443:www.cloudflare.com"
  "5223:www.apple.com"
  "853:dns.google"
  "993:outlook.office.com"
  "995:outlook.office.com"
  "8443:www.cloudflare.com"
  "2053:www.cloudflare.com"
  "2083:www.cloudflare.com"
  "2087:www.cloudflare.com"
  "2096:www.cloudflare.com"
  "10443:www.cloudflare.com"
  "443:www.microsoft.com"
  "5223:www.icloud.com"
  "853:cloudflare-dns.com"
  "993:www.microsoft.com"
  "8443:www.apple.com"
  "2086:www.cloudflare.com"
  "8880:www.cloudflare.com"
  "2052:www.cloudflare.com"
  "2082:www.cloudflare.com"
)

# ============================================================
#  Вспомогательные функции
# ============================================================

check_root() {
  if [[ $EUID -ne 0 ]]; then
    error "Запускать нужно от root (sudo -i или sudo bash $0)"
  fi
}

is_installed() {
  [[ -f "$BIN_PATH" && -x "$TELEMT_BIN" && -d "$CONFIG_DIR" ]]
}

port_in_use() {
  local port=$1
  if ss -tuln | grep -q ":$port "; then
    return 0  # занят
  fi
  return 1
}

get_public_ip() {
  curl -s --max-time 5 ifconfig.me || curl -s --max-time 5 icanhazip.com || echo "YOUR_IP"
}

generate_secret() {
  openssl rand -hex 16
}

# ============================================================
#  Установка
# ============================================================

install_telemt_binary() {
  info "Скачиваю последний telemt..."
  cd /tmp
  ARCH=$(uname -m)
  LIBC="gnu"
  if ldd --version 2>&1 | grep -iq musl; then LIBC="musl"; fi

  wget -qO- "https://github.com/telemt/telemt/releases/latest/download/telemt-${ARCH}-linux-${LIBC}.tar.gz" | tar -xz
  mv telemt "$TELEMT_BIN"
  chmod +x "$TELEMT_BIN"
  success "telemt установлен: $($TELEMT_BIN --version 2>/dev/null || echo 'ok')"
}

create_user() {
  if ! id telemt &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -d /opt/telemt telemt
  fi
  mkdir -p /opt/telemt "$CONFIG_DIR"
  chown -R telemt:telemt /opt/telemt "$CONFIG_DIR"
}

ask_instances() {
  echo >&2
  echo -e "${CYAN}Сколько инстансов создать?${NC} (рекомендуется 3–8, максимум $MAX_INSTANCES)" >&2
  read -rp "Количество [3]: " num
  num=${num:-3}
  if ! [[ "$num" =~ ^[0-9]+$ ]] || (( num < 1 || num > MAX_INSTANCES )); then
    error "Введите число от 1 до $MAX_INSTANCES"
  fi
  echo "$num"   # только число уходит в stdout
}

create_configs() {
  local count=$1
  local secrets=()
  local used_ports=()

  info "Генерирую $count конфигов..."

  for ((i=1; i<=count; i++)); do
    local pair="${PORT_SNI_LIST[$((i-1))]}"
    local port="${pair%%:*}"
    local domain="${pair#*:}"
    local api_port=$((API_BASE_PORT + i - 1))
    local secret
    secret=$(generate_secret)
    secrets+=("$secret")

    # Проверка порта
    if port_in_use "$port"; then
      warn "Порт $port уже занят! Пропускаю этот инстанс или выбери другой список."
      # Можно сделать авто-поиск свободного, но пока просто предупреждаем
      read -rp "Продолжить с этим портом всё равно? (y/N): " yn
      if [[ ! "$yn" =~ ^[Yy]$ ]]; then
        error "Остановка. Освободи порт $port или измени список PORT_SNI_LIST"
      fi
    fi

    used_ports+=("$port")

    cat > "$CONFIG_DIR/telemt${i}.toml" <<EOF
[general]
fast_mode = true
use_middle_proxy = false
# ad_tag = ""          # раскомментируй и вставь после настройки через @MTProxybot

[general.modes]
classic = false
secure = false
tls = true

[network]
ipv4 = true
ipv6 = false
prefer = 4

[server]
port = ${port}
listen_addr_ipv4 = "0.0.0.0"
client_mss = "tspu"

[server.api]
enabled = true
listen = "127.0.0.1:${api_port}"
whitelist = ["127.0.0.1/32"]

[censorship]
tls_domain = "${domain}"
mask = true
mask_port = 443
tls_emulation = true
unknown_sni_action = "reject_handshake"
fake_cert_len = 2048

[access]
replay_check_len = 65536
ignore_time_skew = false

[access.users]
user${i} = "${secret}"
EOF

    chown telemt:telemt "$CONFIG_DIR/telemt${i}.toml"
    success "telemt${i}: порт ${port}, SNI ${domain}, api ${api_port}"
  done

  # Сохраняем список для менеджера
  printf "%s\n" "${used_ports[@]}" > "$INSTALL_DIR/ports.list"
  echo "$count" > "$INSTALL_DIR/count"
}

create_systemd() {
  local count=$1
  for ((i=1; i<=count; i++)); do
    local pair="${PORT_SNI_LIST[$((i-1))]}"
    local port="${pair%%:*}"
    local domain="${pair#*:}"

    cat > /etc/systemd/system/${SERVICE_PREFIX}${i}.service <<EOF
[Unit]
Description=Telemt Proxy ${i} (${port} ${domain})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=telemt
Group=telemt
WorkingDirectory=/opt/telemt
ExecStart=${TELEMT_BIN} ${CONFIG_DIR}/telemt${i}.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
  done
  systemctl daemon-reload
  success "systemd-юниты созданы"
}

setup_ufw() {
  local count=$1
  info "Настраиваю UFW..."

  # SSH обязательно
  ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp >/dev/null 2>&1

  for ((i=1; i<=count; i++)); do
    local pair="${PORT_SNI_LIST[$((i-1))]}"
    local port="${pair%%:*}"
    ufw allow ${port}/tcp >/dev/null 2>&1
  done

  # Rate-limit (простая версия)
  modprobe xt_recent 2>/dev/null || true
  echo xt_recent > /etc/modules-load.d/xt_recent.conf 2>/dev/null || true

  ufw --force enable >/dev/null 2>&1
  success "UFW настроен"
}

start_all() {
  local count=$1
  for ((i=1; i<=count; i++)); do
    systemctl enable --now ${SERVICE_PREFIX}${i} >/dev/null 2>&1
  done
  success "Все инстансы запущены"
}

install_manager() {
  mkdir -p "$INSTALL_DIR"
  # Копируем сам себя как менеджер
  cp "$0" "$BIN_PATH"
  chmod +x "$BIN_PATH"
  ln -sf "$BIN_PATH" /usr/local/bin/telemt 2>/dev/null || true
  success "Команда 'teleport' установлена"
}

do_install() {
  check_root
  echo -e "${BOLD}${CYAN}"
  echo "=============================================="
  echo "   Teleport - Multi Telemt Installer"
  echo "=============================================="
  echo -e "${NC}"

  if is_installed; then
    warn "Похоже, уже установлено. Хочешь переустановить?"
    read -rp "(y/N): " yn
    [[ "$yn" =~ ^[Yy]$ ]] || exit 0
  fi

  apt update -qq
  apt install -y wget tar jq ufw openssl curl >/dev/null

  create_user
  install_telemt_binary
  mkdir -p "$INSTALL_DIR"

  local count
  count=$(ask_instances)

  create_configs "$count"
  create_systemd "$count"
  setup_ufw "$count"
  install_manager
  start_all "$count"

  echo
  success "Установка завершена!"
  echo
  echo -e "Теперь просто введи:  ${GREEN}teleport${NC}"
  echo
  show_links
}

# ============================================================
#  Управление
# ============================================================

get_count() {
  if [[ -f "$INSTALL_DIR/count" ]]; then
    cat "$INSTALL_DIR/count"
  else
    echo 0
  fi
}

show_status() {
  local count
  count=$(get_count)
  echo -e "${BOLD}Статус инстансов:${NC}"
  echo "----------------------------------------"
  for ((i=1; i<=count; i++)); do
    local status
    if systemctl is-active --quiet ${SERVICE_PREFIX}${i}; then
      status="${GREEN}running${NC}"
    else
      status="${RED}stopped${NC}"
    fi
    local pair="${PORT_SNI_LIST[$((i-1))]}"
    local port="${pair%%:*}"
    local domain="${pair#*:}"
    printf "  telemt%-2d  порт %-5s  %-25s  %b\n" "$i" "$port" "$domain" "$status"
  done
  echo
}

show_users() {
  local count
  count=$(get_count)
  echo -e "${BOLD}Онлайн / статистика:${NC}"
  echo "----------------------------------------"
  for ((i=1; i<=count; i++)); do
    local api_port=$((API_BASE_PORT + i - 1))
    if systemctl is-active --quiet ${SERVICE_PREFIX}${i}; then
      local data
      data=$(curl -s --max-time 2 "http://127.0.0.1:${api_port}/v1/stats/summary" 2>/dev/null || echo "{}")
      local conns users
      conns=$(echo "$data" | jq -r '.data.current_connections // 0' 2>/dev/null || echo 0)
      users=$(echo "$data" | jq -r '.data.active_users // 0' 2>/dev/null || echo 0)
      printf "  telemt%-2d  соединений: %-4s  активных users: %s\n" "$i" "$conns" "$users"
    else
      printf "  telemt%-2d  ${RED}не запущен${NC}\n" "$i"
    fi
  done
  echo
}

show_links() {
  local count
  count=$(get_count)
  local ip
  ip=$(get_public_ip)
  echo -e "${BOLD}Ссылки для клиентов:${NC}"
  echo "----------------------------------------"
  for ((i=1; i<=count; i++)); do
    local api_port=$((API_BASE_PORT + i - 1))
    if systemctl is-active --quiet ${SERVICE_PREFIX}${i}; then
      local links
      links=$(curl -s --max-time 2 "http://127.0.0.1:${api_port}/v1/users" 2>/dev/null | jq -r '.[].links.tls[]?' 2>/dev/null || true)
      if [[ -n "$links" ]]; then
        echo -e "${CYAN}telemt${i}:${NC}"
        echo "$links"
      else
        # fallback генерация
        local pair="${PORT_SNI_LIST[$((i-1))]}"
        local port="${pair%%:*}"
        local domain="${pair#*:}"
        local secret
        secret=$(grep -oP 'user\d+ = "\K[^"]+' "$CONFIG_DIR/telemt${i}.toml" | head -1)
        local domain_hex
        domain_hex=$(echo -n "$domain" | xxd -p | tr -d '\n')
        echo -e "${CYAN}telemt${i}:${NC}"
        echo "tg://proxy?server=${ip}&port=${port}&secret=ee${secret}${domain_hex}"
      fi
      echo
    fi
  done
}

restart_all() {
  local count
  count=$(get_count)
  info "Перезапускаю все инстансы..."
  for ((i=1; i<=count; i++)); do
    systemctl restart ${SERVICE_PREFIX}${i}
  done
  success "Готово"
}

set_adtag() {
  echo
  echo "1. Зайди в @MTProxybot → /newproxy"
  echo "2. Отправь IP:PORT одного из инстансов"
  echo "3. Отправь секрет пользователя"
  echo "4. Скопируй полученный ad_tag (32 hex)"
  echo
  read -rp "Вставь ad_tag: " tag
  if [[ ${#tag} -ne 32 ]]; then
    error "ad_tag должен быть ровно 32 hex-символа"
  fi

  local count
  count=$(get_count)
  for ((i=1; i<=count; i++)); do
    sed -i "s|# ad_tag = \"\"|ad_tag = \"${tag}\"|" "$CONFIG_DIR/telemt${i}.toml"
    sed -i 's/use_middle_proxy = false/use_middle_proxy = true/' "$CONFIG_DIR/telemt${i}.toml"
  done
  restart_all
  success "ad_tag прописан во все инстансы. Подожди ~1 час после настройки promotion в боте."
}

show_menu() {
  clear
  echo -e "${BOLD}${CYAN}"
  echo "╔══════════════════════════════════════════════╗"
  echo "║           Teleport — Telemt Manager          ║"
  echo "╚══════════════════════════════════════════════╝"
  echo -e "${NC}"
  show_status
  echo "  1) Статус + онлайн"
  echo "  2) Показать все ссылки"
  echo "  3) Перезапустить всё"
  echo "  4) Настроить ad_tag (спонсорский канал)"
  echo "  5) Логи последнего инстанса"
  echo "  6) Обновить telemt"
  echo "  0) Выход"
  echo
  read -rp "Выбор: " choice
  case $choice in
    1) show_status; show_users; read -rp "Enter..." ;;
    2) show_links; read -rp "Enter..." ;;
    3) restart_all; sleep 1 ;;
    4) set_adtag ;;
    5) journalctl -u ${SERVICE_PREFIX}1 -n 50 --no-pager; read -rp "Enter..." ;;
    6) install_telemt_binary; restart_all ;;
    0) exit 0 ;;
    *) warn "Неверный выбор" ;;
  esac
}

# ============================================================
#  Точка входа
# ============================================================

main() {
  if [[ "${1:-}" == "install" ]] || ! is_installed; then
    do_install
    exit 0
  fi

  # Быстрые команды
  case "${1:-}" in
    status)   show_status; show_users ;;
    users)    show_users ;;
    links)    show_links ;;
    restart)  restart_all ;;
    adtag)    set_adtag ;;
    *)        while true; do show_menu; done ;;
  esac
}

main "$@"