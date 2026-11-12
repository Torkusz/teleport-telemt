#!/usr/bin/env bash
# telemt-panel: exit node for cascade (SSH-туннель → SOCKS5 только на localhost).
# Запускать от root на ЗАРУБЕЖНОМ VPS. Клиенты сюда не ходят — только ваш РФ-entry, и только по SSH.
#
# Почему так: SOCKS5 не шифруется, и на пути из РФ запросы с адресами Telegram внутри него могут
# молча дропаться (CONNECT зависает). Внутри SSH-туннеля SOCKS-запросы не видны, SOCKS наружу не торчит.
#
# Использование:
#   bash exit-setup.sh "<ssh-публичный-ключ панели>" [ssh_user] [socks_port]
#   (скрипт из панели уже содержит ключ — просто выполните его)
set -euo pipefail

#__PANEL_DEFAULTS__
PUBKEY="${PUBKEY:-${1:-}}"
SSH_USER="${SSH_USER:-${2:-telemt-tunnel}}"
RPORT="${RPORT:-${3:-1080}}"
NAME=telemt-exit-socks

[[ "$(id -u)" -eq 0 ]] || { echo "Запустите от root" >&2; exit 1; }
[[ "$PUBKEY" == ssh-* ]] || { echo "Нужен публичный SSH-ключ панели (начинается с ssh-ed25519 ...). Возьмите скрипт из панели: Каскад → Скрипт." >&2; exit 1; }
[[ "$SSH_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { echo "Некорректный ssh_user: $SSH_USER" >&2; exit 1; }
[[ "$RPORT" =~ ^[0-9]+$ ]] && (( RPORT >= 1 && RPORT <= 65535 )) || { echo "Некорректный порт SOCKS: $RPORT" >&2; exit 1; }

# --- 1. Docker
if ! command -v docker >/dev/null 2>&1; then
  echo "[*] Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker || true
fi

# --- 2. sshd
SSHD="$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)"
if [[ ! -x "$SSHD" ]]; then
  echo "[*] Installing openssh-server..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server
  else
    echo "sshd не найден, установите openssh-server вручную и запустите скрипт снова" >&2
    exit 1
  fi
  SSHD="$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)"
fi
systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null || true

# --- 3. отдельный пользователь без shell: может только пробрасывать порт на localhost:RPORT
if ! id "$SSH_USER" >/dev/null 2>&1; then
  NOLOGIN="$(command -v nologin 2>/dev/null || echo /usr/sbin/nologin)"
  useradd --system --create-home --home-dir "/home/$SSH_USER" --shell "$NOLOGIN" "$SSH_USER"
fi
usermod -p '*' "$SSH_USER"   # не «locked»: иначе sshd с UsePAM no отвергает вход по ключу
HOME_DIR="$(getent passwd "$SSH_USER" | cut -d: -f6)"
install -d -m 700 -o "$SSH_USER" -g "$(id -gn "$SSH_USER")" "$HOME_DIR/.ssh"
AK="$HOME_DIR/.ssh/authorized_keys"
printf 'restrict,port-forwarding,permitopen="127.0.0.1:%s" %s\n' "$RPORT" "$PUBKEY" > "$AK"
chown "$SSH_USER:$(id -gn "$SSH_USER")" "$AK"
chmod 600 "$AK"
echo "[ok] пользователь $SSH_USER: только проброс на 127.0.0.1:$RPORT, shell отключён"

# --- 4. SOCKS5 на localhost (наружу не торчит, пароль не нужен — доступ только через SSH-ключ)
docker rm -f "$NAME" 2>/dev/null || true
docker run -d --name "$NAME" --restart unless-stopped \
  --network host \
  heywoodlh/microsocks \
  -i 127.0.0.1 -p "$RPORT" >/dev/null
sleep 2
if timeout 3 bash -c "</dev/tcp/127.0.0.1/$RPORT" 2>/dev/null; then
  echo "[ok] SOCKS5 слушает 127.0.0.1:$RPORT"
else
  echo "[!] SOCKS5 не отвечает на 127.0.0.1:$RPORT — смотрите: docker logs $NAME" >&2
fi
if command -v curl >/dev/null 2>&1; then
  if curl -sS --max-time 6 -x "socks5h://127.0.0.1:$RPORT" telnet://149.154.167.51:443 </dev/null >/dev/null 2>&1; then
    echo "[ok] exit достучался до Telegram DC (149.154.167.51:443)"
  else
    echo "[!] exit не достучался до Telegram DC — проверьте исходящий трафик VPS" >&2
  fi
fi

# --- 5. закрыть старый публичный SOCKS (если был открыт прежней версией скрипта)
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qE "^${RPORT}/tcp +ALLOW"; then
  ufw delete allow "${RPORT}/tcp" >/dev/null 2>&1 && echo "[ok] правило ufw ${RPORT}/tcp закрыто: SOCKS больше не нужен снаружи"
fi

# --- 6. проверка настроек sshd для этого пользователя (только предупреждения)
SSHD_T="$("$SSHD" -T -C "user=$SSH_USER,host=localhost,addr=127.0.0.1" 2>/dev/null || true)"
SSH_PORT="$(awk '/^port /{print $2; exit}' <<<"$SSHD_T")"; SSH_PORT="${SSH_PORT:-22}"
tf="$(awk '/^allowtcpforwarding /{print $2; exit}' <<<"$SSHD_T")"
[[ "$tf" == "no" || "$tf" == "remote" ]] && echo "[!] sshd: AllowTcpForwarding=$tf — туннель не заработает. Разрешите для пользователя $SSH_USER (Match User $SSH_USER → AllowTcpForwarding local)." >&2
[[ "$(awk '/^pubkeyauthentication /{print $2; exit}' <<<"$SSHD_T")" == "no" ]] && echo "[!] sshd: PubkeyAuthentication no — вход по ключу выключен" >&2
au="$(grep -iE '^(allowusers|allowgroups) ' <<<"$SSHD_T" || true)"
if [[ -n "$au" ]] && ! grep -qw "$SSH_USER" <<<"$au"; then
  echo "[!] sshd ограничивает вход ($au) — добавьте $SSH_USER в AllowUsers" >&2
fi

PUB="$(curl -4 -fsS --max-time 5 ifconfig.me 2>/dev/null || curl -4 -fsS --max-time 5 icanhazip.com 2>/dev/null || echo YOUR_EXIT_IP)"
echo
echo "=== EXIT READY ==="
echo "upstream_host = $PUB"
echo "ssh_port      = $SSH_PORT"
echo "ssh_user      = $SSH_USER"
echo "socks_port    = $RPORT   (только 127.0.0.1 на exit)"
echo
echo "В панели (инстанс → Каскад): включите «SSH-туннель», впишите Exit host, SSH порт и SOCKS порт, сохраните."
echo "Туннель панель поднимает и перезапускает сама. Ссылка tg://webproxy для клиентов НЕ меняется."
