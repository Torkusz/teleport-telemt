#!/usr/bin/env bash
# Настройка ХОСТА (контейнер этого сделать не может): keepalive+BBR, UFW, rate-limit от зондирования.
# Использование: sudo ./host-setup.sh 443 5223 8530
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Запустите от root: sudo $0 ПОРТЫ..."; exit 1; }
[[ $# -ge 1 ]] || { echo "Укажите порты прокси: $0 443 5223 8530"; exit 1; }
PORTS=("$@")

# --- 1. sysctl: быстрый keepalive (лечит залипание iOS) + BBR
cat > /etc/sysctl.d/99-telemt-net.conf <<'EOT'
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 3
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOT
sysctl --system >/dev/null && echo "[ok] sysctl: $(sysctl -n net.ipv4.tcp_congestion_control)"

# --- 2. UFW. SSH-порт берём из реальной конфигурации sshd, иначе рискуем отрезать себя.
command -v ufw >/dev/null || { apt-get update -qq && apt-get install -y -qq ufw; }
SSH_PORT="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')"; SSH_PORT="${SSH_PORT:-22}"
ufw allow "${SSH_PORT}/tcp" >/dev/null
for p in "${PORTS[@]}"; do ufw allow "${p}/tcp" >/dev/null; done
echo "[ok] открыты: SSH ${SSH_PORT}, прокси ${PORTS[*]}"

# --- 3. rate-limit 1 SYN/сек на IP, отдельный список на каждый порт (против активного зондирования)
modprobe xt_recent
echo xt_recent > /etc/modules-load.d/xt_recent.conf
lsmod | grep -q xt_recent || { echo "[ОШИБКА] модуль xt_recent не загружен — rate-limit не включаю"; exit 1; }
cp /etc/ufw/before.rules "/etc/ufw/before.rules.bak.$(date +%s)"
python3 - "${PORTS[@]}" <<'PY'
import re, sys
ports = sys.argv[1:]
path = "/etc/ufw/before.rules"
text = open(path).read()
text = re.sub(r"\n# === MTProto rate-limit.*?# === конец MTProto rate-limit ===\n", "\n", text, flags=re.S)  # идемпотентно
anchor = "-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
if anchor not in text:
    sys.exit("Не найдена точка вставки в before.rules")
block = "\n# === MTProto rate-limit (1 SYN/сек на IP, per-port) ===\n"
for p in ports:
    block += f"-A ufw-before-input -p tcp --dport {p} --syn -m recent --name mtp{p} --rcheck --seconds 1 -j DROP\n"
    block += f"-A ufw-before-input -p tcp --dport {p} --syn -m recent --name mtp{p} --set -j ACCEPT\n"
block += "# === конец MTProto rate-limit ===\n"
text = text.replace(anchor, anchor + block, 1)
open(path, "w").write(text)
PY
ufw --force enable >/dev/null && ufw reload >/dev/null
if iptables -S ufw-before-input 2>/dev/null | grep -q recent || nft list ruleset 2>/dev/null | grep -qi recent; then
  echo "[ok] rate-limit активен"; else echo "[!] правил recent не видно — проверьте: lsmod | grep xt_recent; ufw status verbose"; fi
echo "Готово."
