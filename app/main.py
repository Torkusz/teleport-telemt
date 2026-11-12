"""telemt-panel: веб-панель управления несколькими инстансами telemt (MTProto-прокси).

Один контейнер = панель + N процессов telemt. Панель — источник истины:
хранит состояние в /data/state.json, генерирует telemt.toml для каждого инстанса,
запускает/перезапускает процессы и читает статистику из Control API telemt.
"""
import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import shutil
import io
import platform
import socket
import ssl
import subprocess
import tarfile
import time
import urllib.request
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi import File, UploadFile, Form
from pydantic import BaseModel

from caddy_sites import SiteManager

DATA = Path(os.getenv("DATA_DIR", "/data"))
TELEMT_BIN = os.getenv("TELEMT_BIN", "telemt")
PANEL_BIND = os.getenv("PANEL_BIND", "127.0.0.1")
PANEL_PORT = int(os.getenv("PANEL_PORT", "8080"))
API_PORT_BASE = 19100  # Control API инстансов: 127.0.0.1:19100+id
WEB_LISTEN_BASE = 18080  # WEB-listener telemt на 127.0.0.1:18080+id
SITE_LISTEN_BASE = 18200
TUNNEL_LOCAL_BASE = 19300  # локальный конец SSH-туннеля к exit: 127.0.0.1:19300+id
DEFAULT_SSH_USER = "telemt-tunnel"
SSH_DIR = DATA / "ssh"
STATIC = Path(__file__).parent / "static"
SITES_DIR = DATA / "sites"
CADDY_DIR = DATA / "caddy"
ANSI = re.compile(r"\x1b\[[0-9;]*m")

PRESETS = [
    {"port": 443, "sni": "www.cloudflare.com", "note": "Обычный HTTPS к CDN. Самый «серый» вариант (FakeTLS)."},
    {"port": 5223, "sni": "www.apple.com", "note": "Порт Apple Push (APNs): у каждого iPhone постоянное соединение."},
    {"port": 8530, "sni": "www.microsoft.com", "note": "Порт WSUS (обновления Windows)."},
    {"port": 2053, "sni": "www.cloudflare.com", "note": "Альтернативный HTTPS-порт Cloudflare."},
    {"port": 8443, "sni": "www.cloudflare.com", "note": "Альтернативный HTTPS-порт."},
]

HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
SSH_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")


# ---------------------------------------------------------------- состояние
DEFAULT_SYSTEM = {"sysctl": True, "firewall": True, "rate_limit": True}


class Store:
    def __init__(self):
        self.path = DATA / "state.json"
        self.lock = asyncio.Lock()
        self.d = {"settings": {"public_host": "", "acme_email": "", "default_site": "default"}, "system": dict(DEFAULT_SYSTEM), "next_id": 1, "instances": []}

    def load(self):
        DATA.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.d = json.loads(self.path.read_text())
        self.d.setdefault("system", {})
        for k, v in DEFAULT_SYSTEM.items():
            self.d["system"].setdefault(k, v)

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.d, indent=2, ensure_ascii=False))
        os.replace(tmp, self.path)

    def get(self, iid):
        for i in self.d["instances"]:
            if i["id"] == iid:
                return i
        raise HTTPException(404, "Инстанс не найден")


store = Store()
detected_host = {"value": ""}
sites_mgr: SiteManager | None = None


def inst_dir(i):
    return DATA / "instances" / str(i["id"])


def link_host():
    return store.d["settings"]["public_host"] or detected_host["value"]


def web_listen_port(i):
    return WEB_LISTEN_BASE + int(i["id"])


MAX_EXITS = 8
EXIT_DEFAULTS = {"host": "", "ssh_port": 22, "ssh_user": DEFAULT_SSH_USER, "socks_port": 1080, "weight": 10, "enabled": True}


def cascade_exits(i):
    """Список exit'ов для SSH-туннелей. Старые инстансы (один upstream_host) превращаются в список из одного exit."""
    raw = i.get("exits") or []
    if not raw and i.get("upstream_tunnel") and (i.get("upstream_host") or "").strip():
        raw = [{"host": i.get("upstream_host"), "ssh_port": i.get("ssh_port"),
                "ssh_user": i.get("ssh_user"), "socks_port": i.get("upstream_port")}]
    out = []
    for e in raw:
        d = {**EXIT_DEFAULTS, **{k: v for k, v in dict(e).items() if v not in (None, "")}}
        d["host"] = (d["host"] or "").strip()
        d["enabled"] = bool(d.get("enabled", True))
        out.append(d)
    return out


def active_exits(i):
    return [(idx, e) for idx, e in enumerate(cascade_exits(i)) if e["enabled"] and e["host"]]


def cascade_on(i):
    """Каскад: исходящий трафик к DC Telegram через SOCKS5 на зарубежном сервере (или нескольких)."""
    if not i.get("cascade_enabled"):
        return False
    if i.get("upstream_tunnel"):
        return bool(active_exits(i))
    return bool((i.get("upstream_host") or "").strip())


def tunnel_on(i):
    """SSH-туннели до exit'ов: telemt ходит на 127.0.0.1:<local>, а не по открытому SOCKS5 через границу."""
    return cascade_on(i) and bool(i.get("upstream_tunnel", False))


def tunnel_local_port(i, idx=0):
    """Локальный конец туннеля к exit №idx: 19300+id (первый), 19400+id (второй) и т.д."""
    return TUNNEL_LOCAL_BASE + int(i["id"]) + 100 * int(idx)


def render_upstreams(i):
    """Блоки [[upstreams]] для каскада. При cascade middle-proxy отключается."""
    q = json.dumps
    if not cascade_on(i):
        return []
    utype = (i.get("upstream_type") or "socks5").lower()
    if utype not in ("socks5", "socks4"):
        utype = "socks5"
    if tunnel_on(i):
        # SOCKS на каждом exit слушает только localhost и без пароля — доступ ограничен SSH-ключом.
        # Несколько exit'ов = несколько upstream'ов, telemt распределяет по weight.
        lines = []
        for idx, e in active_exits(i):
            lines += [
                "",
                f"# --- cascade: exit #{idx + 1} {e['host']} (SSH-туннель -> localhost SOCKS) ---",
                "[[upstreams]]",
                f'type = {q(utype)}',
                f'address = {q(f"127.0.0.1:{tunnel_local_port(i, idx)}")}',
                f"weight = {max(1, int(e['weight']))}",
                "enabled = true",
            ]
        return lines
    host = (i.get("upstream_host") or "").strip()
    port = int(i.get("upstream_port") or 1080)
    user = (i.get("upstream_user") or "").strip()
    password = (i.get("upstream_pass") or "").strip()
    lines = [
        "",
        "# --- cascade: exit SOCKS on foreign VPS ---",
        "[[upstreams]]",
        f'type = {q(utype)}',
        f'address = {q(f"{host}:{port}")}',
        "weight = 10",
        "enabled = true",
    ]
    if user:
        lines.append(f"username = {q(user)}")
    if password:
        lines.append(f"password = {q(password)}")
    return lines


def render_toml(i):
    q = json.dumps
    transport = i.get("transport") or "tls"
    # Каскад несовместим с middle-proxy Telegram: исходящий путь должен идти через ваш exit
    mm = bool(i.get("middle_proxy") or i.get("ad_tag")) and not cascade_on(i)
    out = ["[general]", "fast_mode = true", f"use_middle_proxy = {str(mm).lower()}", 'log_level = "normal"']
    if i.get("ad_tag") and not cascade_on(i):
        out.append(f"ad_tag = {q(i['ad_tag'])}")
    if cascade_on(i) and i.get("ad_tag"):
        out.append("# ad_tag отключён: при cascade нужен use_middle_proxy = false")

    if transport == "web":
        # WEB-режим: FakeTLS/ee не используется. Нужен nginx/Caddy на 443 → 127.0.0.1:web_port
        host = link_host() or "proxy.example.com"
        base = (i.get("web_base_path") or "").strip().strip("/")
        site_id = (i.get("web_site") or store.d["settings"].get("default_site") or "default").strip() or "default"
        if i.get("web_decoy_upstream"):
            decoy = i["web_decoy_upstream"].strip()
        elif sites_mgr is not None:
            decoy = sites_mgr.upstream_url(site_id)
        else:
            decoy = "http://127.0.0.1:18200"
        out += [
            "", "[general.modes]", "classic = false", "secure = true", "tls = false",
            "", "[general.links]", 'show = "*"',
            f"public_host = {q(host)}",
            "", "[network]", "ipv4 = true", "ipv6 = false", "prefer = 4",
            "", "[server]", f"port = {web_listen_port(i)}",
            "", "[server.api]", "enabled = true", f'listen = "127.0.0.1:{API_PORT_BASE + i["id"]}"',
            'whitelist = ["127.0.0.1/32"]', f"auth_header = {q(i['api_token'])}", "minimal_runtime_enabled = false",
            "", "[[server.listeners]]",
            'ip = "127.0.0.1"',
            f"port = {web_listen_port(i)}",
            'transport = "web"',
            "proxy_protocol = false",
            'web_client_ip_source = "x_forwarded_for"',
            'web_trusted_proxy_cidrs = ["127.0.0.1/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]',
            "", "[web]",
            "enabled = true",
            'carrier = "https-lanes"',
            'decoy_fasttrack_mode = "off"',
            'http_connection_capacity_action = "drop"',
            "", "[[web.vhosts]]",
            f"host = {q(host)}",
        ]
        if base:
            out.append(f"base_path = {q(base)}")
        # public_addr обязателен в telemt WEB — без него процесс падает с Config error
        pub = (store.d["settings"].get("public_addr") or "").strip()
        if not pub:
            ip = (detected_host.get("value") or "").strip()
            if ip and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                pub = f"{ip}:443"
            elif host and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                pub = f"{host}:443"
            else:
                pub = f"{host}:443"
        if pub and ":" not in pub.split("/")[-1]:
            pub = f"{pub}:443"
        out.append(f"public_addr = {q(pub)}")
        out += [
            "", "[web.vhosts.decoy]",
            'mode = "http_upstream"',
            f"upstream = {q(decoy)}",
        ]
        # профили по пользователям
        for u in i["users"]:
            if u.get("enabled", True):
                out += [
                    "", "[[web.vhosts.profiles]]",
                    f"user = {q(u['name'])}",
                    'secret_mode = "dd"',
                    "max_sessions = 16",
                    "max_streams = 1024",
                    "max_streams_per_session = 64",
                ]
        out += ["", "[access]", "replay_check_len = 65536", "ignore_time_skew = false", "", "[access.users]"]
        for u in i["users"]:
            if u.get("enabled", True):
                out.append(f"{q(u['name'])} = {q(u['secret'])}")
        out += render_upstreams(i)
        return "\n".join(out) + "\n"

    # --- классический FakeTLS (ee) ---
    out += ["", "[general.modes]", "classic = false", "secure = false", "tls = true", "", "[general.links]", 'show = "*"']
    if link_host():
        out.append(f"public_host = {q(link_host())}")
    out += ["", "[network]", "ipv4 = true", "ipv6 = false", "prefer = 4", "", "[server]", f"port = {i['port']}"]
    if i.get("mss"):
        out.append(f"client_mss = {q(i['mss'])}")
    out += [
        "", "[server.api]", "enabled = true", f'listen = "127.0.0.1:{API_PORT_BASE + i["id"]}"',
        'whitelist = ["127.0.0.1/32"]', f"auth_header = {q(i['api_token'])}", "minimal_runtime_enabled = false",
        "", "[[server.listeners]]", 'ip = "0.0.0.0"',
        "", "[censorship]", f"tls_domain = {q(i['sni'])}", "mask = true", f"mask_port = {i.get('mask_port') or 443}",
    ]
    if i.get("mask_host"):
        out.append(f"mask_host = {q(i['mask_host'])}")
    out += [
        "tls_emulation = true", 'tls_front_dir = "tlsfront"', 'unknown_sni_action = "reject_handshake"',
        "", "[access]", "replay_check_len = 65536", "ignore_time_skew = false", "", "[access.users]",
    ]
    for u in i["users"]:
        if u.get("enabled", True):
            out.append(f"{q(u['name'])} = {q(u['secret'])}")
    out += render_upstreams(i)
    return "\n".join(out) + "\n"


def write_config(i):
    d = inst_dir(i)
    d.mkdir(parents=True, exist_ok=True)
    cfg = d / "telemt.toml"
    tmp = d / "telemt.toml.tmp"
    tmp.write_text(render_toml(i))
    os.replace(tmp, cfg)  # атомарно: telemt следит за файлом и подхватывает пользователей без рестарта
    return cfg


# ---------------------------------------------------------------- процессы
class Runner:
    def __init__(self, iid):
        self.iid = iid
        self.proc = None
        self.task = None
        self.logs = deque(maxlen=500)
        self.started = 0.0
        self.restarts = 0
        self.stopping = False

    @property
    def running(self):
        return self.proc is not None and self.proc.returncode is None

    def log(self, s):
        self.logs.append(f"{time.strftime('%H:%M:%S')} {s}")

    async def _loop(self):
        backoff = 2
        while not self.stopping:
            try:
                inst = store.get(self.iid)
            except HTTPException:
                return
            cfg = write_config(inst)
            if tunnel_on(inst):
                if not await wait_tunnel_ready(inst, 10):
                    self.log("[panel] SSH-туннель к exit ещё не поднят — запускаю telemt, туннель догонит сам (см. строки [tunnel])")
            self.log(f"[panel] запуск telemt (порт {inst['port']}, SNI {inst['sni']})")
            self.started = time.time()
            try:
                self.proc = await asyncio.create_subprocess_exec(
                    telemt_bin(), "--data-path", str(inst_dir(inst)), str(cfg),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            except Exception as e:  # noqa
                self.log(f"[panel] не удалось запустить: {e}")
                await asyncio.sleep(10)
                continue
            async for line in self.proc.stdout:
                self.log(ANSI.sub("", line.decode(errors="replace").rstrip()))
            code = await self.proc.wait()
            if self.stopping:
                return
            self.restarts += 1
            self.log(f"[panel] telemt завершился с кодом {code}, перезапуск через {backoff}с")
            if time.time() - self.started > 60:
                backoff = 2
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)

    def start(self):
        self.stopping = False
        self.task = asyncio.create_task(self._loop())

    async def stop(self):
        self.stopping = True
        if self.running:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), 8)
            except asyncio.TimeoutError:
                self.proc.kill()
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except (asyncio.CancelledError, Exception):  # noqa
                pass
        self.proc = None


runners: dict[int, Runner] = {}
tunnels: dict[tuple, "Tunnel"] = {}   # (id инстанса, индекс exit) -> Tunnel


def ensure_runner(iid):
    return runners.setdefault(iid, Runner(iid))


def ensure_tunnel(iid, idx=0):
    return tunnels.setdefault((iid, idx), Tunnel(iid, idx))


def start_tunnels(inst):
    for idx, _ in active_exits(inst):
        ensure_tunnel(inst["id"], idx).start()


async def stop_tunnels(iid):
    keys = [k for k in tunnels if k[0] == iid]
    ts = [tunnels.pop(k) for k in keys]
    await asyncio.gather(*(t.stop() for t in ts))


# ---------------------------------------------------------------- SSH-туннель до exit
def ensure_ssh_key():
    """Ключ панели для входа на exit (генерируется один раз, лежит в /data/ssh)."""
    SSH_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(SSH_DIR, 0o700)
    key = SSH_DIR / "id_ed25519"
    if not key.exists():
        r = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "telemt-panel", "-f", str(key)],
                           capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            raise RuntimeError(f"ssh-keygen: {r.stderr.strip() or r.stdout.strip()}")
    os.chmod(key, 0o600)
    return key


def ssh_pubkey():
    key = ensure_ssh_key()
    pub = Path(str(key) + ".pub")
    if not pub.exists():
        r = subprocess.run(["ssh-keygen", "-y", "-f", str(key)], capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            raise RuntimeError(f"ssh-keygen -y: {r.stderr.strip()}")
        pub.write_text(r.stdout.strip() + " telemt-panel\n")
    return pub.read_text().strip()


def known_hosts_path(host):
    safe = re.sub(r"[^A-Za-z0-9.-]", "_", host)
    return SSH_DIR / f"known_hosts.{safe}"


def port_listening(port, timeout=0.3):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


async def wait_tunnel_ready(inst, timeout=10):
    """Ждём, пока поднимется хотя бы один туннель (остальные догонят сами)."""
    ports = [tunnel_local_port(inst, idx) for idx, _ in active_exits(inst)]
    deadline = time.time() + timeout
    while time.time() < deadline:
        for pt in ports:
            if await asyncio.to_thread(port_listening, pt):
                return True
        await asyncio.sleep(0.5)
    return False


SSH_HINTS = (
    ("REMOTE HOST IDENTIFICATION HAS CHANGED", "ключ хоста exit изменился (переустановка?). Нажмите «Сбросить ключ хоста» в настройках каскада."),
    ("Host key verification failed", "ключ хоста exit не совпал. Нажмите «Сбросить ключ хоста» в настройках каскада."),
    ("Permission denied", "exit не принял ключ панели: выполните на exit свежий скрипт из панели (он добавляет ключ)."),
    ("Connection refused", "SSH-порт exit закрыт или указан неверно (поле «SSH порт»)."),
    ("timed out", "до SSH-порта exit не достучаться (файрвол/неверный IP/блокировка по пути)."),
    ("administratively prohibited", "на exit запрещён TCP-forwarding (AllowTcpForwarding no) или нет permitopen на этот порт."),
    ("cannot listen to port", "локальный порт туннеля занят — перезапустите инстанс."),
)


class Tunnel:
    """`ssh -N -L 127.0.0.1:<local>:127.0.0.1:<socks>` до exit №idx; перезапускается сам, пишет в лог инстанса."""

    def __init__(self, iid, idx=0):
        self.iid = iid
        self.idx = idx
        self.proc = None
        self.task = None
        self.started = 0.0
        self.restarts = 0
        self.stopping = False

    @property
    def running(self):
        return self.proc is not None and self.proc.returncode is None

    def log(self, s):
        ensure_runner(self.iid).log(f"[tunnel #{self.idx + 1}] {s}")

    @staticmethod
    def command(inst, idx=0):
        e = cascade_exits(inst)[idx]
        host = e["host"]
        kh = known_hosts_path(host)
        return [
            "ssh", "-N", "-F", "/dev/null",
            "-i", str(SSH_DIR / "id_ed25519"), "-p", str(int(e["ssh_port"])),
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={kh}", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
            "-o", "ExitOnForwardFailure=yes", "-o", "ConnectTimeout=10",
            "-o", "LogLevel=ERROR",
            "-L", f"127.0.0.1:{tunnel_local_port(inst, idx)}:127.0.0.1:{int(e['socks_port'])}",
            f"{e['ssh_user']}@{host}",
        ]

    async def _loop(self):
        backoff = 2
        while not self.stopping:
            try:
                inst = store.get(self.iid)
            except HTTPException:
                return
            exits = cascade_exits(inst)
            if (not tunnel_on(inst) or not inst.get("enabled", True)
                    or self.idx >= len(exits) or not exits[self.idx]["enabled"]):
                return
            e = exits[self.idx]
            try:
                await asyncio.to_thread(ensure_ssh_key)
                cmd = self.command(inst, self.idx)
            except Exception as ex:  # noqa
                self.log(f"не удалось подготовить ключ: {ex}")
                await asyncio.sleep(15)
                continue
            self.log(f"подключаюсь к {e['ssh_user']}@{e['host']}:{e['ssh_port']} "
                     f"(локально 127.0.0.1:{tunnel_local_port(inst, self.idx)}, weight {e['weight']})")
            self.started = time.time()
            try:
                self.proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            except FileNotFoundError:
                self.log("ssh не найден в образе — пересоберите: docker compose build --no-cache && docker compose up -d")
                await asyncio.sleep(30)
                continue
            except Exception as ex:  # noqa
                self.log(f"не удалось запустить ssh: {ex}")
                await asyncio.sleep(15)
                continue
            hinted = set()
            async for line in self.proc.stdout:
                txt = ANSI.sub("", line.decode(errors="replace").rstrip())
                self.log(txt)
                for needle, hint in SSH_HINTS:
                    if needle in txt and needle not in hinted:
                        hinted.add(needle)
                        self.log("→ " + hint)
            code = await self.proc.wait()
            if self.stopping:
                return
            self.restarts += 1
            self.log(f"ssh завершился с кодом {code}, повтор через {backoff}с")
            if time.time() - self.started > 60:
                backoff = 2
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)

    def start(self):
        self.stopping = False
        self.task = asyncio.create_task(self._loop())

    async def stop(self):
        self.stopping = True
        if self.running:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), 5)
            except asyncio.TimeoutError:
                self.proc.kill()
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except (asyncio.CancelledError, Exception):  # noqa
                pass
        self.proc = None


def exits_status(i):
    """Состояние каждого exit'а: настройки + поднят ли локальный конец туннеля."""
    out = []
    for idx, e in enumerate(cascade_exits(i)):
        t = tunnels.get((i["id"], idx))
        lp = tunnel_local_port(i, idx)
        out.append({
            **e, "idx": idx, "local_port": lp,
            "running": bool(t and t.running),
            "up": bool(e["enabled"]) and port_listening(lp),
            "restarts": t.restarts if t else 0,
            "uptime": int(time.time() - t.started) if (t and t.running) else 0,
        })
    return out


def tunnel_status(i, ex=None):
    if not tunnel_on(i):
        return None
    act = [x for x in (ex if ex is not None else exits_status(i)) if x["enabled"] and x["host"]]
    return {
        "up": any(x["up"] for x in act),
        "running": any(x["running"] for x in act),
        "total": len(act),
        "up_count": sum(1 for x in act if x["up"]),
        "local_port": act[0]["local_port"] if act else 0,
        "restarts": sum(x["restarts"] for x in act),
        "uptime": max((x["uptime"] for x in act), default=0),
    }


async def socks_probe(port, ip="149.154.167.51", dport=443, timeout=6.0):
    """SOCKS5 CONNECT на DC Telegram через локальный конец туннеля: проверяет всю цепочку до exit и дальше."""
    t0 = time.time()
    w = None
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), 3)
        w.write(b"\x05\x01\x00")
        await w.drain()
        if await asyncio.wait_for(r.readexactly(2), timeout) != b"\x05\x00":
            return {"ok": False, "ms": 0, "error": "SOCKS-рукопожатие отклонено"}
        w.write(b"\x05\x01\x00\x01" + socket.inet_aton(ip) + int(dport).to_bytes(2, "big"))
        await w.drain()
        head = await asyncio.wait_for(r.readexactly(4), timeout)
        atyp = head[3]
        rest = 6 if atyp == 1 else 18 if atyp == 4 else 0
        if atyp == 3:
            rest = (await asyncio.wait_for(r.readexactly(1), timeout))[0] + 2
        await asyncio.wait_for(r.readexactly(rest), timeout)
        ok = head[1] == 0
        return {"ok": ok, "ms": int((time.time() - t0) * 1000), "error": "" if ok else f"SOCKS-код ответа {head[1]}"}
    except asyncio.TimeoutError:
        return {"ok": False, "ms": 0, "error": "таймаут: exit не достучался до Telegram или туннель завис"}
    except (OSError, asyncio.IncompleteReadError) as ex:
        return {"ok": False, "ms": 0, "error": f"туннель не отвечает ({type(ex).__name__})"}
    finally:
        if w is not None:
            w.close()


async def restart_instance(i):
    await stop_tunnels(i["id"])
    r = ensure_runner(i["id"])
    await r.stop()
    if i["enabled"]:
        if tunnel_on(i):
            start_tunnels(i)
        r.start()


# ---------------------------------------------------------------- бинарник telemt и обновление
def telemt_bin():
    p = DATA / "bin" / "telemt"
    return str(p) if p.exists() else TELEMT_BIN


def telemt_version():
    try:
        out = subprocess.run([telemt_bin(), "--version"], capture_output=True, text=True, timeout=5).stdout.strip()
        return out.split()[-1]
    except Exception:  # noqa
        return ""


def fetch_latest_version():
    try:  # без лимитов API: /releases/latest редиректит на /releases/tag/<версия>
        req = urllib.request.Request("https://github.com/telemt/telemt/releases/latest", headers={"User-Agent": "telemt-panel"})
        with urllib.request.urlopen(req, timeout=10) as r:
            m = re.search(r"/releases/tag/v?([0-9][^/?#]*)", r.geturl())
            if m:
                return m.group(1)
    except Exception:  # noqa
        pass
    req = urllib.request.Request("https://api.github.com/repos/telemt/telemt/releases/latest",
                                 headers={"User-Agent": "telemt-panel", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())["tag_name"].lstrip("v")


def install_latest_telemt():
    url = f"https://github.com/telemt/telemt/releases/latest/download/telemt-{platform.machine()}-linux-gnu.tar.gz"
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "telemt-panel"}), timeout=120) as r:
        data = r.read()
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        m = next((m for m in tf.getmembers() if m.isfile() and os.path.basename(m.name) == "telemt"), None)
        if not m:
            raise RuntimeError("В архиве нет бинарника telemt")
        blob = tf.extractfile(m).read()
    (DATA / "bin").mkdir(parents=True, exist_ok=True)
    new = DATA / "bin" / "telemt.new"
    new.write_bytes(blob)
    os.chmod(new, 0o755)
    out = subprocess.run([str(new), "--version"], capture_output=True, text=True, timeout=10)
    if out.returncode != 0:
        new.unlink(missing_ok=True)
        raise RuntimeError("Скачанный бинарник не запускается: " + (out.stderr or out.stdout)[:200])
    os.replace(new, DATA / "bin" / "telemt")
    return out.stdout.strip().split()[-1]


# ---------------------------------------------------------------- настройка хоста: sysctl + iptables
SYSCTLS = [  # (группа, имя, целевое значение)
    ("ipv4", "tcp_keepalive_time", "60"), ("ipv4", "tcp_keepalive_intvl", "15"), ("ipv4", "tcp_keepalive_probes", "3"),
    ("core", "default_qdisc", "fq"), ("ipv4", "tcp_congestion_control", "bbr"),
]
FW_CHAIN = "TELEMT_PANEL"
fw_state = {"sig": None, "error": "", "rate_error": "", "active": False}
sys_state = {"errors": {}}


def sysctl_read(grp, name):
    try:
        return Path(f"/proc/sys/net/{grp}/{name}").read_text().strip()
    except Exception:  # noqa
        return None


def sysctl_apply():
    errs = {}
    for grp, name, val in SYSCTLS:
        cur = sysctl_read(grp, name)
        if cur is None or cur == val:  # None = параметра нет в этом ядре (например, default_qdisc) — пропускаем
            continue
        mounted = Path(f"/hostsys/{grp}/{name}")  # rw-bind-mount из compose; в /proc/sys Docker пишет только read-only
        target = mounted if mounted.exists() else Path(f"/proc/sys/net/{grp}/{name}")
        try:
            target.write_text(val)
        except Exception as e:  # noqa
            errs[name] = str(e)
    sys_state["errors"] = errs


def _ipt(*args):
    return subprocess.run(["iptables", "-w", "5", *args], capture_output=True, text=True, timeout=15)


def fw_rules(ports, rate):
    rules = []
    for p in ports:
        if rate:
            rules.append(["-p", "tcp", "--dport", str(p), "--syn", "-m", "recent", "--name", f"mtp{p}", "--rcheck", "--seconds", "1", "-j", "DROP"])
            rules.append(["-p", "tcp", "--dport", str(p), "--syn", "-m", "recent", "--name", f"mtp{p}", "--set", "-j", "ACCEPT"])
        rules.append(["-p", "tcp", "--dport", str(p), "-j", "ACCEPT"])
    return rules


def fw_remove():
    while _ipt("-D", "INPUT", "-j", FW_CHAIN).returncode == 0:
        pass
    _ipt("-F", FW_CHAIN)
    _ipt("-X", FW_CHAIN)
    fw_state.update(sig=None, active=False, error="", rate_error="")


def fw_build(ports, rate):
    if _ipt("-N", FW_CHAIN).returncode != 0:
        _ipt("-F", FW_CHAIN)
    for rule in fw_rules(ports, rate):
        r = _ipt("-A", FW_CHAIN, *rule)
        if r.returncode != 0:
            return r.stderr.strip()
    return ""


def fw_reconcile(manage, ports, rate):
    """Свой chain TELEMT_PANEL первым в INPUT: открывает порты прокси и ограничивает SYN (xt_recent).
    Не трогает правила UFW/хостера, поэтому ничего не ломает при удалении."""
    if not manage:
        if _ipt("-S", "INPUT").returncode == 0:
            fw_remove()
        return
    if _ipt("-S", "INPUT").returncode != 0:
        fw_state.update(error="iptables недоступен из контейнера (нужны NET_ADMIN и network_mode: host)", active=False)
        return
    sig = json.dumps([sorted(ports), rate])
    top = [l for l in _ipt("-S", "INPUT").stdout.splitlines() if l.startswith("-A INPUT")][:1]
    jump_first = top == [f"-A INPUT -j {FW_CHAIN}"]
    chain_ok = _ipt("-n", "-L", FW_CHAIN).returncode == 0
    if chain_ok and jump_first and fw_state["sig"] == sig:
        return
    err = fw_build(ports, rate)
    rate_err = ""
    if err and rate:  # чаще всего нет модуля xt_recent (LXC/OpenVZ) — оставим хотя бы открытие портов
        rate_err = err
        err = fw_build(ports, False)
    if err:
        fw_state.update(error=err, rate_error="", active=False)
        return
    if not jump_first:
        while _ipt("-D", "INPUT", "-j", FW_CHAIN).returncode == 0:
            pass
        _ipt("-I", "INPUT", "1", "-j", FW_CHAIN)
    fw_state.update(sig=sig, error="", rate_error=rate_err, active=True)


def host_reconcile_sync():
    sysd = store.d["system"]
    if sysd["sysctl"]:
        sysctl_apply()
    ports = []
    has_web = False
    for i in store.d["instances"]:
        if not i.get("enabled"):
            continue
        if (i.get("transport") or "tls") == "web":
            has_web = True
            continue
        ports.append(i["port"])
    if has_web and 443 not in ports:
        ports.append(443)
    # сайт-прикрытие с сертификатом: 80 (проверка домена Let's Encrypt, редирект) и 443
    if CADDY_MANAGED and (store.d["settings"].get("public_host") or "").strip():
        for pt in (80, 443):
            if pt not in ports:
                ports.append(pt)
    fw_reconcile(sysd["firewall"], ports, sysd["rate_limit"])


async def host_reconcile():
    try:
        await asyncio.to_thread(host_reconcile_sync)
    except Exception as e:  # noqa
        fw_state["error"] = str(e)


async def host_loop():
    while True:
        await host_reconcile()
        await asyncio.sleep(30)  # ufw reload или хостер могут снести правила — возвращаем


# ---------------------------------------------------------------- Control API telemt
def tapi_sync(i, path):
    req = urllib.request.Request(f"http://127.0.0.1:{API_PORT_BASE + i['id']}{path}",
                                 headers={"Authorization": i["api_token"]})
    try:
        with urllib.request.urlopen(req, timeout=2) as r:
            return json.loads(r.read())
    except Exception:  # noqa
        return None


async def tapi(i, path):
    return await asyncio.to_thread(tapi_sync, i, path)


def local_link(i, u):
    host = link_host() or "SERVER_IP"
    transport = i.get("transport") or "tls"
    if transport == "web":
        # tg://webproxy — порт всегда 443, secret = dd + 16 байт (hex)
        base = (i.get("web_base_path") or "").strip().strip("/")
        server = f"{host}/{base}" if base else host
        # path-vhost: server percent-encoded в ссылке; панель отдаёт читаемый вид
        return f"tg://webproxy?server={server}&secret=dd{u['secret']}"
    return f"tg://proxy?server={host}&port={i['port']}&secret=ee{u['secret']}{i['sni'].encode().hex()}"


def public_view(i, users_api, summary, health):
    _ex = exits_status(i)
    r = ensure_runner(i["id"])
    api_users = {u["username"]: u for u in (users_api or {}).get("data", [])}
    transport = i.get("transport") or "tls"
    users = []
    for u in i["users"]:
        a = api_users.get(u["name"], {})
        link_key = "web" if transport == "web" else "tls"
        links = [l for l in (a.get("links") or {}).get(link_key, []) if "server=::" not in l]
        if not links and transport == "web":
            # fallback: telemt может отдавать web-ссылки в другом ключе
            links = [l for l in (a.get("links") or {}).get("tls", []) if "webproxy" in l]
        link = links[0] if links else local_link(i, u)
        if transport == "web":
            tme = link.replace("tg://webproxy", "https://t.me/webproxy", 1)
        else:
            tme = link.replace("tg://proxy", "https://t.me/proxy", 1)
        users.append({
            "name": u["name"], "secret": u["secret"], "enabled": u.get("enabled", True),
            "link": link, "web_link": tme,
            "link_from_api": bool(links),
            "connections": a.get("current_connections", 0), "ips": a.get("active_unique_ips", 0),
            "octets": a.get("total_octets", 0),
        })
    s = (summary or {}).get("data") or {}
    return {
        **{k: i.get(k) for k in (
            "id", "name", "port", "sni", "mss", "middle_proxy", "ad_tag",
            "mask_host", "mask_port", "enabled", "transport", "web_base_path", "web_decoy_upstream", "web_site",
            "cascade_enabled", "upstream_type", "upstream_host", "upstream_port", "upstream_user", "upstream_pass",
        )},
        "cascade_active": cascade_on(i),
        "upstream_tunnel": bool(i.get("upstream_tunnel", False)),
        "ssh_port": int(i.get("ssh_port") or 22),
        "ssh_user": i.get("ssh_user") or DEFAULT_SSH_USER,
        "tunnel": tunnel_status(i, _ex),
        "exits": _ex,
        "web_listen_port": web_listen_port(i) if transport == "web" else None,
        "status": {"running": r.running, "api": bool(health), "restarts": r.restarts,
                   "uptime": int(time.time() - r.started) if r.running else 0},
        "stats": {"connections_total": s.get("connections_total", 0), "bad_total": s.get("connections_bad_total", 0),
                  "handshake_timeouts": s.get("handshake_timeouts_total", 0),
                  "bad_by_class": s.get("connections_bad_by_class", []),
                  "hs_by_class": s.get("handshake_failures_by_class", [])},
        "users": users,
    }


# ---------------------------------------------------------------- авторизация
def load_secrets():
    pw = os.getenv("PANEL_PASSWORD", "").strip()
    pwf = DATA / "admin_password"
    if not pw:
        if pwf.exists():
            pw = pwf.read_text().strip()
        else:
            pw = secrets.token_urlsafe(12)
            pwf.write_text(pw)
            os.chmod(pwf, 0o600)
            print(f"\n=== Пароль администратора сгенерирован: {pw}  (хранится в {pwf}) ===\n", flush=True)
    kf = DATA / "session.key"
    if not kf.exists():
        kf.write_text(secrets.token_hex(32))
        os.chmod(kf, 0o600)
    return pw, kf.read_text().strip().encode()


ADMIN_PW = ""
SESSION_KEY = b""
fails: dict[str, list[float]] = {}
SESSION_TTL = 7 * 86400


def sign(ts):
    return hmac.new(SESSION_KEY, str(ts).encode(), hashlib.sha256).hexdigest()


def require_auth(request: Request):
    tok = request.cookies.get("tp_session", "")
    try:
        ts, sig = tok.split(".")
        ok = hmac.compare_digest(sig, sign(ts)) and time.time() - int(ts) < SESSION_TTL
    except Exception:  # noqa
        ok = False
    if not ok:
        raise HTTPException(401, "Требуется вход")
    if request.method != "GET" and request.headers.get("x-requested-with") != "panel":
        raise HTTPException(403, "CSRF")


# ---------------------------------------------------------------- приложение
async def detect_public_ip():
    def work():
        for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
            try:
                with urllib.request.urlopen(url, timeout=5) as r:
                    ip = r.read().decode().strip()
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                        return ip
            except Exception:  # noqa
                continue
        return ""
    detected_host["value"] = await asyncio.to_thread(work)
    for i in store.d["instances"]:  # конфиги содержат public_host — пересоберём
        if i["enabled"] and detected_host["value"] and not store.d["settings"]["public_host"]:
            write_config(i)


# ---------------------------------------------------------------- Caddy: сайт-прикрытие + сертификат
# Caddy запускает сама панель (бинарник лежит в образе): сайт поднимается на домене из «Системы»,
# сертификат Let's Encrypt/ZeroSSL Caddy получает и продлевает сам. CADDY_MANAGE=0 — свой Caddy на хосте.
CADDY_MANAGED = os.getenv("CADDY_MANAGE", "1").strip().lower() not in ("0", "false", "no", "off")
CADDY_ADMIN = os.getenv("CADDY_ADMIN", "unix//run/telemt/caddy.sock")  # только сокет внутри контейнера
CADDY_STORAGE = DATA / "caddy-storage"       # сертификаты и ACME-аккаунт: переживают пересборку образа
CADDY_CONFIG_HOME = DATA / "caddy-config"
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
CADDY_BUSY_MSG = ("Caddy не запущен: порт {ports} на сервере уже занят другим процессом (не панелью). "
                  "Выясните на хосте: sudo ss -ltnp | grep -E ':(80|443) '. Если это Caddy, nginx или apache — остановите его "
                  "(например: sudo systemctl disable --now caddy) и нажмите «Применить / перезапустить». "
                  "Если он должен остаться — задайте CADDY_MANAGE=0 в .env.")


def ports_in_use(ports=(80, 443)):
    """Какие из портов уже кем-то слушаются (проверка bind до запуска Caddy)."""
    busy = []
    for pt in ports:
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sk.bind(("0.0.0.0", pt))
        except OSError as e:
            if e.errno == 98:  # EADDRINUSE
                busy.append(pt)
        finally:
            sk.close()
    return busy


def caddy_content():
    return sites_mgr.generate_caddyfile(
        store.d["settings"].get("public_host", ""), store.d["settings"].get("acme_email", ""),
        store.d["instances"], WEB_LISTEN_BASE,
        admin_addr=CADDY_ADMIN if CADDY_MANAGED else None,
        site_id=store.d["settings"].get("default_site") or "default",
    )


def caddy_env():
    return {**os.environ, "XDG_DATA_HOME": str(CADDY_STORAGE), "XDG_CONFIG_HOME": str(CADDY_CONFIG_HOME)}


def dns_info(host):
    """Указывает ли A-запись домена на этот сервер (иначе Let's Encrypt не сможет подтвердить домен)."""
    server_ip = detected_host["value"]
    try:
        ips = sorted({a[4][0] for a in socket.getaddrinfo(host, None, socket.AF_INET)})
    except socket.gaierror as e:
        return {"ok": False, "ips": [], "server_ip": server_ip, "error": f"домен не резолвится: {e}"}
    return {"ok": (server_ip in ips) if server_ip else None, "ips": ips, "server_ip": server_ip}


def cert_info(host):
    """Реальный TLS-запрос к локальному Caddy с полной проверкой цепочки: сертификат публично доверенный и сайт отвечает."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection(("127.0.0.1", 443), timeout=4) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as t:
                c = t.getpeercert()
                exp = int(ssl.cert_time_to_seconds(c["notAfter"]))
                issuer = {k: v for rdn in c.get("issuer", ()) for k, v in rdn}
                t.settimeout(4)
                t.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                head = t.recv(300).split(b"\r\n", 1)[0].decode(errors="replace")
                who = issuer.get("organizationName") or issuer.get("commonName", "")
                res = {"ok": True, "issuer": who, "expires": exp, "days_left": int((exp - time.time()) // 86400), "site": head}
                if "Local Authority" in (issuer.get("commonName", "") + who):
                    res.update(ok=False, error="сертификат выдан внутренним CA Caddy — клиенты ему не доверяют; нужен публичный домен, указывающий на этот сервер")
                return res
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "error": f"сертификат не прошёл проверку: {e.verify_message}"}
    except ssl.SSLError:
        return {"ok": False, "error": "сертификат ещё не выпущен или ACME не прошёл — смотрите лог Caddy"}
    except OSError as e:
        return {"ok": False, "error": f"Caddy не слушает 443 ({e.__class__.__name__}) — порт занят другим сервисом или Caddy не запущен"}


class CaddyRunner:
    def __init__(self):
        self.proc = None
        self.logs = deque(maxlen=400)
        self.started = 0.0
        self.restarts = 0
        self.stopping = False
        self.applied = ""      # sha256 Caddyfile, который сейчас загружен в Caddy
        self.validated = ""    # sha256 последней проверенной версии
        self.valid = None
        self.valid_msg = ""
        self.version = ""
        self.last_error = ""
        self.cert = None
        self.dns = None
        self.checked_at = 0.0
        self.next_start = 0.0
        self.next_reload = 0.0
        self.lock = asyncio.Lock()

    @property
    def running(self):
        return self.proc is not None and self.proc.returncode is None

    def log(self, s):
        self.logs.append(f"{time.strftime('%H:%M:%S')} {s}")

    async def start(self):
        CADDY_STORAGE.mkdir(parents=True, exist_ok=True)
        CADDY_CONFIG_HOME.mkdir(parents=True, exist_ok=True)
        if CADDY_ADMIN.startswith("unix/"):
            Path(CADDY_ADMIN[5:]).parent.mkdir(parents=True, exist_ok=True)
        path = sites_mgr.caddy_dir / "Caddyfile"
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.stopping = False
        self.last_error = ""
        self.proc = await asyncio.create_subprocess_exec(
            "caddy", "run", "--config", str(path), "--adapter", "caddyfile",
            env=caddy_env(), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        self.applied = digest
        self.started = time.time()
        self.log("[panel] caddy запущен")
        asyncio.create_task(self._read(self.proc))

    async def _read(self, proc):
        async for line in proc.stdout:
            self.log(ANSI.sub("", line.decode(errors="replace").rstrip()))
        code = await proc.wait()
        if self.stopping:
            return
        self.restarts += 1
        self.log(f"[panel] caddy завершился с кодом {code}, повтор через несколько секунд")
        self.last_error = f"caddy завершился с кодом {code}: " + " | ".join(list(self.logs)[-3:])[-300:]
        self.next_start = time.time() + (3 if time.time() - self.started > 60 else 15)
        if "address already in use" in " ".join(list(self.logs)[-8:]):
            self.last_error = CADDY_BUSY_MSG.format(ports="80/443")
            self.next_start = time.time() + 30

    async def reload(self):
        path = sites_mgr.caddy_dir / "Caddyfile"
        digest = hashlib.sha256(path.read_bytes()).hexdigest()

        def run():
            return subprocess.run(
                ["caddy", "reload", "--config", str(path), "--adapter", "caddyfile", "--address", CADDY_ADMIN],
                capture_output=True, text=True, timeout=30, env=caddy_env())
        r = await asyncio.to_thread(run)
        if r.returncode == 0:
            self.applied, self.last_error = digest, ""
            self.log("[panel] конфиг применён (reload)")
            return True, "Caddy перезагружен"
        msg = (r.stderr or r.stdout or "reload не удался").strip()[-400:]
        self.last_error = msg
        self.next_reload = time.time() + 30
        self.log("[panel] reload не удался: " + msg)
        return False, msg

    async def stop(self):
        self.stopping = True
        if self.running:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), 10)
            except asyncio.TimeoutError:
                self.proc.kill()
        self.proc = None


caddy = CaddyRunner()


async def caddy_apply(force=False):
    """Пишет Caddyfile, проверяет и запускает/перезагружает Caddy. Возвращает (ok, сообщение)."""
    async with caddy.lock:
        content = caddy_content()
        path = sites_mgr.caddy_dir / "Caddyfile"
        if not path.exists() or path.read_text(encoding="utf-8") != content:
            sites_mgr.write_caddyfile(content)
        if not CADDY_MANAGED:
            if force:
                return await asyncio.to_thread(sites_mgr.try_reload)
            return True, "Caddyfile записан (Caddy управляется вне панели)"
        if not shutil.which("caddy"):
            caddy.last_error = "caddy не найден в образе — пересоберите: docker compose build --no-cache && docker compose up -d"
            return False, caddy.last_error
        if not caddy.version:
            def ver():
                try:
                    return subprocess.run(["caddy", "version"], capture_output=True, text=True, timeout=5).stdout.split()[0]
                except Exception:  # noqa
                    return ""
            caddy.version = await asyncio.to_thread(ver)
        # Не отнимаем 80/443 у FakeTLS-инстансов telemt: после перезагрузки Caddy мог бы занять порт первым
        host_set = bool((store.d["settings"].get("public_host") or "").strip())
        clash = [i for i in store.d["instances"]
                 if i.get("enabled") and (i.get("transport") or "tls") != "web" and int(i.get("port") or 0) in (80, 443)]
        if host_set and clash and not caddy.running:
            c = clash[0]
            caddy.last_error = (f"Caddy не запущен: порт {c['port']} занят инстансом telemt «{c.get('name') or c['id']}» (FakeTLS). "
                                "Для сайта с сертификатом нужны 80 и 443 — переведите инстанс на другой порт или используйте WEB-режим.")
            return False, caddy.last_error
        if caddy.last_error.startswith("Caddy не запущен: порт"):
            caddy.last_error = ""
        digest = hashlib.sha256(content.encode()).hexdigest()
        if force or digest != caddy.validated:
            ok, msg = await asyncio.to_thread(sites_mgr.validate_caddyfile, caddy_env())
            caddy.valid, caddy.valid_msg, caddy.validated = ok, msg, digest
            if not ok:
                caddy.log("[panel] Caddyfile не прошёл проверку: " + msg)
        if caddy.valid is False:
            return False, caddy.valid_msg or "Caddyfile не прошёл проверку"
        if not caddy.running:
            if not force and time.time() < caddy.next_start:
                return False, "ожидание перед повторным запуском Caddy"
            busy = await asyncio.to_thread(ports_in_use) if host_set else []
            if busy:
                caddy.last_error = CADDY_BUSY_MSG.format(ports="/".join(map(str, busy)))
                caddy.next_start = time.time() + 20
                return False, caddy.last_error
            await caddy.start()
            return True, "Caddy запущен"
        if force or digest != caddy.applied:
            if not force and time.time() < caddy.next_reload:
                return False, "ожидание перед повторной перезагрузкой"
            return await caddy.reload()
        return True, "Конфиг актуален"


async def caddy_refresh_checks():
    host = (store.d["settings"].get("public_host") or "").strip()
    if not host:
        caddy.cert = caddy.dns = None
    elif IPV4_RE.match(host):
        caddy.dns = {"ok": None, "ips": [host], "server_ip": detected_host["value"]}
        caddy.cert = {"ok": False, "error": "для голого IP публичный сертификат автоматически не выпускается — укажите домен"}
    else:
        caddy.dns = await asyncio.to_thread(dns_info, host)
        caddy.cert = await asyncio.to_thread(cert_info, host) if (caddy.running or not CADDY_MANAGED) \
            else {"ok": False, "error": "Caddy не запущен"}
    caddy.checked_at = time.time()


async def caddy_loop():
    await asyncio.sleep(1.5)
    while True:
        try:
            if sites_mgr is not None:
                await caddy_apply()
                if time.time() - caddy.checked_at > 30:
                    await caddy_refresh_checks()
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa
            caddy.log(f"[panel] ошибка менеджера Caddy: {e}")
        await asyncio.sleep(3)


def caddy_public():
    return {
        "managed": CADDY_MANAGED, "running": caddy.running, "restarts": caddy.restarts, "version": caddy.version,
        "valid": caddy.valid, "valid_msg": caddy.valid_msg, "last_error": caddy.last_error,
        "uptime": int(time.time() - caddy.started) if caddy.running else 0,
        "cert": caddy.cert, "dns": caddy.dns, "server_ip": detected_host["value"],
        "public_host": store.d["settings"].get("public_host", ""),
    }


@asynccontextmanager
async def lifespan(_):
    global ADMIN_PW, SESSION_KEY, sites_mgr
    store.load()
    store.d.setdefault("settings", {})
    store.d["settings"].setdefault("public_host", "")
    store.d["settings"].setdefault("acme_email", "")
    store.d["settings"].setdefault("default_site", "default")
    sites_mgr = SiteManager(DATA, SITE_LISTEN_BASE)
    sites_mgr.start_all()
    ADMIN_PW, SESSION_KEY = load_secrets()
    for i in store.d["instances"]:
        if i["enabled"]:
            if tunnel_on(i):
                start_tunnels(i)
            ensure_runner(i["id"]).start()
    asyncio.create_task(detect_public_ip())
    host_task = asyncio.create_task(host_loop())
    caddy_task = asyncio.create_task(caddy_loop())
    yield
    host_task.cancel()
    caddy_task.cancel()
    await caddy.stop()
    await asyncio.gather(*(r.stop() for r in runners.values()), *(t.stop() for t in tunnels.values()))


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


class Login(BaseModel):
    password: str


@app.post("/api/login")
def login(body: Login, request: Request, response: Response):
    ip = request.client.host if request.client else "?"
    now = time.time()
    recent = [t for t in fails.get(ip, []) if now - t < 300]
    if len(recent) >= 5:
        raise HTTPException(429, "Слишком много попыток. Подождите 5 минут.")
    if not hmac.compare_digest(body.password.encode(), ADMIN_PW.encode()):
        fails[ip] = recent + [now]
        raise HTTPException(401, "Неверный пароль")
    ts = int(now)
    response.set_cookie("tp_session", f"{ts}.{sign(ts)}", max_age=SESSION_TTL, httponly=True, samesite="strict")
    return {"ok": True}


@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie("tp_session")
    return {"ok": True}


class ExitIn(BaseModel):
    host: str = ""
    ssh_port: int = 22
    ssh_user: str = DEFAULT_SSH_USER
    socks_port: int = 1080
    weight: int = 10
    enabled: bool = True


class InstIn(BaseModel):
    name: str = ""
    port: int = 443
    sni: str = "www.cloudflare.com"
    mss: str = "tspu"
    middle_proxy: bool = False
    ad_tag: str = ""
    mask_host: str = ""
    mask_port: int = 443
    enabled: bool = True
    transport: str = "tls"          # "tls" | "web"
    web_base_path: str = ""         # например "tg" или "telegram/web"
    web_decoy_upstream: str = ""    # пусто = сайт из панели
    web_site: str = "default"       # id decoy-сайта
    # --- cascade: РФ entry → abroad SOCKS exit ---
    cascade_enabled: bool = False
    upstream_type: str = "socks5"   # socks5 | socks4
    upstream_host: str = ""         # IP/host зарубежного VPS
    upstream_port: int = 1080
    upstream_user: str = ""
    upstream_pass: str = ""
    upstream_tunnel: bool = True    # SSH-туннель до exit (SOCKS на exit слушает только localhost)
    ssh_port: int = 22              # SSH-порт exit (старый формат: один exit; новый — список exits)
    ssh_user: str = DEFAULT_SSH_USER
    exits: list[ExitIn] = []        # несколько exit'ов: по SSH-туннелю на каждый, telemt балансирует по weight


def port_free(port):
    s = socket.socket()
    try:
        s.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _validate_exit(e: ExitIn, n: int):
    e.host = (e.host or "").strip()
    if not e.host:
        raise HTTPException(400, f"exit #{n}: укажите IP/хост")
    if not HOST_RE.match(e.host) and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", e.host):
        raise HTTPException(400, f"exit #{n}: некорректный хост")
    if not 1 <= int(e.ssh_port or 0) <= 65535:
        raise HTTPException(400, f"exit #{n}: ssh_port 1–65535")
    if not 1 <= int(e.socks_port or 0) <= 65535:
        raise HTTPException(400, f"exit #{n}: порт SOCKS 1–65535")
    e.ssh_user = (e.ssh_user or DEFAULT_SSH_USER).strip()
    if not SSH_USER_RE.match(e.ssh_user):
        raise HTTPException(400, f"exit #{n}: ssh_user — латиница нижнего регистра, цифры, _ и -")
    if not 1 <= int(e.weight or 0) <= 100:
        raise HTTPException(400, f"exit #{n}: weight 1–100")


def validate_cascade(body: InstIn):
    ut = (body.upstream_type or "socks5").lower()
    if ut not in ("socks5", "socks4"):
        raise HTTPException(400, "upstream_type: socks5 или socks4")
    body.upstream_type = ut
    body.upstream_host = (body.upstream_host or "").strip()
    if body.upstream_tunnel:
        exits = list(body.exits or [])
        if not exits and body.cascade_enabled and body.upstream_host:
            # старый формат (один exit в плоских полях) → список из одного
            exits = [ExitIn(host=body.upstream_host, ssh_port=body.ssh_port, ssh_user=body.ssh_user,
                            socks_port=body.upstream_port)]
        if len(exits) > MAX_EXITS:
            raise HTTPException(400, f"Не больше {MAX_EXITS} exit'ов")
        seen = set()
        for n, e in enumerate(exits, 1):
            _validate_exit(e, n)
            key = (e.host, int(e.ssh_port))
            if key in seen:
                raise HTTPException(400, f"exit #{n}: {e.host}:{e.ssh_port} уже в списке")
            seen.add(key)
        if body.cascade_enabled:
            if not exits:
                raise HTTPException(400, "Добавьте хотя бы один exit (IP зарубежного VPS)")
            if not any(e.enabled for e in exits):
                raise HTTPException(400, "Включите хотя бы один exit")
        body.exits = exits
        if exits:  # плоские поля — копия первого exit'а (совместимость и отображение)
            body.upstream_host, body.upstream_port = exits[0].host, int(exits[0].socks_port)
            body.ssh_port, body.ssh_user = int(exits[0].ssh_port), exits[0].ssh_user
        body.upstream_user = (body.upstream_user or "").strip()
        body.upstream_pass = (body.upstream_pass or "").strip()
    elif body.cascade_enabled:
        host = body.upstream_host
        if not host:
            raise HTTPException(400, "Для каскада укажите upstream_host (IP зарубежного VPS)")
        if not HOST_RE.match(host) and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            raise HTTPException(400, "Некорректный upstream_host")
        if not 1 <= int(body.upstream_port or 0) <= 65535:
            raise HTTPException(400, "upstream_port: 1–65535")
        body.upstream_user = (body.upstream_user or "").strip()
        body.upstream_pass = (body.upstream_pass or "").strip()


def validate(body: InstIn, current=None):
    transport = (body.transport or "tls").lower()
    if transport not in ("tls", "web"):
        raise HTTPException(400, "transport: tls или web")
    body.transport = transport
    validate_cascade(body)

    if transport == "web":
        # публичный порт всегда 443 (nginx), telemt слушает loopback — проверяем только private port
        if not link_host():
            raise HTTPException(400, "Для WEB-режима задайте «Адрес в ссылках» (домен) в Системе")
        base = (body.web_base_path or "").strip().strip("/")
        if base and not re.match(r"^[A-Za-z0-9][A-Za-z0-9_/-]{0,126}[A-Za-z0-9]$", base):
            raise HTTPException(400, "web_base_path: сегменты [A-Za-z0-9_-], без ведущего/завершающего /")
        # private port не пересекается с панелью и другими WEB
        wport = WEB_LISTEN_BASE + (current["id"] if current else store.d["next_id"])
        if wport == PANEL_PORT:
            raise HTTPException(400, "Внутренний WEB-порт совпал с панелью")
        for o in store.d["instances"]:
            if (o.get("transport") or "tls") != "web":
                continue
            if current and o["id"] == current["id"]:
                continue
            if WEB_LISTEN_BASE + o["id"] == wport:
                raise HTTPException(400, "Конфликт внутренних WEB-портов")
        # port в UI для web — информационный (443)
        body.port = 443
        return

    if not 1 <= body.port <= 65535:
        raise HTTPException(400, "Порт должен быть от 1 до 65535")
    if body.port == PANEL_PORT:
        raise HTTPException(400, "Этот порт занят самой панелью")
    for o in store.d["instances"]:
        if (o.get("transport") or "tls") == "web":
            continue
        if o["port"] == body.port and (current is None or o["id"] != current["id"]):
            raise HTTPException(400, f"Порт {body.port} уже используется инстансом «{o['name']}»")
    own_running = current is not None and current["port"] == body.port and ensure_runner(current["id"]).running
    if body.enabled and not own_running:
        if not port_free(body.port):
            raise HTTPException(400, f"Порт {body.port} занят другим процессом на сервере")
    if not HOST_RE.match(body.sni):
        raise HTTPException(400, "SNI должен быть доменом, например www.cloudflare.com")
    if body.mss not in ("", "tspu") and not (body.mss.isdigit() and 40 <= int(body.mss) <= 1460):
        raise HTTPException(400, "MSS: пусто, «tspu» или число 40–1460")
    if body.ad_tag and not HEX32.match(body.ad_tag):
        raise HTTPException(400, "ad_tag — ровно 32 hex-символа")
    if body.mask_host and not HOST_RE.match(body.mask_host):
        raise HTTPException(400, "Некорректный mask_host")
    if not 1 <= body.mask_port <= 65535:
        raise HTTPException(400, "Некорректный mask_port")


@app.get("/api/presets", dependencies=[Depends(require_auth)])
def presets():
    return PRESETS


@app.get("/api/state", dependencies=[Depends(require_auth)])
async def state():
    async def one(i):
        users, summ, health = await asyncio.gather(tapi(i, "/v1/users"), tapi(i, "/v1/stats/summary"), tapi(i, "/v1/health"))
        return public_view(i, users, summ, health)
    insts = await asyncio.gather(*(one(i) for i in store.d["instances"]))
    caddy = {}
    sites = []
    if sites_mgr is not None:
        sites = sites_mgr.list_sites()
        caddy = {**sites_mgr.caddy_status(), **caddy_public(), "preview": caddy_content()}
    return {
        "settings": {**store.d["settings"], "detected_host": detected_host["value"]},
        "system": store.d.get("system", {}),
        "instances": insts,
        "sites": sites,
        "caddy": caddy,
    }


@app.post("/api/instances", dependencies=[Depends(require_auth)])
async def create_instance(body: InstIn):
    validate(body)
    async with store.lock:
        iid = store.d["next_id"]
        store.d["next_id"] += 1
        default_name = f"web:{link_host()}" if body.transport == "web" else f"{body.sni}:{body.port}"
        inst = {**body.model_dump(), "id": iid, "name": body.name.strip()[:40] or default_name,
                "api_token": secrets.token_hex(16),
                "users": [{"name": "user1", "secret": secrets.token_hex(16), "enabled": True}]}
        store.d["instances"].append(inst)
        store.save()
    await restart_instance(inst)
    await host_reconcile()
    return {"id": iid}


@app.patch("/api/instances/{iid}", dependencies=[Depends(require_auth)])
async def update_instance(iid: int, body: InstIn):
    inst = store.get(iid)
    validate(body, inst)
    async with store.lock:
        inst.update({**body.model_dump(), "name": body.name.strip()[:40] or inst["name"]})
        store.save()
    await restart_instance(inst)  # SNI/порт/MSS не применяются на лету — нужен рестарт
    await host_reconcile()
    return {"ok": True}


@app.delete("/api/instances/{iid}", dependencies=[Depends(require_auth)])
async def delete_instance(iid: int):
    inst = store.get(iid)
    await ensure_runner(iid).stop()
    runners.pop(iid, None)
    await stop_tunnels(iid)
    async with store.lock:
        store.d["instances"].remove(inst)
        store.save()
    await host_reconcile()
    return {"ok": True}


@app.post("/api/instances/{iid}/restart", dependencies=[Depends(require_auth)])
async def restart(iid: int):
    inst = store.get(iid)
    if inst["enabled"] and not ensure_runner(iid).running and not port_free(inst["port"]):
        raise HTTPException(400, f"Порт {inst['port']} занят другим процессом на сервере")
    await restart_instance(inst)
    return {"ok": True}


class UserIn(BaseModel):
    name: str
    secret: str = ""


@app.post("/api/instances/{iid}/users", dependencies=[Depends(require_auth)])
async def add_user(iid: int, body: UserIn):
    inst = store.get(iid)
    if not USER_RE.match(body.name):
        raise HTTPException(400, "Имя: латиница, цифры, _ . - (до 64 символов)")
    if any(u["name"] == body.name for u in inst["users"]):
        raise HTTPException(409, "Такой пользователь уже есть")
    if body.secret and not HEX32.match(body.secret):
        raise HTTPException(400, "Секрет — 32 hex-символа или пусто (сгенерировать)")
    async with store.lock:
        inst["users"].append({"name": body.name, "secret": (body.secret or secrets.token_hex(16)).lower(), "enabled": True})
        store.save()
    write_config(inst)  # telemt подхватит пользователя сам, без рестарта
    return {"ok": True}


def find_user(inst, name):
    for u in inst["users"]:
        if u["name"] == name:
            return u
    raise HTTPException(404, "Пользователь не найден")


@app.delete("/api/instances/{iid}/users/{name}", dependencies=[Depends(require_auth)])
async def del_user(iid: int, name: str):
    inst = store.get(iid)
    u = find_user(inst, name)
    if len(inst["users"]) == 1:
        raise HTTPException(400, "Нельзя удалить последнего пользователя")
    async with store.lock:
        inst["users"].remove(u)
        store.save()
    write_config(inst)
    return {"ok": True}


@app.post("/api/instances/{iid}/users/{name}/rotate", dependencies=[Depends(require_auth)])
async def rotate_user(iid: int, name: str):
    inst = store.get(iid)
    u = find_user(inst, name)
    async with store.lock:
        u["secret"] = secrets.token_hex(16)
        store.save()
    write_config(inst)
    return {"ok": True}


@app.get("/api/instances/{iid}/logs", dependencies=[Depends(require_auth)])
def logs(iid: int):
    store.get(iid)
    return {"lines": list(ensure_runner(iid).logs)[-300:]}


def tls_probe(host):
    """Достижим ли маскировочный домен с этого сервера и отдаёт ли он валидный TLS."""
    try:
        socket.getaddrinfo(host, 443)
    except OSError as e:
        return False, f"DNS не резолвит {host}: {e}"
    try:
        with socket.create_connection((host, 443), timeout=5) as s:
            with ssl.create_default_context().wrap_socket(s, server_hostname=host) as t:
                return True, f"TLS-рукопожатие с {host}:443 успешно ({t.version()})"
    except Exception as e:  # noqa
        return False, f"Не удалось установить TLS с {host}:443: {e}"


@app.get("/api/instances/{iid}/diagnostics", dependencies=[Depends(require_auth)])
async def diagnostics(iid: int):
    i = store.get(iid)
    r = ensure_runner(iid)
    checks = []

    def add(level, title, detail):
        checks.append({"level": level, "title": title, "detail": detail})

    add("ok" if r.running else "bad", "Процесс telemt", "Запущен" if r.running else "Не запущен — смотрите вкладку «Логи».")
    health, summ = await asyncio.gather(tapi(i, "/v1/health"), tapi(i, "/v1/stats/summary"))
    add("ok" if health else "bad", "Control API", "Отвечает" if health else "Не отвечает (процесс ещё стартует или упал).")

    def local_listen():
        try:
            socket.create_connection(("127.0.0.1", i["port"]), timeout=2).close()
            return True
        except OSError:
            return False
    listening = await asyncio.to_thread(local_listen)
    add("ok" if listening else "bad", f"Порт {i['port']} слушается локально", "Да" if listening else "Нет — порт не открыт процессом.")

    ok, msg = await asyncio.to_thread(tls_probe, i["mask_host"] or i["sni"])
    add("ok" if ok else "bad", "Маскировочный домен достижим с сервера", msg)

    cache = [p for p in inst_dir(i).rglob("*.json") if "tlsfront" in str(p)]
    if cache:
        add("ok", "TLS-эмуляция: сертификат подтянут", ", ".join(f"{p.name} ({p.stat().st_size // 1024} КБ)" for p in cache))
    else:
        add("warn", "TLS-эмуляция: кэша нет",
            "Telemt не получил реальный сертификат домена и использует поддельный по умолчанию — это легче заметить DPI. "
            "Проверьте пункт про достижимость домена выше.")

    s = (summ or {}).get("data") or {}
    total, bad = s.get("connections_total", 0), s.get("connections_bad_total", 0)
    if summ:
        if total == 0:
            add("warn", "Входящих соединений не было",
                "Либо порт закрыт файрволом хостера/UFW, либо провайдер клиента режет порт или TLS-отпечаток. "
                "Проверьте порт снаружи (например, с телефона по мобильной сети) и обновите Telegram.")
        elif bad and bad >= total * 0.8:
            add("warn", f"Почти все соединения отбракованы ({bad} из {total})",
                "Типичные причины: зондирование, устаревший клиент, несовпадение SNI/секрета со ссылкой. "
                "Если вы меняли SNI — перевыпустите ссылки.")
        else:
            add("ok", "Соединения проходят", f"Всего {total}, из них отбраковано {bad}.")
        for c in s.get("handshake_failures_by_class", []):
            add("info", f"Сбои рукопожатия: {c['class']}", str(c["total"]))
    return {"checks": checks}


@app.get("/api/system", dependencies=[Depends(require_auth)])
async def system_info():
    s = store.d["system"]
    return {
        "telemt": {"version": await asyncio.to_thread(telemt_version), "custom": (DATA / "bin" / "telemt").exists()},
        "system": s,
        "sysctl": [{"name": n, "target": v, "current": sysctl_read(g, n), "ok": sysctl_read(g, n) in (None, v)} for g, n, v in SYSCTLS],
        "sysctl_errors": sys_state["errors"],
        "firewall": {"active": fw_state["active"], "error": fw_state["error"], "rate_error": fw_state["rate_error"],
                     "ports": sorted(i["port"] for i in store.d["instances"] if i["enabled"])},
        "password_from_env": bool(os.getenv("PANEL_PASSWORD", "").strip()),
    }


class SysIn(BaseModel):
    sysctl: bool
    firewall: bool
    rate_limit: bool


@app.put("/api/system", dependencies=[Depends(require_auth)])
async def put_system(body: SysIn):
    async with store.lock:
        store.d["system"] = body.model_dump()
        store.save()
    fw_state["sig"] = None
    await host_reconcile()
    return {"ok": True}


@app.get("/api/system/latest", dependencies=[Depends(require_auth)])
async def latest():
    try:
        return {"latest": await asyncio.to_thread(fetch_latest_version)}
    except Exception as e:  # noqa
        raise HTTPException(502, f"Не удалось получить версию с GitHub: {e}")


@app.post("/api/system/update", dependencies=[Depends(require_auth)])
async def update_telemt():
    try:
        ver = await asyncio.to_thread(install_latest_telemt)
    except Exception as e:  # noqa
        raise HTTPException(502, f"Обновление не удалось: {e}")
    for i in store.d["instances"]:
        await restart_instance(i)
    return {"version": ver}


class PwIn(BaseModel):
    old: str
    new: str


@app.put("/api/password", dependencies=[Depends(require_auth)])
def change_password(body: PwIn, response: Response):
    global ADMIN_PW, SESSION_KEY
    if os.getenv("PANEL_PASSWORD", "").strip():
        raise HTTPException(400, "Пароль задан переменной PANEL_PASSWORD в .env — измените его там и перезапустите контейнер.")
    if not hmac.compare_digest(body.old.encode(), ADMIN_PW.encode()):
        raise HTTPException(401, "Текущий пароль неверен")
    if len(body.new) < 8:
        raise HTTPException(400, "Новый пароль — минимум 8 символов")
    (DATA / "admin_password").write_text(body.new)
    SESSION_KEY = secrets.token_hex(32).encode()  # все старые сессии станут недействительны
    (DATA / "session.key").write_text(SESSION_KEY.decode())
    ADMIN_PW = body.new
    ts = int(time.time())
    response.set_cookie("tp_session", f"{ts}.{sign(ts)}", max_age=SESSION_TTL, httponly=True, samesite="strict")
    return {"ok": True}



# ---------------------------------------------------------------- cascade / exit VPS
def build_exit_script(user: str, password: str, port: int = 1080) -> str:
    """Одноразовый скрипт для зарубежного VPS: SOCKS5 (Docker microsocks/go-socks5)."""
    user = user or "telemt"
    password = password or secrets.token_urlsafe(12)
    port = int(port or 1080)
    return f"""#!/usr/bin/env bash
# telemt-panel: exit node (SOCKS5) for cascade
# Run as root on a FOREIGN VPS. Client never connects here — only your RU entry does.
set -euo pipefail
PORT={port}
USER_NAME={json.dumps(user)}
PASS={json.dumps(password)}
NAME=telemt-exit-socks

if ! command -v docker >/dev/null 2>&1; then
  echo "[*] Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker || true
fi

docker rm -f "$NAME" 2>/dev/null || true
docker run -d --name "$NAME" --restart unless-stopped \\
  -p "${{PORT}}:1080" \\
  -e PROXY_USER="$USER_NAME" \\
  -e PROXY_PASSWORD="$PASS" \\
  serjs/go-socks5-proxy

# firewall (best-effort)
if command -v ufw >/dev/null 2>&1; then
  ufw allow "${{PORT}}/tcp" || true
elif command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --add-port="${{PORT}}/tcp" --permanent || true
  firewall-cmd --reload || true
fi

PUB=$(curl -4 -fsS --max-time 5 ifconfig.me 2>/dev/null || curl -4 -fsS --max-time 5 icanhazip.com 2>/dev/null || echo "YOUR_EXIT_IP")
echo
echo "=== EXIT READY ==="
echo "upstream_host = $PUB"
echo "upstream_port = $PORT"
echo "upstream_user = $USER_NAME"
echo "upstream_pass = $PASS"
echo
echo "В панели (инстанс → Каскад) вставьте эти значения и сохраните."
echo "Ссылка tg://webproxy для клиентов НЕ меняется — только exit."
"""


def build_exit_script_tunnel(pubkey: str, ssh_user: str = DEFAULT_SSH_USER, port: int = 1080) -> str:
    """Скрипт exit для режима SSH-туннеля: берётся из exit-setup.sh (единый источник), в него подставляются значения панели."""
    here = Path(__file__).parent
    for cand in (here / "exit-setup.sh", here.parent / "exit-setup.sh"):
        if cand.exists():
            body = cand.read_text(encoding="utf-8")
            break
    else:
        raise HTTPException(500, "exit-setup.sh не найден рядом с приложением")
    defaults = f"PUBKEY={shlex.quote(pubkey)}\nSSH_USER={shlex.quote(ssh_user)}\nRPORT={int(port)}"
    return body.replace("#__PANEL_DEFAULTS__", defaults, 1)


@app.get("/api/cascade/ssh-pubkey", dependencies=[Depends(require_auth)])
def cascade_ssh_pubkey():
    try:
        return {"pubkey": ssh_pubkey()}
    except (RuntimeError, FileNotFoundError) as e:
        raise HTTPException(500, f"Не удалось получить SSH-ключ панели (нет openssh-client? пересоберите образ): {e}")


class ExitGenIn(BaseModel):
    upstream_port: int = 1080
    upstream_user: str = ""
    upstream_pass: str = ""
    tunnel: bool = True
    ssh_user: str = DEFAULT_SSH_USER


@app.post("/api/cascade/exit-script", dependencies=[Depends(require_auth)])
def cascade_exit_script(body: ExitGenIn):
    """Скрипт развёртки SOCKS5 на зарубежном VPS + готовые креды."""
    user = (body.upstream_user or "").strip() or "telemt"
    password = (body.upstream_pass or "").strip() or secrets.token_urlsafe(14)
    port = int(body.upstream_port or 1080)
    if not 1 <= port <= 65535:
        raise HTTPException(400, "port 1–65535")
    if body.tunnel:
        ssh_user = (body.ssh_user or DEFAULT_SSH_USER).strip()
        if not SSH_USER_RE.match(ssh_user):
            raise HTTPException(400, "ssh_user: латиница нижнего регистра, цифры, _ и -")
        pub = cascade_ssh_pubkey()["pubkey"]
        return {
            "script": build_exit_script_tunnel(pub, ssh_user, port),
            "tunnel": True, "upstream_type": "socks5", "upstream_port": port, "ssh_user": ssh_user,
            "hint": "На зарубежном VPS: скопируйте скрипт → bash. IP и SSH-порт из вывода впишите в каскад инстанса.",
        }
    script = build_exit_script(user, password, port)
    return {
        "script": script,
        "upstream_type": "socks5",
        "upstream_port": port,
        "upstream_user": user,
        "upstream_pass": password,
        "hint": "На зарубежном VPS: скопируйте скрипт → bash. Затем IP из вывода впишите в каскад инстанса.",
    }


@app.post("/api/instances/{iid}/cascade", dependencies=[Depends(require_auth)])
async def set_cascade(iid: int, body: InstIn):
    """Включить/обновить каскад у инстанса (остальные поля можно не трогать)."""
    inst = store.get(iid)
    # merge only cascade fields onto current instance snapshot
    merged = InstIn(
        name=inst.get("name", ""),
        port=inst.get("port", 443),
        sni=inst.get("sni", "www.cloudflare.com"),
        mss=inst.get("mss", "tspu"),
        middle_proxy=bool(inst.get("middle_proxy")),
        ad_tag=inst.get("ad_tag", ""),
        mask_host=inst.get("mask_host", ""),
        mask_port=int(inst.get("mask_port") or 443),
        enabled=bool(inst.get("enabled", True)),
        transport=inst.get("transport") or "tls",
        web_base_path=inst.get("web_base_path") or "",
        web_decoy_upstream=inst.get("web_decoy_upstream") or "",
        web_site=inst.get("web_site") or "default",
        cascade_enabled=body.cascade_enabled,
        upstream_type=body.upstream_type or "socks5",
        upstream_host=body.upstream_host or "",
        upstream_port=int(body.upstream_port or 1080),
        upstream_user=body.upstream_user or "",
        upstream_pass=body.upstream_pass or "",
        upstream_tunnel=body.upstream_tunnel,
        ssh_port=int(body.ssh_port or 22),
        ssh_user=body.ssh_user or DEFAULT_SSH_USER,
        exits=body.exits,
    )
    validate(merged, inst)
    async with store.lock:
        inst["cascade_enabled"] = merged.cascade_enabled
        inst["upstream_type"] = merged.upstream_type
        inst["upstream_host"] = merged.upstream_host
        inst["upstream_port"] = merged.upstream_port
        inst["upstream_user"] = merged.upstream_user
        inst["upstream_pass"] = merged.upstream_pass
        inst["upstream_tunnel"] = merged.upstream_tunnel
        inst["ssh_port"] = merged.ssh_port
        inst["ssh_user"] = merged.ssh_user
        inst["exits"] = [e.model_dump() for e in merged.exits]
        if merged.cascade_enabled:
            # middle-proxy / ad_tag ломают custom upstream
            inst["middle_proxy"] = False
        store.save()
    await restart_instance(inst)
    return {"ok": True, "cascade_active": cascade_on(inst)}


@app.post("/api/instances/{iid}/tunnel/reset-hostkey", dependencies=[Depends(require_auth)])
async def tunnel_reset_hostkey(iid: int):
    """Забыть сохранённый ключ хоста exit (после переустановки exit) и переподключить туннель."""
    inst = store.get(iid)
    hosts = {e["host"] for e in cascade_exits(inst)} | {(inst.get("upstream_host") or "").strip()}
    for host in hosts:
        if host:
            known_hosts_path(host).unlink(missing_ok=True)
    await restart_instance(inst)
    return {"ok": True}


@app.post("/api/instances/{iid}/exits/check", dependencies=[Depends(require_auth)])
async def check_exits(iid: int):
    """Проверка каждого exit'а: SOCKS5 CONNECT на DC Telegram через его туннель (цепочка вход → exit → Telegram)."""
    inst = store.get(iid)
    act = active_exits(inst) if tunnel_on(inst) else []
    results = await asyncio.gather(*(socks_probe(tunnel_local_port(inst, idx)) for idx, _ in act))
    return {"results": [{"idx": idx, "host": e["host"], **r} for (idx, e), r in zip(act, results)]}


@app.get("/api/instances/{iid}/cascade/script", dependencies=[Depends(require_auth)])
def instance_exit_script(iid: int, tunnel: int = -1, exit: int = 0):
    """Скрипт exit. tunnel=1 — режим SSH-туннеля, 0 — прямой SOCKS5, по умолчанию как сохранено в инстансе."""
    inst = store.get(iid)
    use_tunnel = bool(inst.get("upstream_tunnel", False)) if tunnel < 0 else bool(tunnel)
    if use_tunnel:
        ex = cascade_exits(inst)
        e = ex[min(max(exit, 0), len(ex) - 1)] if ex else {}
        ssh_user = e.get("ssh_user") or inst.get("ssh_user") or DEFAULT_SSH_USER
        port = int(e.get("socks_port") or inst.get("upstream_port") or 1080)
        pub = cascade_ssh_pubkey()["pubkey"]
        return {
            "script": build_exit_script_tunnel(pub, ssh_user, port),
            "tunnel": True, "upstream_type": "socks5", "upstream_port": port, "ssh_user": ssh_user,
            "upstream_host": (e.get("host") or inst.get("upstream_host") or ""),
            "cascade_enabled": bool(inst.get("cascade_enabled")),
        }
    user = (inst.get("upstream_user") or "").strip() or "telemt"
    password = (inst.get("upstream_pass") or "").strip() or secrets.token_urlsafe(14)
    port = int(inst.get("upstream_port") or 1080)
    # persist generated secrets if empty so panel and script match
    changed = False
    if not (inst.get("upstream_user") or "").strip():
        inst["upstream_user"] = user
        changed = True
    if not (inst.get("upstream_pass") or "").strip():
        inst["upstream_pass"] = password
        changed = True
    if changed:
        store.save()
    return {
        "script": build_exit_script(user, password, port),
        "upstream_type": inst.get("upstream_type") or "socks5",
        "upstream_port": port,
        "upstream_user": user,
        "upstream_pass": password,
        "upstream_host": inst.get("upstream_host") or "",
        "cascade_enabled": bool(inst.get("cascade_enabled")),
    }


# ---------------------------------------------------------------- Caddy + сайты
class SettingsIn(BaseModel):
    public_host: str = ""
    acme_email: str = ""
    default_site: str = "default"


@app.put("/api/settings", dependencies=[Depends(require_auth)])
async def put_settings(body: SettingsIn):
    host = body.public_host.strip().lower()
    if host and not HOST_RE.match(host) and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        raise HTTPException(400, "Некорректный public_host")
    async with store.lock:
        store.d["settings"]["public_host"] = host
        store.d["settings"]["acme_email"] = body.acme_email.strip()
        site_pick = (body.default_site or "default").strip() or "default"
        if sites_mgr and not (sites_mgr.sites_dir / site_pick).is_dir():
            raise HTTPException(400, f"Сайт «{site_pick}» не найден")
        store.d["settings"]["default_site"] = site_pick
        store.save()
    for i in store.d["instances"]:
        if i.get("enabled"):
            write_config(i)
            if (i.get("transport") or "tls") == "web":
                await restart_instance(i)
    if sites_mgr:
        caddy.checked_at = 0.0  # сразу перепроверить DNS/сертификат нового домена
        asyncio.create_task(caddy_apply())
    return {"ok": True}


@app.get("/api/caddy", dependencies=[Depends(require_auth)])
def get_caddy():
    if not sites_mgr:
        raise HTTPException(503, "sites not ready")
    path = sites_mgr.caddy_dir / "Caddyfile"
    return {**sites_mgr.caddy_status(), **caddy_public(), "preview": caddy_content(), "path": str(path)}


@app.post("/api/caddy/reload", dependencies=[Depends(require_auth)])
async def reload_caddy():
    """Записать Caddyfile, проверить и (пере)запустить Caddy."""
    if not sites_mgr:
        raise HTTPException(503, "sites not ready")
    ok, msg = await caddy_apply(force=True)
    if not ok:
        raise HTTPException(400, msg)
    caddy.checked_at = 0.0
    return {"ok": True, "detail": msg}


@app.post("/api/caddy/check", dependencies=[Depends(require_auth)])
async def check_caddy():
    """Проверить прямо сейчас: DNS домена и сертификат, который отдаёт Caddy."""
    if not sites_mgr:
        raise HTTPException(503, "sites not ready")
    await caddy_refresh_checks()
    return caddy_public()


@app.get("/api/caddy/log", dependencies=[Depends(require_auth)])
def caddy_log():
    return {"lines": list(caddy.logs)[-200:]}


@app.get("/api/sites", dependencies=[Depends(require_auth)])
def list_sites():
    if not sites_mgr:
        return []
    return sites_mgr.list_sites()


@app.post("/api/sites", dependencies=[Depends(require_auth)])
async def create_site(request: Request):
    body = await request.json()
    site_id = (body.get("id") or "").strip()
    if not sites_mgr:
        raise HTTPException(503, "sites not ready")
    try:
        sites_mgr.ensure_site(site_id)
        sites_mgr.start_site(site_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "id": site_id}


@app.delete("/api/sites/{site_id}", dependencies=[Depends(require_auth)])
def delete_site(site_id: str):
    if not sites_mgr:
        raise HTTPException(503, "sites not ready")
    try:
        sites_mgr.delete_site(site_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@app.post("/api/sites/{site_id}/upload", dependencies=[Depends(require_auth)])
async def upload_site(site_id: str, file: UploadFile = File(...)):
    if not sites_mgr:
        raise HTTPException(503, "sites not ready")
    data = await file.read()
    if len(data) > 15 * 1024 * 1024:
        raise HTTPException(400, "Файл больше 15 МБ")
    try:
        url = sites_mgr.save_upload(site_id, file.filename or "index.html", data)
    except ValueError as e:
        raise HTTPException(400, str(e))
    # refresh web instances using this site
    for i in store.d["instances"]:
        if (i.get("transport") or "tls") == "web" and (i.get("web_site") or "default") == site_id:
            write_config(i)
    return {"ok": True, "upstream": url, "site": site_id}


class QuickWebIn(BaseModel):
    name: str = ""
    base_path: str = ""
    site: str = "default"


@app.post("/api/instances/web", dependencies=[Depends(require_auth)])
async def create_web_quick(body: QuickWebIn):
    """Один клик: WEB-инстанс на public_host."""
    if not link_host():
        raise HTTPException(400, "Сначала укажите домен в Системе → Адрес в ссылках")
    site = (body.site or "default").strip() or "default"
    if sites_mgr:
        sites_mgr.ensure_site(site)
        sites_mgr.start_site(site)
    inst_body = InstIn(
        name=body.name or f"WEB {link_host()}",
        transport="web",
        port=443,
        sni=link_host(),
        web_base_path=(body.base_path or "").strip().strip("/"),
        web_site=site,
        enabled=True,
    )
    validate(inst_body)
    async with store.lock:
        iid = store.d["next_id"]
        store.d["next_id"] += 1
        inst = {
            **inst_body.model_dump(),
            "id": iid,
            "name": inst_body.name.strip()[:40] or f"web:{link_host()}",
            "api_token": secrets.token_hex(16),
            "users": [{"name": "user1", "secret": secrets.token_hex(16), "enabled": True}],
        }
        store.d["instances"].append(inst)
        store.save()
    await restart_instance(inst)
    await host_reconcile()
    if sites_mgr:
        content = caddy_content()
        sites_mgr.write_caddyfile(content)
    return {"id": iid}




@app.get("/")
def index():
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})


if __name__ == "__main__":
    uvicorn.run(app, host=PANEL_BIND, port=PANEL_PORT, log_level="warning")
