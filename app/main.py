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
from fastapi.responses import FileResponse
from pydantic import BaseModel

DATA = Path(os.getenv("DATA_DIR", "/data"))
TELEMT_BIN = os.getenv("TELEMT_BIN", "telemt")
PANEL_BIND = os.getenv("PANEL_BIND", "127.0.0.1")
PANEL_PORT = int(os.getenv("PANEL_PORT", "8080"))
API_PORT_BASE = 19100  # Control API инстансов: 127.0.0.1:19100+id
STATIC = Path(__file__).parent / "static"
ANSI = re.compile(r"\x1b\[[0-9;]*m")

PRESETS = [
    {"port": 443, "sni": "www.cloudflare.com", "note": "Обычный HTTPS к CDN. Самый «серый» вариант."},
    {"port": 5223, "sni": "www.apple.com", "note": "Порт Apple Push (APNs): у каждого iPhone постоянное соединение."},
    {"port": 8530, "sni": "www.microsoft.com", "note": "Порт WSUS (обновления Windows)."},
    {"port": 2053, "sni": "www.cloudflare.com", "note": "Альтернативный HTTPS-порт Cloudflare."},
    {"port": 8443, "sni": "www.cloudflare.com", "note": "Альтернативный HTTPS-порт."},
]

HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")


# ---------------------------------------------------------------- состояние
DEFAULT_SYSTEM = {"sysctl": True, "firewall": True, "rate_limit": True}


class Store:
    def __init__(self):
        self.path = DATA / "state.json"
        self.lock = asyncio.Lock()
        self.d = {"settings": {"public_host": ""}, "system": dict(DEFAULT_SYSTEM), "next_id": 1, "instances": []}

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


def inst_dir(i):
    return DATA / "instances" / str(i["id"])


def link_host():
    return store.d["settings"]["public_host"] or detected_host["value"]


def render_toml(i):
    q = json.dumps
    mm = bool(i["middle_proxy"] or i["ad_tag"])
    out = ["[general]", "fast_mode = true", f"use_middle_proxy = {str(mm).lower()}", 'log_level = "normal"']
    if i["ad_tag"]:
        out.append(f"ad_tag = {q(i['ad_tag'])}")
    out += ["", "[general.modes]", "classic = false", "secure = false", "tls = true", "", "[general.links]", 'show = "*"']
    if link_host():
        out.append(f"public_host = {q(link_host())}")
    out += ["", "[network]", "ipv4 = true", "ipv6 = false", "prefer = 4", "", "[server]", f"port = {i['port']}"]
    if i["mss"]:
        out.append(f"client_mss = {q(i['mss'])}")
    out += [
        "", "[server.api]", "enabled = true", f'listen = "127.0.0.1:{API_PORT_BASE + i["id"]}"',
        'whitelist = ["127.0.0.1/32"]', f"auth_header = {q(i['api_token'])}", "minimal_runtime_enabled = false",
        "", "[[server.listeners]]", 'ip = "0.0.0.0"',
        "", "[censorship]", f"tls_domain = {q(i['sni'])}", "mask = true", f"mask_port = {i['mask_port']}",
    ]
    if i["mask_host"]:
        out.append(f"mask_host = {q(i['mask_host'])}")
    out += [
        "tls_emulation = true", 'tls_front_dir = "tlsfront"', 'unknown_sni_action = "reject_handshake"',
        "", "[access]", "replay_check_len = 65536", "ignore_time_skew = false", "", "[access.users]",
    ]
    for u in i["users"]:
        if u.get("enabled", True):
            out.append(f"{q(u['name'])} = {q(u['secret'])}")
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


def ensure_runner(iid):
    return runners.setdefault(iid, Runner(iid))


async def restart_instance(i):
    r = ensure_runner(i["id"])
    await r.stop()
    if i["enabled"]:
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
    ports = [i["port"] for i in store.d["instances"] if i["enabled"]]
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
    return f"tg://proxy?server={host}&port={i['port']}&secret=ee{u['secret']}{i['sni'].encode().hex()}"


def public_view(i, users_api, summary, health):
    r = ensure_runner(i["id"])
    api_users = {u["username"]: u for u in (users_api or {}).get("data", [])}
    users = []
    for u in i["users"]:
        a = api_users.get(u["name"], {})
        links = [l for l in (a.get("links") or {}).get("tls", []) if "server=::" not in l]
        link = links[0] if links else local_link(i, u)
        users.append({
            "name": u["name"], "secret": u["secret"], "enabled": u.get("enabled", True),
            "link": link, "web_link": link.replace("tg://proxy", "https://t.me/proxy", 1),
            "link_from_api": bool(links),
            "connections": a.get("current_connections", 0), "ips": a.get("active_unique_ips", 0),
            "octets": a.get("total_octets", 0),
        })
    s = (summary or {}).get("data") or {}
    return {
        **{k: i[k] for k in ("id", "name", "port", "sni", "mss", "middle_proxy", "ad_tag", "mask_host", "mask_port", "enabled")},
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


@asynccontextmanager
async def lifespan(_):
    global ADMIN_PW, SESSION_KEY
    store.load()
    ADMIN_PW, SESSION_KEY = load_secrets()
    for i in store.d["instances"]:
        if i["enabled"]:
            ensure_runner(i["id"]).start()
    asyncio.create_task(detect_public_ip())
    host_task = asyncio.create_task(host_loop())
    yield
    host_task.cancel()
    await asyncio.gather(*(r.stop() for r in runners.values()))


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


class InstIn(BaseModel):
    name: str = ""
    port: int
    sni: str
    mss: str = "tspu"
    middle_proxy: bool = False
    ad_tag: str = ""
    mask_host: str = ""
    mask_port: int = 443
    enabled: bool = True


def port_free(port):
    s = socket.socket()
    try:
        s.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def validate(body: InstIn, current=None):
    if not 1 <= body.port <= 65535:
        raise HTTPException(400, "Порт должен быть от 1 до 65535")
    if body.port == PANEL_PORT:
        raise HTTPException(400, "Этот порт занят самой панелью")
    for o in store.d["instances"]:
        if o["port"] == body.port and (current is None or o["id"] != current["id"]):
            raise HTTPException(400, f"Порт {body.port} уже используется инстансом «{o['name']}»")
    # порт проверяем при создании, смене порта и включении: если инстанс сейчас работает на этом порту, он сам его держит
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
    return {"settings": {**store.d["settings"], "detected_host": detected_host["value"]}, "instances": insts}


@app.post("/api/instances", dependencies=[Depends(require_auth)])
async def create_instance(body: InstIn):
    validate(body)
    async with store.lock:
        iid = store.d["next_id"]
        store.d["next_id"] += 1
        inst = {**body.model_dump(), "id": iid, "name": body.name.strip()[:40] or f"{body.sni}:{body.port}",
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


class SettingsIn(BaseModel):
    public_host: str = ""


@app.put("/api/settings", dependencies=[Depends(require_auth)])
async def put_settings(body: SettingsIn):
    h = body.public_host.strip()
    if h and not (HOST_RE.match(h)):
        raise HTTPException(400, "Укажите домен или IPv4")
    async with store.lock:
        store.d["settings"]["public_host"] = h
        store.save()
    for i in store.d["instances"]:
        write_config(i)  # public_host входит в конфиг — применяем рестартом
        await restart_instance(i)
    return {"ok": True}



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


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})


if __name__ == "__main__":
    uvicorn.run(app, host=PANEL_BIND, port=PANEL_PORT, log_level="warning")
