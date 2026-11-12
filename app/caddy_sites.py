"""Caddyfile generation, decoy static sites, and site upload helpers for telemt-panel."""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import zipfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)

DEFAULT_SITE_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:system-ui,sans-serif;background:linear-gradient(145deg,#0f172a,#1e293b);color:#e2e8f0}
.card{background:rgba(255,255,255,.08);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,.12);
border-radius:20px;padding:40px 48px;text-align:center;max-width:420px;box-shadow:0 20px 50px rgba(0,0,0,.35)}
h1{margin:0 0 8px;font-size:1.6rem;font-weight:600}p{margin:0;opacity:.7;line-height:1.5}
</style></head><body><div class="card"><h1>Welcome</h1>
<p>This site is under construction.<br>Please check back later.</p></div></body></html>
"""


class SiteManager:
    def __init__(self, data: Path, listen_base: int = 18200):
        self.data = data
        self.sites_dir = data / "sites"
        self.caddy_dir = data / "caddy"
        self.listen_base = listen_base
        self._servers: dict[str, tuple[ThreadingHTTPServer, threading.Thread]] = {}
        self.sites_dir.mkdir(parents=True, exist_ok=True)
        self.caddy_dir.mkdir(parents=True, exist_ok=True)
        self.ensure_default()

    def ensure_default(self):
        d = self.sites_dir / "default"
        d.mkdir(parents=True, exist_ok=True)
        idx = d / "index.html"
        if not idx.exists():
            idx.write_text(DEFAULT_SITE_HTML, encoding="utf-8")

    def list_sites(self) -> list[dict]:
        out = []
        for p in sorted(self.sites_dir.iterdir()):
            if not p.is_dir() or p.name.startswith("."):
                continue
            files = [f.name for f in p.rglob("*") if f.is_file()]
            out.append({
                "id": p.name,
                "files": len(files),
                "has_index": (p / "index.html").exists(),
                "size": sum(f.stat().st_size for f in p.rglob("*") if f.is_file()),
                "port": self.port_for(p.name),
                "running": p.name in self._servers,
            })
        return out

    def port_for(self, site_id: str) -> int:
        # stable port from name hash
        h = sum(ord(c) for c in site_id) % 200
        return self.listen_base + h

    def site_path(self, site_id: str) -> Path:
        if not re.match(r"^[A-Za-z0-9_-]{1,40}$", site_id):
            raise ValueError("id сайта: латиница, цифры, _ -")
        return self.sites_dir / site_id

    def ensure_site(self, site_id: str = "default") -> Path:
        p = self.site_path(site_id)
        p.mkdir(parents=True, exist_ok=True)
        if not (p / "index.html").exists():
            (p / "index.html").write_text(DEFAULT_SITE_HTML, encoding="utf-8")
        return p

    def start_site(self, site_id: str):
        self.ensure_site(site_id)
        if site_id in self._servers:
            return self.port_for(site_id)
        root = self.site_path(site_id)
        port = self.port_for(site_id)

        class Handler(SimpleHTTPRequestHandler):
            def __init__(self, *a, **k):
                super().__init__(*a, directory=str(root), **k)

            def log_message(self, *args):
                pass

        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        except OSError:
            # port busy — try next
            for i in range(1, 20):
                try:
                    port = self.listen_base + (sum(ord(c) for c in site_id) + i) % 200
                    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
                    break
                except OSError:
                    continue
            else:
                raise
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        self._servers[site_id] = (httpd, t)
        return port

    def stop_site(self, site_id: str):
        pair = self._servers.pop(site_id, None)
        if pair:
            pair[0].shutdown()

    def start_all(self):
        self.ensure_default()
        for p in self.sites_dir.iterdir():
            if p.is_dir() and not p.name.startswith("."):
                try:
                    self.start_site(p.name)
                except Exception:
                    pass

    def upstream_url(self, site_id: str = "default") -> str:
        port = self.start_site(site_id)
        return f"http://127.0.0.1:{port}"

    def delete_site(self, site_id: str):
        if site_id == "default":
            raise ValueError("default нельзя удалить")
        self.stop_site(site_id)
        p = self.site_path(site_id)
        if p.exists():
            shutil.rmtree(p)

    def save_upload(self, site_id: str, filename: str, data: bytes):
        root = self.ensure_site(site_id)
        name = Path(filename).name
        if name.lower().endswith(".zip"):
            self._replace_from_zip(root, data)
        else:
            # single file — if html, as index; else store by name
            if name.lower().endswith((".html", ".htm")) and name.lower() in ("index.html", "index.htm", "default.html"):
                (root / "index.html").write_bytes(data)
            elif name.lower().endswith((".html", ".htm")) and (
                    not (root / "index.html").exists()
                    or (root / "index.html").read_text(encoding="utf-8", errors="ignore") == DEFAULT_SITE_HTML):
                # одиночная страница становится главной, пока там стандартная заглушка «Welcome»
                (root / "index.html").write_bytes(data)
            else:
                (root / name).write_bytes(data)
        # restart server to pick up files (SimpleHTTPRequestHandler reads live)
        return self.upstream_url(site_id)

    MAX_ZIP_FILES = 5000
    MAX_ZIP_BYTES = 100 * 1024 * 1024

    def _replace_from_zip(self, root: Path, data: bytes):
        """ZIP заменяет содержимое сайта целиком. index.html ищется в корне архива или в папке проекта
        (архив, собранный «папкой», — самый частый случай). Нет index.html — ошибка, сайт не трогаем."""
        tmp = Path(tempfile.mkdtemp(prefix=".upload_", dir=self.sites_dir))
        try:
            try:
                zf = zipfile.ZipFile(io.BytesIO(data))
            except zipfile.BadZipFile:
                raise ValueError("Это не ZIP-архив")
            with zf:
                infos = [i for i in zf.infolist() if not i.is_dir()]
                if len(infos) > self.MAX_ZIP_FILES or sum(i.file_size for i in infos) > self.MAX_ZIP_BYTES:
                    raise ValueError("Архив слишком большой (до 5000 файлов и 100 МБ в распакованном виде)")
                base = tmp.resolve()
                for info in infos:
                    parts = [p for p in info.filename.replace("\\", "/").split("/") if p not in ("", ".")]
                    if (not parts or ".." in parts or parts[0] == "__MACOSX"
                            or parts[-1] in (".DS_Store", "Thumbs.db")):
                        continue
                    target = tmp.joinpath(*parts).resolve()
                    if not target.is_relative_to(base):  # защита от path traversal
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(zf.read(info))
            site_root = None
            for idx_name in ("index.html", "index.htm"):
                found = sorted((p.parent for p in tmp.rglob(idx_name)),
                               key=lambda d: len(d.relative_to(tmp).parts))
                if found:
                    site_root = found[0]
                    break
            if site_root is None:
                raise ValueError("В архиве не найден index.html — сайт не изменён")
            if not (site_root / "index.html").exists():
                shutil.copy(site_root / "index.htm", site_root / "index.html")
            for child in list(root.iterdir()):
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
            for child in list(site_root.iterdir()):
                shutil.move(str(child), str(root / child.name))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def decoy_root(self, site_id: str = "default") -> Path:
        """Каталог сайта-прикрытия, который отдаёт Caddy (выбранный сайт, при ошибке — default)."""
        try:
            p = self.site_path((site_id or "default").strip() or "default")
            if p.is_dir():
                return p
        except ValueError:
            pass
        return self.sites_dir / "default"

    def generate_caddyfile(self, public_host: str, email: str, web_instances: list[dict], web_listen_base: int,
                           admin_addr: str | None = None, site_id: str = "default") -> str:
        """admin_addr задан, когда Caddy запускает сама панель: тогда в глобальные опции добавляются
        admin-сокет (для reload), читаемый консольный лог и отключение HTTP/3 (UDP 443 не нужен)."""
        host = (public_host or "").strip().lower()
        email = (email or "").strip()
        lines = []
        # Global options MUST be inside a top-level { } block
        glob = []
        if email and "@" in email:
            glob.append(f"\temail {email}")
        if admin_addr:
            glob += [
                f"\tadmin {admin_addr}",
                "\tservers {", "\t\tprotocols h1 h2", "\t}",
                "\tlog {", "\t\tformat console", "\t\tlevel INFO", "\t}",
            ]
        if glob:
            lines += ["{", *glob, "}", ""]
        if not host:
            lines += ["# Укажите домен в Системе → Адрес в ссылках", ""]
            return "\n".join(lines)

        # group WEB instances by host (all share public_host for now)
        webs = [i for i in web_instances if (i.get("transport") or "tls") == "web" and i.get("enabled")]
        if not webs:
            lines += [
                f"{host} {{",
                "\tencode gzip",
                f"\troot * {self.decoy_root(site_id)}",
                "\tfile_server",
                "}",
                "",
            ]
            return "\n".join(lines)

        lines += [f"{host} {{", "\tencode gzip"]
        # more specific base_path first
        webs_sorted = sorted(webs, key=lambda i: len((i.get("web_base_path") or "").strip()), reverse=True)
        for i in webs_sorted:
            port = web_listen_base + int(i["id"])
            base = (i.get("web_base_path") or "").strip().strip("/")
            if base:
                # keep path prefix — telemt WEB expects full path (do NOT use handle_path)
                lines += [
                    f"\thandle /{base}/* {{",
                    f"\t\treverse_proxy 127.0.0.1:{port}",
                    "\t}",
                    f"\thandle /{base} {{",
                    f"\t\treverse_proxy 127.0.0.1:{port}",
                    "\t}",
                ]
            else:
                # whole vhost → telemt (telemt itself serves decoy for non-auth)
                lines += [
                    f"\treverse_proxy 127.0.0.1:{port}",
                ]
        # if all had base_path, leftover goes to default site
        if all((i.get("web_base_path") or "").strip() for i in webs):
            lines += [
                "\thandle {",
                f"\t\troot * {self.decoy_root(site_id)}",
                "\t\tfile_server",
                "\t}",
            ]
        lines += ["}", ""]
        return "\n".join(lines)

    def write_caddyfile(self, content: str) -> Path:
        path = self.caddy_dir / "Caddyfile"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, path)
        return path

    def caddy_status(self) -> dict:
        """Дешёвый статус (вызывается при каждом опросе UI): без запуска процессов."""
        path = self.caddy_dir / "Caddyfile"
        bin_path = shutil.which("caddy")
        import socket

        def listening(port):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    return True
            except OSError:
                return False

        return {
            "binary": bin_path or "",
            "config_path": str(path),
            "config_exists": path.exists(),
            "port_443_open": listening(443),
            "port_80_open": listening(80),
        }

    def validate_caddyfile(self, env: dict | None = None) -> tuple[bool, str]:
        bin_path = shutil.which("caddy")
        path = self.caddy_dir / "Caddyfile"
        if not bin_path:
            return False, "caddy не найден в PATH"
        try:
            r = subprocess.run([bin_path, "validate", "--config", str(path), "--adapter", "caddyfile"],
                               capture_output=True, text=True, timeout=30, env=env)
            raw = (r.stderr or r.stdout or "").strip()
            # из вывода берём строки с причиной (JSON-строки «using config from file» отбрасываем)
            lines = [l for l in raw.splitlines() if l.strip() and not l.lstrip().startswith('{"level"')]
            return r.returncode == 0, ("\n".join(lines) or raw)[-400:]
        except Exception as e:  # noqa
            return False, str(e)

    def try_reload(self) -> tuple[bool, str]:
        bin_path = shutil.which("caddy")
        if not bin_path:
            return False, "caddy не установлен на хосте"
        path = self.caddy_dir / "Caddyfile"
        if not path.exists():
            return False, "Caddyfile ещё не создан"
        try:
            r = subprocess.run(
                [bin_path, "reload", "--config", str(path)],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                return True, "Caddy перезагружен"
            # try start
            r2 = subprocess.run(
                [bin_path, "start", "--config", str(path)],
                capture_output=True, text=True, timeout=15,
            )
            if r2.returncode == 0:
                return True, "Caddy запущен"
            return False, (r.stderr or r.stdout or r2.stderr or "ошибка reload/start")[:400]
        except Exception as e:
            return False, str(e)
