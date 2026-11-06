"""Caddyfile generation, decoy static sites, and site upload helpers for telemt-panel."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
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
            tmp = root / "_upload.zip"
            tmp.write_bytes(data)
            try:
                with zipfile.ZipFile(tmp, "r") as zf:
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        # prevent path traversal
                        target = (root / info.filename).resolve()
                        if not str(target).startswith(str(root.resolve())):
                            continue
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(zf.read(info))
            finally:
                tmp.unlink(missing_ok=True)
            # if single top-level dir, flatten
            kids = [c for c in root.iterdir() if c.name != "_upload.zip"]
            if len(kids) == 1 and kids[0].is_dir() and not (root / "index.html").exists():
                top = kids[0]
                for f in top.rglob("*"):
                    if f.is_file():
                        rel = f.relative_to(top)
                        dest = root / rel
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(f), str(dest))
                shutil.rmtree(top, ignore_errors=True)
        else:
            # single file — if html, as index; else store by name
            if name.lower().endswith((".html", ".htm")) and name.lower() in ("index.html", "index.htm", "default.html"):
                (root / "index.html").write_bytes(data)
            elif name.lower().endswith((".html", ".htm")) and not (root / "index.html").exists():
                (root / "index.html").write_bytes(data)
            else:
                (root / name).write_bytes(data)
        # restart server to pick up files (SimpleHTTPRequestHandler reads live)
        return self.upstream_url(site_id)

    def generate_caddyfile(self, public_host: str, email: str, web_instances: list[dict], web_listen_base: int) -> str:
        host = (public_host or "").strip().lower()
        lines = []
        if email:
            lines += [f"{email}", ""]
        if not host:
            lines += ["# Укажите домен в Системе → Адрес в ссылках", ""]
            return "\n".join(lines)

        # group WEB instances by host (all share public_host for now)
        webs = [i for i in web_instances if (i.get("transport") or "tls") == "web" and i.get("enabled")]
        if not webs:
            lines += [
                f"{host} {{",
                "\tencode gzip",
                f"\troot * {self.sites_dir / 'default'}",
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
                lines += [
                    f"\thandle_path /{base}/* {{",
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
                f"\t\troot * {self.sites_dir / 'default'}",
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
        path = self.caddy_dir / "Caddyfile"
        bin_path = shutil.which("caddy")
        running = False
        version = ""
        if bin_path:
            try:
                version = subprocess.run(
                    [bin_path, "version"], capture_output=True, text=True, timeout=5
                ).stdout.strip().split("\n")[0]
            except Exception:
                pass
            try:
                r = subprocess.run(
                    [bin_path, "validate", "--config", str(path)],
                    capture_output=True, text=True, timeout=8,
                )
                valid = r.returncode == 0
                valid_msg = (r.stderr or r.stdout or "").strip()[:300]
            except Exception as e:
                valid = False
                valid_msg = str(e)
        else:
            valid = path.exists()
            valid_msg = "caddy не найден в PATH (установите на хост)"
        # detect listening 443
        try:
            import socket
            s = socket.socket()
            s.settimeout(0.3)
            running = s.connect_ex(("127.0.0.1", 443)) == 0
            s.close()
        except Exception:
            pass
        return {
            "binary": bin_path or "",
            "version": version,
            "config_path": str(path),
            "config_exists": path.exists(),
            "valid": valid,
            "valid_msg": valid_msg,
            "port_443_open": running,
        }

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
