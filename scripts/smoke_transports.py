#!/usr/bin/env python3
"""End-to-end smoke test: run real VLESS traffic through each local HTTP transport."""
import http.cookiejar
import json
import os
import re
import sqlite3
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = "http://127.0.0.1:8080"
DB = Path("/data/panel.sqlite3")
XRAY = os.getenv("XRAY_BIN", "/usr/local/bin/xray")
MARKER = b"abyss-xray-tunnel-ok"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(MARKER)))
        self.end_headers()
        self.wfile.write(MARKER)

    def log_message(self, *_args):
        pass


def wait_until(predicate, timeout, message):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.5)
    raise RuntimeError(message)


def read_client(client_id):
    conn = sqlite3.connect(DB, timeout=10)
    try:
        row = conn.execute(
            "SELECT id,client_uuid,used_bytes,quota_bytes,enabled FROM clients WHERE id=?",
            (client_id,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        raise RuntimeError("Smoke-test client disappeared from SQLite")
    return row


def port_ready(port):
    import socket
    sock = socket.socket()
    try:
        return sock.connect_ex(("127.0.0.1", port)) == 0
    finally:
        sock.close()


def main():
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
    with opener.open(BASE + "/login", timeout=5) as response:
        page = response.read().decode("utf-8")
    match = re.search(r'name="csrf_token" value="([^"]+)"', page)
    if not match:
        raise RuntimeError("Could not obtain login CSRF token")
    form = urllib.parse.urlencode({
        "username": "admin",
        "password": "admin",
        "csrf_token": match.group(1),
    }).encode()
    request = urllib.request.Request(BASE + "/login", data=form, method="POST")
    with opener.open(request, timeout=8) as response:
        if response.status != 200:
            raise RuntimeError("Administrator login failed")
    with opener.open(BASE + "/api/overview", timeout=5) as response:
        csrf = json.loads(response.read())["csrf"]
    payload = json.dumps({"name": "CI transport smoke", "quota_gb": 1}).encode()
    request = urllib.request.Request(
        BASE + "/api/clients",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
    )
    with opener.open(request, timeout=10) as response:
        created = json.loads(response.read())
    client_id = created["id"]
    row = read_client(client_id)
    client_uuid = row[1]

    server = ThreadingHTTPServer(("127.0.0.1", 9000), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    profiles = [
        ("ws", "/ws", None, 11081),
        ("httpupgrade", "/httpupgrade", None, 11082),
        ("xhttp", "/xhttp", "auto", 11083),
        ("xhttp", "/xhttp-packet", "packet-up", 11084),
    ]
    errors = []
    try:
        for network, path, mode, socks_port in profiles:
            setting_key = {"ws": "wsSettings", "httpupgrade": "httpupgradeSettings", "xhttp": "xhttpSettings"}[network]
            transport_settings = {"path": path}
            if mode:
                transport_settings["mode"] = mode
            config = {
                "log": {"loglevel": "warning"},
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": socks_port,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": False},
                }],
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {"vnext": [{
                        "address": "127.0.0.1",
                        "port": 8080,
                        "users": [{"id": client_uuid, "encryption": "none"}],
                    }]},
                    "streamSettings": {
                        "network": network,
                        "security": "none",
                        setting_key: transport_settings,
                    },
                }],
            }
            config_path = Path("/tmp") / ("abyss-client-" + str(socks_port) + ".json")
            stderr_path = Path("/tmp") / ("abyss-client-" + str(socks_port) + ".stderr")
            config_path.write_text(json.dumps(config), encoding="utf-8")
            stderr_file = stderr_path.open("wb")
            proc = subprocess.Popen([XRAY, "run", "-config", str(config_path)],
                                    stdout=subprocess.DEVNULL, stderr=stderr_file)
            try:
                wait_until(
                    lambda: proc.poll() is not None or port_ready(socks_port),
                    5,
                    f"{network} {mode or ''} client did not start",
                )
                result = subprocess.run([
                    "curl", "--noproxy", "", "--silent", "--show-error", "--max-time", "12",
                    "--socks5-hostname", f"127.0.0.1:{socks_port}", "http://127.0.0.1:9000/check",
                ], capture_output=True, timeout=15)
                if result.returncode or result.stdout != MARKER:
                    stderr_file.flush()
                    detail = stderr_path.read_text(errors="replace")[-1500:]
                    raise RuntimeError(
                        f"Real VLESS {network} {mode or ''} tunnel failed "
                        f"(curl={result.returncode}, body={result.stdout!r}, stderr={detail})"
                    )
                print(f"PASS real VLESS tunnel: {network} {mode or 'default'}")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
                stderr_file.close()
                config_path.unlink(missing_ok=True)
        wait_until(
            lambda: read_client(client_id)[2] > 0,
            18,
            "Real tunnel traffic was not recorded in the client quota counter",
        )
        used = read_client(client_id)[2]
        print(f"PASS real traffic accounting: {used} bytes recorded")
        conn = sqlite3.connect(DB, timeout=10)
        try:
            conn.execute("UPDATE clients SET quota_bytes=1 WHERE id=?", (client_id,))
            conn.commit()
        finally:
            conn.close()
        wait_until(
            lambda: read_client(client_id)[4] == 0,
            18,
            "Client was not automatically disabled after its used traffic exceeded quota",
        )
        print("PASS real quota enforcement: exhausted client disabled")

        # Kill only the server-side Xray process and verify the app's watchdog
        # brings it back. Client Xray processes have already been terminated.
        killed = False
        for cmdline in Path("/proc").glob("[0-9]*/cmdline"):
            try:
                pid = int(cmdline.parent.name)
                args = cmdline.read_bytes().replace(b"\\0", b" ").decode(errors="ignore")
                if XRAY in args and "run" in args and "/data/xray.json" in args:
                    os.kill(pid, 15)
                    killed = True
                    break
            except (OSError, ValueError, ProcessLookupError):
                continue
        if not killed:
            raise RuntimeError("Could not locate the server-side Xray process for recovery test")

        def xray_healthy():
            try:
                with urllib.request.urlopen(BASE + "/health", timeout=2) as response:
                    return json.loads(response.read()).get("xray") == "running"
            except Exception:
                return False
        wait_until(xray_healthy, 22, "Xray watchdog did not recover the stopped process")
        print("PASS Xray watchdog recovery after process termination")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
