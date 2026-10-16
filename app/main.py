from __future__ import annotations
import asyncio, base64, hashlib, hmac, io, json, logging, os, secrets, shutil, sqlite3, subprocess, time, uuid
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone, timedelta
from html import escape as html_escape
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit
import qrcode
from qrcode.image.svg import SvgPathImage
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from itsdangerous import BadSignature
from starlette.datastructures import MutableHeaders
from starlette.middleware.sessions import SessionMiddleware

APP_NAME="Void"
PROFILES=[
    {"key":"ws","label":"WebSocket","network":"ws","path":"/ws","port":10001,"mode":None},
    {"key":"httpupgrade","label":"HTTPUpgrade","network":"httpupgrade","path":"/httpupgrade","port":10002,"mode":None},
    {"key":"xhttp_auto","label":"XHTTP · auto","network":"xhttp","path":"/xhttp","port":10003,"mode":"auto"},
    {"key":"xhttp_packet_up","label":"XHTTP · packet-up","network":"xhttp","path":"/xhttp-packet","port":10004,"mode":"packet-up"},
    {"key":"xhttp_stream_up","label":"XHTTP · stream-up · آزمایشی","network":"xhttp","path":"/xhttp-stream-up","port":10005,"mode":"stream-up","experimental":True},
    {"key":"xhttp_stream_one","label":"XHTTP · stream-one · آزمایشی","protocol":"vless","network":"xhttp","path":"/xhttp-stream-one","port":10006,"mode":"stream-one","experimental":True},
    {"key":"trojan_ws","label":"Trojan · WebSocket TLS","protocol":"trojan","network":"ws","path":"/trojan-ws","port":10007,"mode":None},
    {"key":"vmess_ws","label":"VMess · WebSocket TLS","protocol":"vmess","network":"ws","path":"/vmess-ws","port":10008,"mode":None},
    {"key":"ws_alt","label":"WebSocket · مسیر جایگزین","network":"ws","path":"/connect","port":10010,"mode":None,"subscription_label":"vless-ws-alt"},
    {"key":"httpupgrade_alt","label":"HTTPUpgrade · مسیر جایگزین","network":"httpupgrade","path":"/upgrade","port":10011,"mode":None,"subscription_label":"vless-httpupgrade-alt"},
    {"key":"xhttp_stream_up_alt","label":"XHTTP · stream-up · مسیر جایگزین · آزمایشی","network":"xhttp","path":"/xhttp-stream-up-alt","port":10012,"mode":"stream-up","experimental":True,"subscription_label":"xhttp-stream-up-alt"},
    {"key":"xhttp_stream_one_alt","label":"XHTTP · stream-one · مسیر جایگزین · آزمایشی","network":"xhttp","path":"/xhttp-stream-one-alt","port":10013,"mode":"stream-one","experimental":True,"subscription_label":"xhttp-stream-one-alt"},
    {"key":"ss_ws","label":"Shadowsocks 2022 · WebSocket TLS","protocol":"shadowsocks","network":"ws","path":"/ss-ws","port":10009,"mode":None},
]
DATA_DIR=Path(os.getenv("DATA_DIR","/data")); DATA_DIR.mkdir(parents=True,exist_ok=True)
DB_PATH=DATA_DIR/"panel.sqlite3"; XRAY_CONFIG=DATA_DIR/"xray.json"
XRAY_BIN=os.getenv("XRAY_BIN","/usr/local/bin/xray"); PUBLIC_DOMAIN=os.getenv("RAILWAY_PUBLIC_DOMAIN","").strip()
BASE_URL=os.getenv("BASE_URL","").strip().rstrip("/")
LOG=logging.getLogger("void"); logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO").upper())
xray_proc=None; xray_lock=asyncio.Lock(); restore_lock=asyncio.Lock()

def utc_now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
@contextmanager
def db():
    """Open one short-lived SQLite unit of work and always close its connection."""
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(DB_PATH,timeout=30,isolation_level="DEFERRED")
    c.row_factory=sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=30000")
    try:
        yield c
        c.commit()
    except BaseException:
        c.rollback()
        raise
    finally:
        c.close()
def password_hash(password,salt=None):
    salt=salt or secrets.token_bytes(16); digest=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32)
    return f"scrypt${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"
def verify_password(password,encoded):
    try:
        scheme,salt,expected=encoded.split("$",2)
        if scheme!="scrypt": return False
        actual=password_hash(password,base64.urlsafe_b64decode(salt)).split("$",2)[2]
        return hmac.compare_digest(actual,expected)
    except (ValueError,TypeError): return False
def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY CHECK(id=1),password_hash TEXT NOT NULL,password_changed_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS panel_admins(id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('owner','admin','viewer')),enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,password_changed_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY,name TEXT NOT NULL,client_uuid TEXT NOT NULL UNIQUE,sub_token TEXT NOT NULL UNIQUE,enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,note TEXT NOT NULL DEFAULT '',expires_at TEXT,quota_bytes INTEGER,used_bytes INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS resellers(id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,quota_bytes INTEGER NOT NULL CHECK(quota_bytes>0),enabled INTEGER NOT NULL DEFAULT 1,parent_id TEXT,created_at TEXT NOT NULL,FOREIGN KEY(parent_id) REFERENCES resellers(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,level TEXT NOT NULL,message TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS profile_feedback(id INTEGER PRIMARY KEY AUTOINCREMENT,client_id TEXT NOT NULL,carrier TEXT NOT NULL,profile_key TEXT NOT NULL,result TEXT NOT NULL CHECK(result IN ('ok','fail')),created_at TEXT NOT NULL,user_agent TEXT NOT NULL DEFAULT '',UNIQUE(client_id,carrier,profile_key));
        CREATE INDEX IF NOT EXISTS idx_profile_feedback_carrier ON profile_feedback(carrier,profile_key,created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_clients_created ON clients(created_at DESC);
        """)
        if not c.execute("SELECT id FROM admins WHERE id=1").fetchone():
            # First login intentionally uses admin/admin as requested. Change it immediately after setup.
            # Never print credentials to logs; the bootstrap file is restricted to the owner.
            pw=os.getenv("ABYSS_INITIAL_ADMIN_PASSWORD","admin").strip() or "admin"
            changed=utc_now()
            c.execute("INSERT INTO admins VALUES(1,?,?)",(password_hash(pw),changed))
            p=DATA_DIR/"INITIAL_ADMIN_PASSWORD.txt"; p.write_text(f"Username: admin\nPassword: {pw}\n",encoding="utf-8")
            try: p.chmod(0o600)
            except OSError: pass
            LOG.warning("Initial administrator credential saved to %s; change it after signing in",p)
        # Migrate the existing single-admin credential without changing its password.
        legacy=c.execute("SELECT password_hash,password_changed_at FROM admins WHERE id=1").fetchone()
        if legacy and not c.execute("SELECT id FROM panel_admins WHERE username='admin'").fetchone():
            c.execute("INSERT INTO panel_admins(id,username,password_hash,role,enabled,created_at,password_changed_at) VALUES(?,?,?,?,1,?,?)",
                ("owner-admin","admin",legacy["password_hash"],"owner",legacy["password_changed_at"],legacy["password_changed_at"]))
        # The bootstrap file is only a first-login record. Do not reset the password
        # from it on restart: the administrator may already have changed credentials.
        initial_file=DATA_DIR/"INITIAL_ADMIN_PASSWORD.txt"
        if initial_file.exists():
            try: initial_file.chmod(0o600)
            except OSError: pass
        # Safe in-place migration for persistent databases created by older releases.
        cols={row["name"] for row in c.execute("PRAGMA table_info(clients)")}
        for name, declaration in (("expires_at","TEXT"),("quota_bytes","INTEGER"),("used_bytes","INTEGER NOT NULL DEFAULT 0"),("profile_keys","TEXT")):
            if name not in cols: c.execute(f"ALTER TABLE clients ADD COLUMN {name} {declaration}")
        if "owner_id" not in cols: c.execute("ALTER TABLE clients ADD COLUMN owner_id TEXT")
        c.execute("CREATE INDEX IF NOT EXISTS idx_clients_owner ON clients(owner_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_resellers_parent ON resellers(parent_id)")
        c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('created_at',?)",(utc_now(),))
def event(level,message):
    LOG.log(getattr(logging,level.upper(),logging.INFO),message)
    try:
        with db() as c:
            c.execute("INSERT INTO events(at,level,message) VALUES(?,?,?)",(utc_now(),level.upper(),message[:500]))
            c.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 250)")
    except Exception: LOG.exception("event storage failed")
def get_clients(include_client_uuid=False, owner_id=None, scoped=False):
    cols="id,name,client_uuid,enabled,created_at,note,expires_at,quota_bytes,used_bytes,owner_id,profile_keys" if include_client_uuid else "id,name,enabled,created_at,note,expires_at,quota_bytes,used_bytes,owner_id,profile_keys"
    with db() as c:
        if scoped: return [dict(r) for r in c.execute(f"SELECT {cols} FROM clients WHERE owner_id=? ORDER BY created_at DESC",(owner_id,))]  # nosec B608: cols is a fixed allowlisted projection
        return [dict(r) for r in c.execute(f"SELECT {cols} FROM clients ORDER BY created_at DESC")]  # nosec B608: cols is a fixed allowlisted projection
def get_profile_flags():
    with db() as c:
        saved={row["key"]:row["value"] for row in c.execute("SELECT key,value FROM settings WHERE key LIKE 'profile:%'")}
    return {p["key"]:saved.get("profile:"+p["key"],"0" if p.get("experimental") else "1")=="1" for p in PROFILES}

def get_ss2022_server_password():
    with db() as c:
        row=c.execute("SELECT value FROM settings WHERE key='ss2022_server_password'").fetchone()
        if row: return row["value"]
        generated=base64.b64encode(secrets.token_bytes(16)).decode()
        c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('ss2022_server_password',?)",(generated,))
        return c.execute("SELECT value FROM settings WHERE key='ss2022_server_password'").fetchone()["value"]

def client_is_expired(expires_at):
    if not expires_at:
        return False
    try:
        value=str(expires_at).replace("Z","+00:00")
        expiry=datetime.fromisoformat(value)
        if expiry.tzinfo is None:
            expiry=expiry.replace(tzinfo=timezone.utc)
        return expiry <= datetime.now(timezone.utc)
    except (TypeError,ValueError):
        # Fail closed on corrupt expiry metadata.
        return True

def client_is_active(client):
    if not client.get("enabled"):
        return False
    if client_is_expired(client.get("expires_at")):
        return False
    quota=client.get("quota_bytes")
    return quota is None or int(client.get("used_bytes") or 0) < int(quota)

def valid_name(name:Any):
    if not isinstance(name,str): raise HTTPException(422,"Client name must be text")
    name=" ".join(name.strip().split())
    if not name or len(name)>64 or any(ord(x)<32 for x in name): raise HTTPException(422,"Client name must be 1–64 printable characters")
    return name
def make_xray_config():
    all_clients=[x for x in get_clients(True) if client_is_active(x)]
    ins=[{"tag":"api","listen":"127.0.0.1","port":10085,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":10085,"network":"tcp"}}]
    flags=get_profile_flags()
    for profile in PROFILES:
        if not flags[profile["key"]]: continue
        port,network,path=profile["port"],profile["network"],profile["path"]
        profile_clients=[]
        for client in all_clients:
            try: selected=json.loads(client.get("profile_keys") or "null")
            except (TypeError,ValueError): selected=None
            if selected is None or profile["key"] in selected:
                profile_clients.append({"id":client["client_uuid"],"email":f"client-{client['id']}"})
        clients=profile_clients
        stream={"network":network,"security":"none"}
        stream[{"ws":"wsSettings","httpupgrade":"httpupgradeSettings","xhttp":"xhttpSettings"}[network]]={"path":path,**({"mode":profile["mode"]} if profile["mode"] else {})}
        protocol=profile.get("protocol","vless")
        if protocol=="vless":
            settings={"clients":clients,"decryption":"none"}
        elif protocol=="trojan":
            settings={"clients":[{"password":x["id"],"email":x["email"]} for x in clients]}
        elif protocol=="vmess":
            settings={"clients":[{"id":x["id"],"alterId":0,"email":x["email"]} for x in clients]}
        elif protocol=="shadowsocks":
            ss_clients=[{"password":base64.b64encode(hashlib.sha256(x["id"].encode()).digest()[:16]).decode(),"email":x["email"]} for x in clients]
            settings={"method":"2022-blake3-aes-128-gcm","password":get_ss2022_server_password(),"network":"tcp","clients":ss_clients}
        else:
            raise ValueError("Unsupported profile protocol: "+protocol)
        inbound={"tag":f"in-{profile['key']}","listen":"127.0.0.1","port":port,"protocol":protocol,"settings":settings,"streamSettings":stream}
        ins.append(inbound)
    return {"log":{"loglevel":"debug" if os.getenv("ABYSS_TEST_MODE")=="1" else "warning"},"api":{"tag":"api","services":["StatsService"]},"stats":{},"policy":{"levels":{"0":{"statsUserUplink":True,"statsUserDownlink":True}}},"inbounds":ins,"outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"},{"protocol":"freedom","tag":"api"}],"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]}}
def validate_and_write_xray():
    tmp=XRAY_CONFIG.with_suffix(".tmp"); tmp.write_text(json.dumps(make_xray_config(),indent=2),encoding="utf-8"); tmp.replace(XRAY_CONFIG)
    if Path(XRAY_BIN).exists():
        r=subprocess.run([XRAY_BIN,"run","-test","-config",str(XRAY_CONFIG)],capture_output=True,text=True,timeout=15)
        if r.returncode: raise RuntimeError("Xray configuration test failed: "+(r.stderr or r.stdout)[-1000:])
async def start_xray():
    global xray_proc
    async with xray_lock:
        validate_and_write_xray()
        if not Path(XRAY_BIN).exists(): event("WARNING","Xray is not installed; control dashboard remains available."); return
        if xray_proc and xray_proc.poll() is None:
            # Flush counters before every Xray restart so client create/pause/edit
            # operations do not silently discard traffic accumulated since the last poll.
            try: apply_xray_stats(read_xray_stats())
            except Exception as e: event("WARNING",f"Could not flush Xray usage before restart: {e}")
            xray_proc.terminate()
            try: xray_proc.wait(timeout=4)
            except subprocess.TimeoutExpired: xray_proc.kill()
        err=open(DATA_DIR/"xray-stderr.log","ab")
        try: xray_proc=subprocess.Popen([XRAY_BIN,"run","-config",str(XRAY_CONFIG)],stdout=err,stderr=err)
        finally: err.close()
        await asyncio.sleep(.25)
        if xray_proc.poll() is not None: raise RuntimeError("Xray exited; inspect /data/xray-stderr.log")
def read_xray_stats():
    if not Path(XRAY_BIN).exists(): return {}
    result=subprocess.run([XRAY_BIN,"api","statsquery","--server=127.0.0.1:10085","--pattern","user>>>client-","--reset"],capture_output=True,text=True,timeout=8)
    if result.returncode: raise RuntimeError((result.stderr or result.stdout)[-500:])
    try: payload=json.loads(result.stdout)
    except json.JSONDecodeError: raise RuntimeError("Xray stats API returned invalid JSON")
    stats={}
    for item in payload.get("stat",payload.get("stats",[])):
        name=str(item.get("name","")); value=int(item.get("value",0))
        # user>>>client-<client UUID>>>traffic>>>uplink/downlink
        bits=name.split(">>>")
        if len(bits)>=4 and bits[0]=="user" and bits[1].startswith("client-") and bits[2]=="traffic":
            cid=bits[1].removeprefix("client-")
            stats.setdefault(cid,0); stats[cid]+=max(0,value)
    return stats

def apply_xray_stats(stats):
    if not stats: return
    with db() as c:
        for key,delta in stats.items():
            if delta<=0: continue
            # Accept legacy 8-character emails during a rolling upgrade, but
            # use the full UUID for new Xray stats to avoid prefix collisions.
            if len(key)==8:
                c.execute("UPDATE clients SET used_bytes=used_bytes+? WHERE substr(id,1,8)=?",(int(delta),key))
            else:
                c.execute("UPDATE clients SET used_bytes=used_bytes+? WHERE id=?",(int(delta),key))

async def enforce_client_limits():
    # Expiry and already-recorded quota enforcement must continue even while
    # Xray is down; only the live counter query depends on a running process.
    if Path(XRAY_BIN).exists() and xray_proc and xray_proc.poll() is None:
        stats=read_xray_stats()
        apply_xray_stats(stats)
    auto_disabled=[]
    with db() as c:
        rows=[dict(x) for x in c.execute("SELECT id,name,enabled,expires_at,quota_bytes,used_bytes FROM clients")]
        for row in rows:
            if not row["enabled"]: continue
            expired=client_is_expired(row["expires_at"])
            exhausted=bool(row["quota_bytes"] is not None and int(row["used_bytes"] or 0)>=int(row["quota_bytes"]))
            if expired or exhausted:
                c.execute("UPDATE clients SET enabled=0 WHERE id=?",(row["id"],))
                auto_disabled.append((row["name"],"expired" if expired else "quota reached"))
    # Log after closing the database transaction to avoid nested SQLite writers.
    for name,reason in auto_disabled:
        event("INFO",f"Client {name!r} automatically disabled: {reason}.")
    # Apply any auto-disabled clients to Xray once, but do not prevent the DB
    # enforcement from completing if the engine is currently unavailable.
    if auto_disabled and Path(XRAY_BIN).exists():
        try:
            await start_xray()
        except Exception as e:
            event("ERROR",f"Could not apply automatically disabled clients to Xray: {e}")

async def monitor():
    while True:
        await asyncio.sleep(10)
        if Path(XRAY_BIN).exists() and (xray_proc is None or xray_proc.poll() is not None):
            try: event("WARNING","Restarting stopped Xray process."); await start_xray()
            except Exception as e: event("ERROR",f"Xray recovery failed: {e}")
        try: await enforce_client_limits()
        except Exception as e: event("ERROR",f"Client usage/expiry monitor failed: {e}")
@asynccontextmanager
async def lifespan(app):
    init_db()
    try: await start_xray()
    except Exception as e: event("ERROR",f"Xray startup failed: {e}")
    task=asyncio.create_task(monitor()); yield; task.cancel()
    if xray_proc and xray_proc.poll() is None: xray_proc.terminate()
app=FastAPI(title=APP_NAME,docs_url=None,redoc_url=None,openapi_url=None,lifespan=lifespan)

class RememberMeSessionMiddleware(SessionMiddleware):
    """Use a session cookie by default; remember-me sessions expire after 30 days."""

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await super().__call__(scope, receive, send)
            return

        initial_session_was_empty = True
        raw_cookie = Request(scope).cookies.get(self.session_cookie)
        if raw_cookie:
            try:
                signed = raw_cookie.encode("utf-8")
                unpacked = self.signer.unsign(signed)
                candidate = json.loads(base64.b64decode(unpacked))
                max_age = 30 * 24 * 60 * 60 if isinstance(candidate, dict) and candidate.get("remember_me") is True else 8 * 60 * 60
                verified = self.signer.unsign(signed, max_age=max_age)
                decoded = json.loads(base64.b64decode(verified))
                scope["session"] = decoded if isinstance(decoded, dict) else {}
                initial_session_was_empty = False
            except (BadSignature, ValueError, TypeError, UnicodeDecodeError):
                scope["session"] = {}
        else:
            scope["session"] = {}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                if scope["session"]:
                    data = base64.b64encode(json.dumps(scope["session"]).encode("utf-8"))
                    data = self.signer.sign(data)
                    max_age = "Max-Age=2592000; " if scope["session"].get("remember_me") is True else ""
                    header_value = f"{self.session_cookie}={data.decode('utf-8')}; path={self.path}; {max_age}{self.security_flags}"
                    headers = MutableHeaders(scope=message)
                    headers.append("Set-Cookie", header_value)
                elif not initial_session_was_empty:
                    header_value = f"{self.session_cookie}=null; path={self.path}; expires=Thu, 01 Jan 1970 00:00:00 GMT; {self.security_flags}"
                    headers = MutableHeaders(scope=message)
                    headers.append("Set-Cookie", header_value)
            await send(message)

        await self.app(scope, receive, send_wrapper)

sf=DATA_DIR/".session_secret"
if not sf.exists():
    sf.write_text(secrets.token_urlsafe(48),encoding="ascii")
    try: sf.chmod(0o600)
    except OSError: pass
app.add_middleware(RememberMeSessionMiddleware,secret_key=sf.read_text().strip(),session_cookie="abyss_session",max_age=28800,same_site="strict",https_only=os.getenv("COOKIE_SECURE","1")!="0")
@app.middleware("http")
async def headers(request,call_next):
    r=await call_next(request); r.headers["X-Content-Type-Options"]="nosniff"; r.headers["X-Frame-Options"]="DENY"; r.headers["Referrer-Policy"]="no-referrer"; return r
def require_admin(r):
    if r.session.get("admin") is True:
        admin_id=r.session.get("admin_id","owner-admin")
        with db() as c:
            account=c.execute("SELECT role,enabled,password_changed_at FROM panel_admins WHERE id=?",(admin_id,)).fetchone()
        if not account or not account["enabled"]:
            r.session.clear()
            raise HTTPException(401,"Administrator account is disabled or no longer exists")
        if r.session.get("admin_password_changed_at") != account["password_changed_at"]:
            r.session.clear()
            raise HTTPException(401,"Administrator password changed; please sign in again")
        r.session["admin_role"]=account["role"]
        return
    rid=r.session.get("reseller_id")
    if not rid: raise HTTPException(401,"Authentication required")
    with db() as c:
        current=c.execute("SELECT id,enabled,parent_id FROM resellers WHERE id=?",(rid,)).fetchone()
        if not current or not current["enabled"]:
            r.session.clear()
            raise HTTPException(401,"Reseller account is disabled")
        parent_id=current["parent_id"]
        while parent_id:
            parent=c.execute("SELECT id,enabled,parent_id FROM resellers WHERE id=?",(parent_id,)).fetchone()
            if not parent or not parent["enabled"]:
                r.session.clear()
                raise HTTPException(401,"Parent reseller account is disabled")
            parent_id=parent["parent_id"]
def require_role(r,*roles):
    require_admin(r)
    role=r.session.get("admin_role","owner") if r.session.get("admin") is True else "reseller"
    if role not in roles: raise HTTPException(403,"Insufficient permissions")
def is_root(r): return r.session.get("admin") is True and r.session.get("admin_role","owner")=="owner"
def owner_id_for(r):
    if r.session.get("admin") is True: return None
    return str(r.session.get("reseller_id",""))
def require_root(r):
    require_role(r,"owner")
def require_client_access(r,cid):
    if is_root(r): return
    with db() as c: row=c.execute("SELECT owner_id FROM clients WHERE id=?",(cid,)).fetchone()
    if not row or row["owner_id"] != owner_id_for(r): raise HTTPException(404,"Client not found")
def reseller_allocated(c,rid):
    a=c.execute("SELECT COALESCE(SUM(quota_bytes),0) n FROM clients WHERE owner_id=?",(rid,)).fetchone()["n"]
    b=c.execute("SELECT COALESCE(SUM(quota_bytes),0) n FROM resellers WHERE parent_id=?",(rid,)).fetchone()["n"]
    return int(a or 0)+int(b or 0)
def reseller_remaining(rid):
    with db() as c:
        row=c.execute("SELECT quota_bytes,enabled FROM resellers WHERE id=?",(rid,)).fetchone()
        if not row or not row["enabled"]: raise HTTPException(403,"Reseller account is disabled")
        return int(row["quota_bytes"])-reseller_allocated(c,rid)
def reseller_allocated_for(rid):
    with db() as c:
        return reseller_allocated(c,rid)
def assert_reseller_chain_enabled(c,rid):
    current_id=rid
    seen=set()
    while current_id:
        if current_id in seen:
            raise HTTPException(403,"Invalid reseller hierarchy")
        seen.add(current_id)
        row=c.execute("SELECT enabled,parent_id FROM resellers WHERE id=?",(current_id,)).fetchone()
        if not row or not row["enabled"]:
            raise HTTPException(403,"Reseller account or parent is disabled")
        current_id=row["parent_id"]
def require_csrf(r,allow_viewer=False):
    require_admin(r)
    if not allow_viewer and r.session.get("admin") is True and r.session.get("admin_role")=="viewer":
        raise HTTPException(403,"Read-only viewer account")
    a=r.session.get("csrf",""); b=r.headers.get("x-csrf-token","")
    if not a or not b or not hmac.compare_digest(str(a),b): raise HTTPException(403,"Invalid CSRF token")
def rate_check(r,key,limit=8,window=300):
    now=int(time.time())
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        k="rate:"+key; row=c.execute("SELECT value FROM settings WHERE key=?",(k,)).fetchone()
        if not row: c.execute("INSERT INTO settings VALUES(?,?)",(k,f"{now}:1")); return True
        try: start,count=map(int,row["value"].split(":",1))
        except Exception: start,count=now,limit
        if now-start>=window: c.execute("UPDATE settings SET value=? WHERE key=?",(f"{now}:1",k)); return True
        if count>=limit: return False
        c.execute("UPDATE settings SET value=? WHERE key=?",(f"{start}:{count+1}",k)); return True

LOGIN='''<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="dark"><title>Abyss Tunnel · ورود</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;min-height:100dvh;display:grid;place-items:center;padding:18px;background:radial-gradient(ellipse at 50% 0,#163a43 0,transparent 52%),#080b12;color:#edf2ff;font:15px system-ui,-apple-system,sans-serif}.card{width:min(420px,100%);padding:clamp(22px,6vw,34px);border:1px solid #263b49;border-radius:22px;background:rgba(16,22,34,.96);box-shadow:0 24px 90px #0006}h1{margin:12px 0 8px;font-size:clamp(26px,7vw,34px)}p{line-height:1.9}.mint{color:#8de8d6;letter-spacing:.13em;font-size:11px;font-weight:800}.muted{color:#91a3b4}label{display:block;margin:16px 0 7px;font-size:13px}input{width:100%;min-width:0;padding:13px;border-radius:10px;border:1px solid #2a3548;background:#090e17;color:white;font:inherit}input:focus{outline:2px solid #76e4d1;outline-offset:1px}button{width:100%;padding:13px;margin-top:16px;background:#8de8d6;color:#061412;border:0;border-radius:10px;font:inherit;font-weight:800;cursor:pointer}.err{color:#ff9f9f;font-size:12px;overflow-wrap:anywhere}.symbol{display:grid;place-items:center;width:44px;height:44px;border:1px solid #2c5958;border-radius:13px;background:#102b30;color:#8de8d6;font-size:23px;margin-top:24px}.app-shell{display:grid;grid-template-columns:250px minmax(0,1fr);min-height:100dvh;max-width:1700px;margin:0 auto;background:#080b12}
.sidebar{position:sticky;top:0;height:100dvh;align-self:start;padding:22px 14px;border-left:1px solid #202d3b;background:linear-gradient(180deg,#0d141e,#090d14);z-index:25}
.side-brand{padding:9px 10px 23px;color:#8de8d6;font-size:13px;font-weight:850;letter-spacing:.12em}
.side-caption{padding:12px 10px 7px;color:#687d91;font-size:10px;letter-spacing:.12em}
.side-nav{display:grid;gap:6px}.nav-item{width:100%;text-align:right;display:flex;align-items:center;gap:11px;padding:12px;border:1px solid transparent;border-radius:11px;background:transparent;color:#9eafc0}
.nav-item:hover,.nav-item.active{background:#12242b;border-color:#24474a;color:#8de8d6}.nav-icon{width:25px;text-align:center;font-size:16px}
.workspace{min-width:0;width:100%;max-width:1400px;margin:0 auto;padding:20px clamp(12px,2vw,28px) 38px}
#menuToggle{display:none}.nav-hidden{display:none!important}.section-heading{margin-top:7px;font-size:20px;font-weight:800;color:#eaf5f7}
.top{padding:8px 0 15px;border-bottom:1px solid #1e2a38}.stats{margin-top:18px}
@media(max-width:850px){.app-shell{display:block}.sidebar{position:fixed;top:0;right:0;bottom:0;width:min(290px,84vw);height:100dvh;transform:translateX(105%);transition:transform .2s ease;box-shadow:none;border-left:1px solid #263748}.sidebar.open{transform:translateX(0);box-shadow:0 0 0 9999px #02050bc7}#menuToggle{display:inline-flex;position:sticky;top:8px;z-index:28;margin:8px 8px 0 auto;padding:10px 13px;background:#10252b;border-color:#2a5555;color:#8de8d6}.workspace{padding-top:8px}}
@media(prefers-reduced-motion:reduce){.sidebar{transition:none}}
</style><style id="abyss-premium-upgrade">
:root{color-scheme:dark;--abyss-bg:#070a10;--abyss-panel:#101722;--abyss-line:#263748;--abyss-mint:#8de8d6;--abyss-text:#edf3fb;--abyss-muted:#9aabbd}
html{scroll-behavior:smooth}body{background-color:var(--abyss-bg)}body:before{content:"";position:fixed;inset:0;pointer-events:none;z-index:-1;background:radial-gradient(ellipse at 80% -10%,rgba(43,130,125,.16),transparent 42%),radial-gradient(ellipse at 0% 40%,rgba(37,66,107,.13),transparent 42%)}
.card,.panel,.box,.section,.stat,.metric,.client-card{border-color:var(--abyss-line)!important;box-shadow:0 12px 36px rgba(0,0,0,.14);transition:border-color .18s ease,transform .18s ease,box-shadow .18s ease}
button,.btn,a.button{transition:filter .15s ease,transform .15s ease,box-shadow .15s ease}button:hover,.btn:hover,a.button:hover{filter:brightness(1.08);transform:translateY(-1px)}
button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--abyss-mint);outline-offset:3px}
input,select,textarea{max-width:100%;min-width:0}table{display:block;max-width:100%;overflow-x:auto;border-collapse:collapse}main,.container,.wrap{min-width:0}
@media(max-width:600px){body{font-size:14px}main,.container,.wrap{padding-left:12px!important;padding-right:12px!important}.card,.panel,.box{border-radius:15px!important}.row{flex-wrap:wrap}.row>*{max-width:100%}button,.btn{min-height:42px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style><style id="abyss-login-premium">body{overflow:hidden;background:radial-gradient(ellipse at 15% 20%,rgba(38,107,112,.23),transparent 38%),radial-gradient(ellipse at 85% 85%,rgba(42,61,100,.22),transparent 40%),#070a10}.card{position:relative;overflow:hidden;border-color:#2b4653;background:linear-gradient(155deg,rgba(17,27,41,.98),rgba(9,14,23,.98));box-shadow:0 32px 110px #0009,0 0 0 1px #8de8d60a}.card:before{content:"";position:absolute;inset:0 0 auto;height:2px;background:linear-gradient(90deg,transparent,#8de8d6,#547a9c,transparent)}.mint{font-size:10px;letter-spacing:.19em}.symbol{width:54px;height:54px;margin-top:26px;border-radius:17px;border-color:#396b6a;background:linear-gradient(145deg,#163b3d,#0d1c27);box-shadow:0 10px 35px #0005;font-size:25px}form{margin-top:20px}label{color:#b8c9d7}button{box-shadow:0 10px 26px #8de8d61b}button:hover{filter:brightness(1.06)}@media(max-width:420px){.card{border-radius:19px}.symbol{margin-top:20px}}</style></head><body><main class="card"><div class="abyss-brand-row login-brand"><span class="abyss-logo-mark" aria-hidden="true"></span><span class="brand-name">ABYSS TUNNEL<small>• I T A •</small></span></div><h1>ورود به پنل مدیریت</h1><p class="muted">برای ادامه، اطلاعات خود را وارد کنید.</p><form method="post"><input type="hidden" name="csrf_token" value="{{CSRF}}"><label for="username">نام کاربری</label><div class="login-input-wrap"><span class="login-input-icon" aria-hidden="true">♙</span><input id="username" name="username" placeholder="نام کاربری" autocomplete="username" required></div><label for="password">رمز عبور</label><div class="login-input-wrap"><span class="login-input-icon" aria-hidden="true">♧</span><input id="password" type="password" name="password" placeholder="رمز عبور" autocomplete="current-password" required><button type="button" class="login-password-toggle" aria-label="نمایش رمز عبور" aria-pressed="false" onclick="const i=document.getElementById('password');i.type=i.type==='password'?'text':'password';this.textContent=i.type==='text'?'◌':'◉';this.setAttribute('aria-pressed',i.type==='text');this.setAttribute('aria-label',i.type==='text'?'پنهان کردن رمز عبور':'نمایش رمز عبور')">◉</button></div><div class="login-extra-row"><label class="remember-option"><input type="checkbox" name="remember_me" value="on"><span>مرا به خاطر بسپار</span></label><a href="#" onclick="document.getElementById('loginHelpDialog').showModal();return false">فراموشی رمز عبور؟</a></div><p class="err">{{ERROR}}</p><button>ورود</button></form></main></body></html>'''
DASH='''<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Abyss Tunnel</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#080b12;color:#edf2ff;font:14px system-ui,-apple-system,sans-serif}.wrap{max-width:1100px;margin:auto;padding:22px 14px}.card{background:#101622;border:1px solid #222d40;border-radius:14px;padding:17px;margin:14px 0}.top,.row,.client{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.mint{color:#76e4d1;font-size:11px;letter-spacing:.12em}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.num{font-size:26px;font-weight:750}.fields{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:14px}input,button{font:inherit;border-radius:8px;padding:10px}input{min-width:0;width:100%;background:#090e17;color:white;border:1px solid #2a3548}button{cursor:pointer;background:#14202b;color:white;border:1px solid #2d3b50}button.primary{background:#76e4d1;color:#07120f;font-weight:700}.tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.client{padding:14px 0;border-top:1px solid #222d40}.client-info{min-width:180px;flex:1}.actions{display:flex;gap:6px;flex-wrap:wrap}.small{font-size:11px;color:#8794ac;line-height:1.8}.section-title{font-weight:700}.hidden{display:none!important}#status{color:#76e4d1}.client-name{overflow-wrap:anywhere}dialog{width:min(720px,calc(100% - 20px));max-height:90dvh;overflow:auto;padding:20px;border:1px solid #304254;border-radius:18px;background:#101722;color:#edf2ff;box-shadow:0 25px 90px #0009}dialog::backdrop{background:#02050bd9;backdrop-filter:blur(5px)}.modal-top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:16px}.modal-top h2{font-size:18px;margin:0}.sub-layout{display:grid;grid-template-columns:minmax(0,1fr) 170px;gap:16px;align-items:start}.sub-field{margin:12px 0}.sub-field label{display:block;font-size:12px;color:#9babc0;margin-bottom:6px}.sub-field input{direction:ltr;text-align:left;font-size:12px}.sub-buttons{display:flex;flex-wrap:wrap;gap:8px}.qr-preview{width:170px;max-width:100%;background:white;border-radius:12px;padding:8px;aspect-ratio:1}.danger{border-color:#70404a;color:#ffb5bd}.profile-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-top:13px}.profile-setting{display:flex;align-items:center;gap:10px;padding:12px;border:1px solid #27384a;border-radius:10px;background:#0b111b;min-width:0}.profile-setting input{width:18px;height:18px;accent-color:#76e4d1;flex-shrink:0}.profile-setting span{overflow-wrap:anywhere}.button-link{display:inline-flex;align-items:center;padding:10px;border-radius:8px;border:1px solid #2d3b50;background:#14202b;color:white;text-decoration:none;font:inherit}@media(max-width:700px){.stats{grid-template-columns:1fr 1fr}.fields{grid-template-columns:1fr 1fr}.wrap{padding:14px 10px}.actions button{padding:8px;font-size:12px}}@media(max-width:560px){.sub-layout{grid-template-columns:1fr}.profile-grid{grid-template-columns:1fr}.qr-preview{width:145px;display:block;margin:8px auto 0}}@media(max-width:420px){.stats,.fields{grid-template-columns:1fr}}
</style><style id="abyss-premium-upgrade">
:root{color-scheme:dark;--abyss-bg:#070a10;--abyss-panel:#101722;--abyss-line:#263748;--abyss-mint:#8de8d6;--abyss-text:#edf3fb;--abyss-muted:#9aabbd}
html{scroll-behavior:smooth}body{background-color:var(--abyss-bg)}body:before{content:"";position:fixed;inset:0;pointer-events:none;z-index:-1;background:radial-gradient(ellipse at 80% -10%,rgba(43,130,125,.16),transparent 42%),radial-gradient(ellipse at 0% 40%,rgba(37,66,107,.13),transparent 42%)}
.card,.panel,.box,.section,.stat,.metric,.client-card{border-color:var(--abyss-line)!important;box-shadow:0 12px 36px rgba(0,0,0,.14);transition:border-color .18s ease,transform .18s ease,box-shadow .18s ease}
button,.btn,a.button{transition:filter .15s ease,transform .15s ease,box-shadow .15s ease}button:hover,.btn:hover,a.button:hover{filter:brightness(1.08);transform:translateY(-1px)}
button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--abyss-mint);outline-offset:3px}
input,select,textarea{max-width:100%;min-width:0}table{display:block;max-width:100%;overflow-x:auto;border-collapse:collapse}main,.container,.wrap{min-width:0}
@media(max-width:600px){body{font-size:14px}main,.container,.wrap{padding-left:12px!important;padding-right:12px!important}.card,.panel,.box{border-radius:15px!important}.row{flex-wrap:wrap}.row>*{max-width:100%}button,.btn{min-height:42px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style><style id="abyss-premium-layout">.app-shell{max-width:1800px;grid-template-columns:258px minmax(0,1fr)}.sidebar{padding:26px 16px;background:linear-gradient(180deg,#0d1620,#080c13);border-left:1px solid #263849}.side-brand{font-size:14px;letter-spacing:.16em;padding:10px 12px 25px}.side-caption{font-size:10px;letter-spacing:.14em}.nav-item{font-size:13px;min-height:43px}.nav-item.active{box-shadow:inset -3px 0 #8de8d6}.workspace{max-width:1460px;padding:26px clamp(14px,2.5vw,36px) 46px}.top{align-items:center;gap:18px;padding:12px 0 20px}.top .tools{justify-content:flex-start;flex-wrap:wrap}.section-heading{font-size:23px;letter-spacing:-.02em}.stats{gap:14px}.stats>.card,.workspace>section.card{border-radius:18px;padding:21px;background:linear-gradient(145deg,#111b28,#0c121c)}.fields{grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}.field{display:grid;gap:7px;min-width:0;color:#9aafc1;font-size:12px}.field input,.field select{height:44px;padding:11px 12px;border-radius:11px;background:#080e17;border-color:#2c3d50}.field input:focus,.field select:focus{border-color:#8de8d6;box-shadow:0 0 0 3px #8de8d61c}.workspace .section-title{font-size:16px}.workspace .small{line-height:1.85}.workspace .client{padding:16px 0;border-top-color:#263647}.workspace .actions{gap:7px}.workspace button,.workspace .button-link{border-radius:10px;min-height:40px}.workspace button.primary{box-shadow:0 7px 22px #8de8d61a}.workspace #clients{display:grid;gap:9px}.workspace #clients .client{padding:14px;border:1px solid #263749;border-radius:13px;background:#0a111b}.workspace #subDialog{border-color:#304556}.workspace .stats .num{font-size:29px}.workspace [data-section-page]{scroll-margin-top:20px}#menuToggle{border-radius:12px;box-shadow:0 10px 25px #0005}.sidebar.open{box-shadow:0 0 0 9999px #02050bc7}.workspace .tools button{white-space:nowrap}@media(max-width:850px){.workspace{padding:10px 12px 30px}.top{padding-top:10px}.top .tools{gap:7px}.top .tools button{flex:1}.fields{grid-template-columns:1fr}.sidebar{z-index:60}.workspace>section.card{padding:15px}.stats>.card{padding:15px}}@media(min-width:851px){#menuToggle{display:none!important}}@media(prefers-reduced-motion:reduce){.nav-item,.workspace button{transition:none!important}}</style></head><body><main class="app-shell">
<button type="button" id="menuToggle" onclick="toggleSidebar()" aria-label="باز کردن منو">☰ منو</button>
<aside class="sidebar" id="sidebar"><div class="side-brand abyss-brand-row"><span class="abyss-logo-mark" aria-hidden="true"></span><span class="brand-name">ABYSS TUNNEL<small>• I T A •</small></span></div><div class="side-caption">مدیریت داشبورد</div><nav class="side-nav" aria-label="ناوبری داشبورد">
<button class="nav-item active" data-nav="dashboard" onclick="showSection('dashboard')"><span class="nav-icon">◫</span>نمای کلی</button>
<button class="nav-item" data-nav="clients" onclick="showSection('clients')"><span class="nav-icon">♙</span>مدیریت کاربران</button><button class="nav-item" data-nav="create" onclick="showSection('create')"><span class="nav-icon">＋</span>ساخت سرویس</button><button class="nav-item" data-nav="servers" onclick="showSection('servers')"><span class="nav-icon">▤</span>مدیریت سرورها</button><button class="nav-item" data-nav="protocols" onclick="showSection('protocols')"><span class="nav-icon">⎇</span>پروتکل‌ها</button><button class="nav-item" data-nav="reports" onclick="showSection('reports')"><span class="nav-icon">≋</span>گزارش‌ها</button>
<button class="nav-item" data-nav="reseller" onclick="showSection('reseller')"><span class="nav-icon">⌘</span>حساب‌های نمایندگی و سهمیه</button>
<button class="nav-item" data-nav="settings" onclick="showSection('settings')"><span class="nav-icon">⚙</span>تنظیمات اتصال</button>
<button class="nav-item" data-nav="diagnostics" onclick="showSection('diagnostics')"><span class="nav-icon">✧</span>عیب‌یابی هوشمند</button>
<button class="nav-item" data-nav="backup" data-owner-only onclick="showSection('backup')"><span class="nav-icon">▣</span>پشتیبان‌گیری</button>
<button class="nav-item" data-nav="metrics" onclick="showSection('metrics')"><span class="nav-icon">◌</span>پایش زنده</button>
<button class="nav-item" data-nav="admins" data-owner-only onclick="showSection('admins')"><span class="nav-icon">♙</span>مدیریت مدیران</button>
<button class="nav-item" data-nav="apikeys" data-owner-only onclick="showSection('apikeys')"><span class="nav-icon">⌘</span>API و ربات</button>
<button class="nav-item" data-nav="events" onclick="showSection('events')"><span class="nav-icon">≋</span>رویدادهای اخیر</button>
<a class="nav-item" href="/api-docs" target="_blank" rel="noopener"><span class="nav-icon">↗</span>مستندات API</a>
<a class="nav-item" href="https://github.com/bodisbos-cmd/Void" target="_blank" rel="noopener"><span class="nav-icon">⌘</span>GitHub</a>
<a class="nav-item" href="https://github.com/bodisbos-cmd/Void/stargazers" target="_blank" rel="noopener"><span class="nav-icon">☆</span>ستاره دادن</a>
</nav><div class="side-caption" style="margin-top:22px">سازنده · Abyss Tunnel</div><div class="abyss-utility-links"><a href="https://github.com/bodisbos-cmd/Void" target="_blank" rel="noopener">⌘ GitHub</a><a href="https://github.com/bodisbos-cmd/Void/stargazers" target="_blank" rel="noopener">☆ ستاره دادن</a><a href="#support-link-not-configured" onclick="if(this.getAttribute('href')==='#support-link-not-configured'){alert('لینک حمایت مالی هنوز تنظیم نشده است؛ متغیر SUPPORT_URL را در Railway تنظیم کن.');return false}">◇ حمایت از پروژه</a></div></aside>
<div class="workspace"><header class="top"><div class="abyss-brand-row"><span class="abyss-logo-mark" aria-hidden="true"></span><span class="brand-name"><b>ABYSS TUNNEL</b><small>• I T A • · داشبورد مدیریت</small></span></div><div class="mint" data-i18n="tagline">داشبورد مدیریتی خصوصی</div><div id="sectionTitle" class="section-heading">نمای کلی</div><div class="tools"><input class="top-tools-search" id="globalSearch" type="search" placeholder="جست‌وجوی کاربر…" data-i18n-placeholder="search" aria-label="جست‌وجوی کاربر" onkeydown="if(event.key==='Enter'){event.preventDefault();runGlobalSearch()}"><button type="button" class="toolbar-icon" onclick="showSection('events')" title="رویدادهای اخیر" aria-label="رویدادهای اخیر"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg></button><button type="button" class="toolbar-icon" onclick="showSection('settings')" title="تنظیمات اتصال" aria-label="تنظیمات اتصال">⚙</button><button id="langBtn" onclick="toggleLanguage()">English</button><button type="button" class="toolbar-icon" onclick="showPanelHelp()" title="راهنمای پنل" aria-label="راهنمای پنل">?</button><span class="account-badge"><span class="account-avatar" aria-hidden="true">◉</span><span class="account-copy"><b id="accountUsername">مدیر پنل</b><small id="accountRole">حساب مدیریت</small></span></span><button onclick="changePassword()" data-i18n="changePassword">تغییر رمز عبور</button><button onclick="load()" data-i18n="refresh">به‌روزرسانی</button><button onclick="location.href='/logout'" data-i18n="logout">خروج</button></div></header>
<section id="overviewStats" class="stats" data-section-page="dashboard"><div class="card"><span data-i18n="total">کل کاربران</span><div class="num" id="total">—</div></div><div class="card"><span data-i18n="active">کاربران فعال</span><div class="num" id="active">—</div></div><div class="card"><span data-i18n="xray">وضعیت Xray</span><div class="num" id="xray">—</div></div><div class="card"><span>مصرف ثبت‌شده</span><div class="num" id="dashboardTraffic">—</div><div class="small">ترافیک ثبت‌شدهٔ داشبورد</div></div></section>
<section id="dashboardUsageCard" class="card" data-section-page="dashboard"><div class="section-title">وضعیت سرویس‌ها</div><div class="small">وضعیت فرایندها و منابع همین کانتینر؛ نه پینگ واقعی اپراتور موبایل.</div><div class="stats"><div class="card"><span>CPU</span><div class="num" id="dashCpu">—</div></div><div class="card"><span>RAM</span><div class="num" id="dashRam">—</div></div><div class="card"><span>دیسک</span><div class="num" id="dashDisk">—</div></div></div><canvas id="usageSparkline" height="144" aria-label="نمودار زنده منابع"></canvas><div id="chartLegend" class="chart-legend"><span><i class="cpu"></i>CPU</span><span><i class="ram"></i>RAM</span><span><i class="net"></i>ترافیک</span></div><div id="chartNote" class="small" style="margin-top:7px">در انتظار نخستین نمونهٔ واقعی منابع…</div></section>
<section class="card" data-section-page="clients"><div class="row"><div><div class="section-title" data-i18n="clients">مدیریت کاربران <span class="help-dot" title="ساخت سرویس، مدیریت زمان و حجم و کنترل دسترسی." aria-label="راهنمای مدیریت کاربران">؟</span></div><div class="small" data-i18n="clientHelp">ساخت سرویس، کنترل دسترسی و مدیریت لینک اشتراک</div></div><div class="users-search-actions"><input id="search" placeholder="جست‌وجوی نام یا شناسه…" oninput="renderClients()" data-i18n-placeholder="search"><button class="primary" type="button" onclick="showSection('create')">افزودن کاربر +</button></div></div>
<div id="clients" style="margin-top:12px"></div></section><section class="card" id="createServiceCard" data-section-page="create"><div class="reference-page-head"><div><div class="section-title">ساخت سرویس جدید <span class="help-dot" title="برای سرویس زمان، حجم و پروفایل‌های اتصال را مشخص کن." aria-label="راهنمای ساخت سرویس">؟</span></div><div class="small">سرویس را برای کاربر بساز؛ هر تغییری در محدودیت‌ها و پروفایل‌ها به همین سرویس اعمال می‌شود.</div></div></div><div class="fields"><input id="name" maxlength="64" placeholder="نام کاربر" data-i18n-placeholder="name" title="نام نمایشی سرویس"><input id="days" type="number" min="1" max="3650" placeholder="مدت (روز، اختیاری)" data-i18n-placeholder="days" title="خالی گذاشتن یعنی بدون انقضا"><input id="quota" type="number" min="1" max="100000" placeholder="حجم (GB، اختیاری)" data-i18n-placeholder="quota" title="خالی گذاشتن یعنی بدون محدودیت حجم"><input id="note" maxlength="300" placeholder="یادداشت (اختیاری)" data-i18n-placeholder="note"></div><div class="section-title" style="margin-top:16px">پروفایل‌های قابل ارائه <span class="help-dot" title="چند پروفایل را هم‌زمان انتخاب کن. فقط پروفایل‌های فعال سراسری قابل ارائه‌اند." aria-label="راهنمای انتخاب پروفایل‌ها">؟</span></div><div id="clientProfileChoices" class="profile-grid"></div><div class="row" style="margin-top:9px"><span class="small" data-i18n="optional">خالی گذاشتن مدت و حجم یعنی نامحدود.</span><button class="primary" onclick="add()" data-i18n="create">+ ساخت کاربر</button></div></section>

<section class="card" id="serversPage" data-section-page="servers">
  <div class="reference-page-head"><div><div class="section-title">مدیریت سرورها</div><div class="small">وضعیت همین استقرار را می‌خواند؛ آدرس یا سرور فرضی نمایش داده نمی‌شود.</div></div><button type="button" onclick="loadServerStatus()">به‌روزرسانی</button></div>
  <div class="server-identity"><div><div class="small">سرور جاری · Railway</div><strong id="serverHost">در حال دریافت دامنه…</strong></div><span class="state-chip neutral" id="serverOverall">در انتظار بررسی</span></div>
  <div class="server-table-wrap"><table class="server-table"><thead><tr><th>نام سرور</th><th>آی‌پی / دامنه</th><th>Xray</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody id="serverTableBody"><tr><td colspan="5">در حال دریافت وضعیت…</td></tr></tbody></table></div>
  <div class="server-grid" id="serverStatusGrid"><article class="server-state"><div class="small">در حال خواندن وضعیت اجزای واقعی…</div></article></div>
  <div class="small" id="serverStatusNote" style="margin-top:14px;line-height:1.9">آزمون مسیر داخلی، تست واقعی اتصال از سیم‌کارت یا دستگاه مقصد نیست.</div>
</section>
<section class="card" id="protocolsPage" data-section-page="protocols">
  <div class="reference-page-head"><div><div class="section-title">پروتکل‌ها</div><div class="small">پروفایل‌های واقعی موجود در همین نسخه؛ روشن و خاموش کردن هر گزینه از تنظیمات Xray عبور می‌کند.</div></div><button type="button" onclick="loadProtocolCatalog()">به‌روزرسانی</button></div>
  <div id="protocolCatalog" class="protocol-catalog"><article class="protocol-state"><div class="small">در حال دریافت پروفایل‌ها…</div></article></div>
</section>
<section class="card" id="reportsPage" data-section-page="reports">
  <div class="reference-page-head"><div><div class="section-title">گزارش‌ها</div><div class="small">نتایج اعتبارسنجی Xray و مسیرهای داخلی، به‌همراه رویدادهای ثبت‌شدهٔ پنل.</div></div><button type="button" onclick="loadReports()">اجرای بررسی</button></div>
  <div class="report-summary" id="reportSummary">هنوز بررسی اجرا نشده است.</div>
  <div class="section-title">موارد نیازمند توجه</div><div class="report-issues" id="reportIssues"><div class="small">در انتظار بررسی…</div></div>
  <div class="section-title">وضعیت پروفایل‌های اتصال</div><div class="report-profiles" id="reportProfiles"></div>
  <div class="section-title" style="margin-top:20px">رویدادهای اخیر</div><div class="report-events" id="reportEvents"><div class="small">در انتظار رویدادها…</div></div>
  <div class="small" style="margin-top:12px;line-height:1.9">نکته: پاسخ دادن پورت و مسیر وب، اتصال واقعی کانفیگ یا پینگ کاربر را اثبات نمی‌کند؛ آن بخش باید با کلاینت و شبکهٔ مقصد بررسی شود.</div>
</section>
<section class="card" id="backupCard" data-section-page="backup"><div class="section-title">پشتیبان‌گیری و بازیابی <span class="help-dot" title="نسخهٔ پشتیبان شامل اطلاعات حساس و لینک‌های دسترسی است؛ محرمانه نگهش دار." aria-label="راهنمای پشتیبان‌گیری">؟</span></div><div class="small">فایل پشتیبان شامل اطلاعات حساس کاربران است؛ آن را محرمانه نگه دار.</div><div class="tools" style="margin-top:12px"><button class="primary" onclick="location.href='/api/backup'">دریافت نسخه پشتیبان</button><input id="restoreFile" type="file" accept=".sqlite3,.db,application/vnd.sqlite3"><button class="danger" onclick="restoreBackup()">بازیابی از فایل</button></div></section><section class="card" id="resellerCard" data-section-page="reseller"><div class="section-title">حساب‌های نمایندگی و تقسیم حجم</div><div class="small">بخشی از حجم تخصیص‌یافته‌ات را به یک نماینده بده. مجموع حجم سرویس‌ها و حساب‌های نمایندگی از سهمیه‌ات بیشتر نمی‌شود.</div><div class="fields"><input id="resellerUsername" maxlength="48" placeholder="نام کاربری نماینده"><input id="resellerPassword" type="password" placeholder="رمز عبور حداقل ۱۴ نویسه"><input id="resellerQuota" type="number" min="0.1" step="0.1" placeholder="حجم اختصاصی (GB)"><button class="primary" onclick="addReseller()">ساخت نماینده</button></div><div id="resellerList" style="margin-top:12px"></div><div id="allocationStatus" class="small"></div></section><section class="card" id="settingsCard" data-section-page="settings"><div class="section-title" data-i18n="settings">تنظیمات اتصال</div><div class="small" data-i18n="settingsHelp">پروفایل‌های قابل ارائه در اشتراک و Xray را فعال یا غیرفعال کن.</div><div class="small" style="margin-top:8px">پروفایل‌های XHTTP با حالت‌های stream-up/stream-one و مسیرهای جایگزین آزمایشی‌اند؛ چون در آزمون تونل از درگاه HTTP/1.1 تایم‌اوت داشتند، پیش‌فرض خاموش‌اند. فقط برای آزمون دستی فعال‌شان کن.</div><div id="profileSettings" class="profile-grid"></div></section><section class="card" id="diagnosticsCard" data-section-page="diagnostics"><div class="section-title">عیب‌یابی هوشمند و پیشنهاد اتصال</div><div class="small">اعتبارسنجی Xray و Nginx، بررسی مسیرهای داخلی و پیشنهاد پروفایل بر پایهٔ گزارش واقعی کاربران هر اپراتور. این بررسی داخلی به‌تنهایی پینگ واقعی تونل را ثابت نمی‌کند.</div><div class="tools" style="margin-top:12px"><label class="small" for="diagnosticCarrier">اپراتور</label><select id="diagnosticCarrier"><option value="auto">نامشخص / انتخاب خودکار</option><option value="mci">همراه اول</option><option value="irancell">ایرانسل</option><option value="rightel">رایتل</option><option value="wifi">وای‌فای</option></select><button class="primary" onclick="runDiagnostics()">بررسی همه پروفایل‌ها</button><button data-owner-only class="danger" onclick="repairDiagnostics()">تعمیر امن و راه‌اندازی مجدد</button></div><div id="diagnosticSummary" class="small" style="margin-top:12px">هنوز بررسی اجرا نشده است.</div><div id="diagnosticResults" class="diag-grid"></div><div class="small" style="margin-top:12px">گزارش‌های تست از صفحهٔ اشتراک بر اساس اپراتور جمع می‌شوند؛ پیشنهادها پس از رسیدن به حداقل ۳ گزارش نمایش داده می‌شوند.</div></section><section class="card" id="metricsCard" data-section-page="metrics"><div class="section-title">پایش زنده سرویس</div><div class="small">آمار منابع همین کانتینر و ترافیک ثبت‌شده؛ سرعت و پینگ واقعی اینترنت کاربر نیست.</div><div class="stats"><div class="card"><span>CPU</span><div class="num" id="metricCpu">—</div></div><div class="card"><span>RAM</span><div class="num" id="metricRam">—</div></div><div class="card"><span>دیسک</span><div class="num" id="metricDisk">—</div></div><div class="card"><span>سرعت ثبت‌شده</span><div class="num" id="metricSpeed">—</div></div><div class="card"><span>Load</span><div class="num" id="metricLoad">—</div></div><div class="card"><span>مصرف ثبت‌شده</span><div class="num" id="metricTraffic">—</div></div></div><div class="tools"><button onclick="loadMetrics()">به‌روزرسانی آمار</button></div><div id="profileChecks" class="small" style="margin-top:12px">بررسی هنوز اجرا نشده است. وضعیت مسیر HTTP با اتصال واقعی تونل متفاوت است.</div></section>
<section class="card" id="adminUsersCard" data-section-page="admins" data-owner-only><div class="section-title">مدیریت حساب‌های مدیر</div><div class="small">برای همکاران حساب جدا بساز. مشاهده‌گر فقط می‌تواند اطلاعات را ببیند.</div><div class="fields"><input id="adminUsername" maxlength="32" placeholder="نام کاربری"><input id="adminPassword" type="password" placeholder="رمز قوی، حداقل ۱۴ نویسه"><select id="adminRole"><option value="admin">مدیر</option><option value="viewer">مشاهده‌گر</option></select><button class="primary" onclick="createPanelAdmin()">ساخت حساب</button></div><div id="adminUsersList" style="margin-top:12px"></div></section>
<section class="card" id="apiKeysCard" data-section-page="apikeys" data-owner-only><div class="section-title">API و اتصال ربات</div><div class="small">کلید کامل فقط یک بار نمایش داده می‌شود؛ آن را در متغیر امن ربات نگه دار و داخل GitHub نگذار.</div><div class="fields"><input id="apiKeyName" maxlength="48" placeholder="نام کلید API"><select id="apiKeyExpiry"><option value="">بدون انقضا</option><option value="30">۳۰ روز</option><option value="90">۹۰ روز</option><option value="365">یک سال</option></select><button class="primary" onclick="createApiKey()">ساخت کلید API</button></div><div class="small" style="margin-top:8px">مجوزها: <label><input type="checkbox" class="apiScope" value="clients:read" checked> مشاهده کاربران</label> <label><input type="checkbox" class="apiScope" value="clients:write" checked> مدیریت کاربران</label> <label><input type="checkbox" class="apiScope" value="subscriptions:read" checked> لینک اشتراک</label> <label><input type="checkbox" class="apiScope" value="metrics:read" checked> آمار</label></div><div id="apiKeysList" style="margin-top:12px"></div><a class="button-link" href="/api-docs" target="_blank" rel="noopener">مستندات تعاملی API ↗</a><div class="small">GET/POST /api/v1/clients · PATCH/DELETE /api/v1/clients/{id} · GET /api/v1/system/metrics</div></section>
<section id="panelHealthCard" class="card" data-section-page="dashboard"><div class="section-title">وضعیت سرویس‌ها</div><div id="status" class="small">در حال بررسی اتصال داشبورد…</div><div class="dashboard-component-list" id="dashboardComponentStatus"><div class="small">در حال دریافت وضعیت Nginx، Xray، Database و Panel…</div></div><div class="section-title" style="margin-top:18px">آخرین سرویس‌ها</div><div id="recentActivityList" class="report-events"><div class="small">در انتظار دریافت اطلاعات…</div></div></section>
<section class="card" data-section-page="events"><div class="section-title" data-i18n="events">رویدادهای اخیر</div><div id="events"></div></section></div></main><dialog id="subDialog"><div class="modal-top"><div><h2 data-i18n="subTitle">مدیریت لینک اشتراک</h2><div id="subClientName" class="small"></div></div><button onclick="closeSub()" aria-label="بستن">✕</button></div><div class="sub-layout"><div><div class="sub-field"><label for="pageUrl">لینک واحد اشتراک (مرورگر + برنامهٔ سازگار)</label><input id="pageUrl" readonly></div><div class="sub-buttons"><button class="primary" onclick="copyField('pageUrl',this)" aria-label="کپی لینک واحد">⧉</button><span id="copyStatus" class="small" aria-live="polite"></span><a class="button-link" id="openPage" target="_blank" rel="noopener">باز کردن صفحه اشتراک</a></div><p class="small">برای برنامهٔ سازگار هم همین لینک را وارد کن؛ حجم و زمان از هدر استاندارد اشتراک به برنامه‌های سازگار ارسال می‌شود.</p></div><div><img id="subQr" class="qr-preview" alt="QR code" width="170" height="170"><div class="small" style="text-align:center" data-i18n="qrHint">برای واردکردن سریع، QR را اسکن کن.</div></div></div></dialog><dialog id="profilesDialog"><div class="modal-top"><div><h2>پروفایل‌های این سرویس</h2><div id="profilesClientName" class="small"></div></div><button onclick="document.getElementById('profilesDialog').close()" aria-label="بستن">✕</button></div><div class="small">چند پروفایل را هم‌زمان فعال کن. پروفایل خاموش در تنظیمات اصلی قابل انتخاب نیست.</div><div id="editClientProfileChoices" class="profile-grid"></div><div class="tools" style="margin-top:16px"><button class="primary" onclick="saveClientProfiles()">ذخیرهٔ پروفایل‌ها</button><button onclick="document.getElementById('profilesDialog').close()">انصراف</button></div></dialog><dialog id="panelHelpDialog"><div class="modal-top"><div><h2>راهنمای پنل</h2><div class="small">راهنمای سریع بخش‌های اصلی</div></div><button type="button" onclick="document.getElementById('panelHelpDialog').close()" aria-label="بستن">✕</button></div><div class="help-dialog-grid"><article><b>کاربران</b><p class="small">مشاهده و جست‌وجوی سرویس‌ها، وضعیت مصرف و لینک اشتراک.</p></article><article><b>ساخت سرویس</b><p class="small">نام، مدت، حجم و پروفایل‌های فعال را انتخاب کن.</p></article><article><b>سرورها و پروتکل‌ها</b><p class="small">وضعیت واقعی همین استقرار و پروفایل‌های موجود را ببین.</p></article><article><b>گزارش‌ها</b><p class="small">خطاهای پیکربندی و مسیرهای داخلی را بررسی کن. پاسخ مسیر وب به‌تنهایی اتصال واقعی کاربر را ثابت نمی‌کند.</p></article><article><b>اشتراک</b><p class="small">از جزئیات هر سرویس، لینک اشتراک و QR Code را باز یا کپی کن.</p></article></div></dialog><script src="/dashboard.js?v=20261016-layoutfix1" defer></script></body></html>'''

DASH_JS=r'''let csrf='',allClients=[],lang=localStorage.getItem('abyss-lang')||'fa';
const words={
fa:{tagline:'داشبورد مدیریتی خصوصی',changePassword:'تغییر رمز عبور',refresh:'به‌روزرسانی',logout:'خروج',total:'کل کاربران',active:'کاربران فعال',xray:'وضعیت Xray',clients:'مدیریت کاربران',clientHelp:'ساخت سرویس، کنترل دسترسی و مدیریت لینک اشتراک',search:'جست‌وجوی نام یا شناسه…',name:'نام کاربر',days:'مدت (روز، اختیاری)',quota:'حجم (GB، اختیاری)',note:'یادداشت (اختیاری)',optional:'خالی گذاشتن مدت و حجم یعنی نامحدود.',create:'+ ساخت کاربر',events:'رویدادهای اخیر',settings:'تنظیمات اتصال',settingsHelp:'پروفایل‌های قابل ارائه در اشتراک و Xray را فعال یا غیرفعال کن.',profileWs:'WebSocket',profileUpgrade:'HTTPUpgrade',profileXhttpAuto:'XHTTP · auto',profileXhttpPacket:'XHTTP · packet-up',online:'فعال',starting:'در حال راه‌اندازی',notInstalled:'نصب نیست',paused:'متوقف',used:'مصرف‌شده',unlimited:'نامحدود',expires:'انقضا',noExpiry:'بدون انقضا',subscription:'لینک اشتراک',copy:'کپی لینک',edit:'ویرایش',resetUsage:'ریست مصرف',subTitle:'مدیریت لینک اشتراک',sharePage:'صفحه اشتراک برای کاربر',rawSubscription:'لینک خام اشتراک برای کلاینت',copyPage:'کپی لینک صفحه',copiedPage:'لینک صفحه کپی شد.',copyRaw:'کپی لینک خام',openPage:'باز کردن صفحه',qrHint:'برای واردکردن سریع، QR را اسکن کن.',editName:'نام کاربر:',editNote:'یادداشت:',editDays:'مدت از امروز به روز (خالی = نامحدود):',editQuota:'حجم GB (خالی = نامحدود):',editSuccess:'مشخصات کاربر به‌روزرسانی شد.',resetConfirm:'مصرف ثبت‌شده این کاربر صفر شود؟',resetSuccess:'مصرف کاربر صفر شد.',pause:'توقف',enable:'فعال‌سازی',revoke:'حذف',noClients:'کاربری ثبت نشده است.',noResults:'موردی پیدا نشد.',connected:'اتصال داشبورد برقرار است.',apiError:'خطای API داشبورد: ',confirmRevoke:'این کاربر و دسترسی او حذف شود؟',copied:'لینک اشتراک کپی شد.',copyFail:'کپی خودکار ممکن نبود؛ لینک را کپی کن:',currentPassword:'رمز عبور فعلی:',newPassword:'رمز جدید (حداقل ۱۴ نویسه و شامل حرف و عدد):',passwordChanged:'رمز عبور تغییر کرد.',passwordRule:'رمز باید حداقل ۱۴ نویسه و شامل حروف و اعداد باشد.',createError:'ساخت کاربر ناموفق بود: ',changeError:'تغییر رمز ناموفق بود: ',xrayError:'آفلاین',subscriptionError:'دریافت لینک ناموفق بود: '},
en:{tagline:'PRIVATE CONTROL CENTER',changePassword:'Change password',refresh:'Refresh',logout:'Sign out',total:'Total clients',active:'Active clients',xray:'Xray status',clients:'Client management',clientHelp:'Create services, control access and manage subscription links',search:'Search by name or ID…',name:'Client name',days:'Duration (days, optional)',quota:'Quota (GB, optional)',note:'Note (optional)',optional:'Leave duration and quota empty for unlimited access.',create:'+ Create client',events:'Recent events',settings:'Connection settings',settingsHelp:'Enable or disable the profiles available in Xray and client subscriptions.',profileWs:'WebSocket',profileUpgrade:'HTTPUpgrade',profileXhttpAuto:'XHTTP · auto',profileXhttpPacket:'XHTTP · packet-up',online:'Online',starting:'Starting',notInstalled:'Not installed',paused:'Paused',used:'Used',unlimited:'Unlimited',expires:'Expires',noExpiry:'No expiry',subscription:'Subscription',copy:'Copy link',edit:'Edit',resetUsage:'Reset usage',subTitle:'Subscription links',sharePage:'Share page for the client',rawSubscription:'Raw subscription URL for clients',copyPage:'Copy page link',copiedPage:'Page link copied.',copyRaw:'Copy raw link',openPage:'Open page',qrHint:'Scan the QR code to import quickly.',editName:'Client name:',editNote:'Note:',editDays:'Duration from today in days (blank = unlimited):',editQuota:'Quota in GB (blank = unlimited):',editSuccess:'Client details updated.',resetConfirm:'Reset this client’s recorded usage to zero?',resetSuccess:'Client usage reset to zero.',pause:'Pause',enable:'Enable',revoke:'Revoke',noClients:'No clients yet.',noResults:'No matches found.',connected:'Dashboard connected successfully.',apiError:'Dashboard API error: ',confirmRevoke:'Revoke this client and remove access?',copied:'Subscription link copied.',copyFail:'Could not copy automatically. Copy this URL:',currentPassword:'Current password:',newPassword:'New password (14+ characters, letters and numbers):',passwordChanged:'Password changed.',passwordRule:'Password must be at least 14 characters and include letters and numbers.',createError:'Could not create client: ',changeError:'Could not change password: ',xrayError:'Offline',subscriptionError:'Could not get subscription: '}
};
function tr(k){return (words[lang]||words.fa)[k]||k}
function applyLanguage(){document.documentElement.lang=lang;document.documentElement.dir=lang==='fa'?'rtl':'ltr';document.querySelectorAll('[data-i18n]').forEach(el=>el.textContent=tr(el.dataset.i18n));document.querySelectorAll('[data-i18n-placeholder]').forEach(el=>el.placeholder=tr(el.dataset.i18nPlaceholder));const langBtn=document.getElementById('langBtn');if(langBtn)langBtn.textContent=lang==='fa'?'English':'فارسی';const status=document.getElementById('status');if(status)status.textContent=tr('connected');renderClients()}
function toggleLanguage(){lang=lang==='fa'?'en':'fa';localStorage.setItem('abyss-lang',lang);applyLanguage()}
async function api(u,o={}){o.headers={...(o.headers||{}),'Content-Type':'application/json','X-CSRF-Token':csrf};let r=await fetch(u,o),d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.detail||'Request failed');return d}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function renderClients(){const term=(document.getElementById('search')?.value||'').trim().toLowerCase();const rows=allClients.filter(c=>(c.name+' '+c.id+' '+(c.note||'')).toLowerCase().includes(term));document.getElementById('clients').innerHTML=rows.map(c=>'<div class="client"><div class="client-info"><b class="client-name">'+esc(c.name)+'</b><div class="small">'+esc(c.id.slice(0,8))+' · '+(c.enabled?tr('online'):tr('paused'))+' · '+tr('used')+' '+(Number(c.used_bytes||0)/1073741824).toFixed(3)+' GB'+(c.quota_bytes===null?' / '+tr('unlimited'):(' / '+(c.quota_bytes/1073741824).toFixed(2)+' GB'))+' · '+(c.expires_at?tr('expires')+' '+esc(c.expires_at):tr('noExpiry'))+(c.note?' · '+esc(c.note):'')+'</div></div><div class="actions"><button class="copy-icon-btn" title="کپی لینک اشتراک" aria-label="کپی لینک اشتراک" onclick="copyClientSub(\''+c.id+'\',this)">⧉</button><button title="جزئیات اشتراک" aria-label="جزئیات اشتراک" onclick="sub(\''+c.id+'\')">↗</button><button title="ویرایش سرویس" aria-label="ویرایش سرویس" onclick="editClient(\''+c.id+'\')">✎</button><button title="انتخاب پروفایل‌های این سرویس" aria-label="انتخاب پروفایل‌های این سرویس" onclick="editClientProfiles(\''+c.id+'\')">⚙</button><button title="صفرکردن مصرف ثبت‌شده" aria-label="صفرکردن مصرف ثبت‌شده" onclick="resetUsage(\''+c.id+'\')">↺</button><button title="'+(c.enabled?'توقف سرویس':'فعال‌سازی سرویس')+'" aria-label="'+(c.enabled?'توقف سرویس':'فعال‌سازی سرویس')+'" onclick="toggle(\''+c.id+'\','+(!c.enabled)+')">'+(c.enabled?'Ⅱ':'▶')+'</button><button class="danger" title="حذف سرویس" aria-label="حذف سرویس" onclick="revoke(\''+c.id+'\')">⌫</button></div></div>').join('')||(allClients.length?(term?'<p class="small">'+tr('noResults')+'</p>':''):'<p class="small">'+tr('noClients')+'</p>')}
async function copyClientSub(id,button){const before=button.innerHTML;try{const d=await api('/api/clients/'+id+'/subscription');const url=d.subscription_url||d.url||d.page_url;await navigator.clipboard.writeText(url);button.classList.add('copied');button.innerHTML='✓';button.title='کپی شد';setTimeout(()=>{button.classList.remove('copied');button.innerHTML=before;button.title='کپی لینک اشتراک'},1200)}catch(e){if(e.name==='NotAllowedError'){sub(id)}else alert(tr('subscriptionError')+e.message)}}
function renderSettings(profiles){const labels={ws:'profileWs',httpupgrade:'profileUpgrade',xhttp_auto:'profileXhttpAuto',xhttp_packet_up:'profileXhttpPacket'};document.getElementById('profileSettings').innerHTML=(profiles||[]).map(p=>'<label class="profile-setting"><input type="checkbox" '+(p.enabled?'checked':'')+' onchange="setProfile(\''+p.key+'\',this.checked)"><span>'+tr(labels[p.key]||p.label)+'</span></label>').join('')}

function renderProtocolCatalog(profiles){const el=document.getElementById('protocolCatalog');if(!el)return;const rows=profiles||[];el.innerHTML=rows.map(p=>'<article class="protocol-state"><div class="state-title"><span>'+esc(p.label)+'</span><span class="state-chip '+(p.enabled?'good':'neutral')+'">'+(p.enabled?'فعال':'خاموش')+'</span></div><strong>'+esc(p.protocol||'VLESS')+'</strong><div class="protocol-meta"><span>'+esc(p.network||'—')+'</span><span>'+esc(p.path||'—')+'</span>'+(p.port?'<span>Port '+esc(p.port)+'</span>':'')+(p.mode?'<span>'+esc(p.mode)+'</span>':'')+'</div>'+(p.experimental?'<div class="experimental-label">حالت آزمایشی · پیش‌فرض خاموش</div>':'')+'<label class="protocol-switch"><span>فعال در تنظیمات Xray</span><input type="checkbox" '+(p.enabled?'checked':'')+' onchange="setProfile(\''+esc(p.key)+'\',this.checked)" aria-label="فعال یا خاموش کردن '+esc(p.label)+'"></label></article>').join('')||'<div class="small">پروفایلی در دسترس نیست.</div>'}
async function loadProtocolCatalog(){try{const d=await api('/api/settings');renderProtocolCatalog(d.profiles||[])}catch(e){const el=document.getElementById('protocolCatalog');if(el)el.innerHTML='<div class="report-issue bad">دریافت پروفایل‌ها ناموفق بود: '+esc(e.message)+'</div>'}}
async function loadServerStatus(){const host=document.getElementById('serverHost'),grid=document.getElementById('serverStatusGrid'),overall=document.getElementById('serverOverall'),note=document.getElementById('serverStatusNote');if(host)host.textContent=location.host||'—';if(grid)grid.innerHTML='<article class="server-state"><div class="small">در حال بررسی اجزا…</div></article>';try{const [d,m]=await Promise.all([api('/api/system/diagnostics'),api('/api/system/metrics')]);const items=[{title:'پنل مدیریت',value:'در دسترس',ok:true,note:'درخواست احراز هویت‌شده پاسخ داد.'},{title:'Xray',value:d.xray_running?'در حال اجرا':d.xray_installed?'متوقف':'نصب‌نشده',ok:d.xray_running,note:d.xray_installed?'وضعیت پردازش Xray همین سرویس.':'باینری Xray در این کانتینر پیدا نشد.'},{title:'پیکربندی Xray',value:d.config_test?.ok?'معتبر':'نیازمند بررسی',ok:!!d.config_test?.ok,note:d.config_test?.detail||'نتیجهٔ اعتبارسنجی در دسترس نیست.'},{title:'Nginx',value:d.nginx_installed?(d.nginx_ok?'پیکربندی معتبر':'دارای خطا'):'مشخص نیست',ok:d.nginx_installed?!!d.nginx_ok:null,note:d.nginx_installed?(d.nginx_error||'نتیجهٔ آزمون nginx -t.'):'Nginx از مسیر بررسی این کانتینر شناسایی نشد.'},{title:'پایگاه‌داده',value:'قابل‌دسترسی',ok:true,note:'داده‌های وضعیت از API احراز هویت‌شده خوانده شدند.'},{title:'فضای ذخیره‌سازی',value:m.current?.disk_used_percent==null?'نامشخص':'دیسک قابل‌اندازه‌گیری',ok:m.current?.disk_used_percent!=null,note:m.current?.disk_used_percent==null?'آمار دیسک ارائه نشد.':'مصرف دیسک کانتینر: '+m.current.disk_used_percent+'%'}];if(grid)grid.innerHTML=items.map(x=>'<article class="server-state"><div class="state-title"><span>'+esc(x.title)+'</span><span class="state-chip '+(x.ok===true?'good':x.ok===false?'bad':'neutral')+'">'+(x.ok===true?'سالم':x.ok===false?'بررسی لازم':'نامشخص')+'</span></div><strong>'+esc(x.value)+'</strong><div class="small">'+esc(x.note)+'</div></article>').join('');const table=document.getElementById('serverTableBody');if(table)table.innerHTML='<tr><td>سرور جاری</td><td>'+esc(location.host||'—')+'</td><td><span class="state-chip '+(d.xray_running?'good':'bad')+'">'+(d.xray_running?'فعال':'متوقف')+'</span></td><td><span class="state-chip '+(d.ok?'good':'bad')+'">'+(d.ok?'سالم':'بررسی لازم')+'</span></td><td><button type="button" onclick="loadServerStatus()">بررسی مجدد</button></td></tr>';const pass=items.filter(x=>x.ok===true).length;if(overall){overall.className='state-chip '+(items.some(x=>x.ok===false)?'bad':'good');overall.textContent=pass+' از '+items.length+' بررسی موفق'}if(note)note.textContent=(d.note||'')+' · این گزارش وضعیت محلی همین استقرار است و اتصال واقعی از شبکهٔ کاربر را تأیید نمی‌کند.'}catch(e){if(grid)grid.innerHTML='<div class="report-issue bad">گرفتن وضعیت سرور ناموفق بود: '+esc(e.message)+'</div>';if(overall){overall.className='state-chip bad';overall.textContent='بررسی ناموفق'}if(note)note.textContent='پاسخ وضعیت سرور در دسترس نیست: '+e.message}}
async function loadDashboardHealth(){const el=document.getElementById('dashboardComponentStatus');if(!el)return;try{const d=await api('/api/system/diagnostics');const items=[{label:'Nginx',ok:d.nginx_installed?!!d.nginx_ok:null,value:d.nginx_installed?(d.nginx_ok?'فعال':'خطا'):'نامشخص'},{label:'Xray',ok:!!d.xray_running,value:d.xray_running?'فعال':d.xray_installed?'متوقف':'نصب‌نشده'},{label:'Database',ok:true,value:'قابل‌دسترسی'},{label:'Panel',ok:true,value:'فعال'}];el.innerHTML=items.map(x=>'<div class="dashboard-component"><span>'+esc(x.label)+'</span><span class="component-state '+(x.ok===true?'good':x.ok===false?'bad':'')+'">'+esc(x.value)+'</span></div>').join('')}catch(e){el.innerHTML='<div class="report-issue bad">دریافت وضعیت سرویس‌ها ناموفق بود: '+esc(e.message)+'</div>'}}
async function loadReports(){const summary=document.getElementById('reportSummary'),issues=document.getElementById('reportIssues'),profiles=document.getElementById('reportProfiles'),events=document.getElementById('reportEvents');if(summary)summary.textContent='در حال اجرای بررسی‌های واقعی…';try{const [d,o]=await Promise.all([api('/api/system/diagnostics'),api('/api/overview')]);if(summary)summary.textContent=(d.summary||'بررسی انجام شد.')+' · اتصال واقعی تونل از این صفحه تست نمی‌شود.';if(issues)issues.innerHTML=(d.issues||[]).map(x=>'<div class="report-issue '+(String(x).includes('خطا')||String(x).includes('متوقف')||String(x).includes('بسته')?'bad':'')+'">'+esc(x)+'</div>').join('')||'<div class="report-issue good">موردی برای گزارش وجود ندارد.</div>';if(profiles)profiles.innerHTML=(d.profiles||[]).map(p=>'<article class="report-state"><div class="state-title"><span>'+esc(p.label)+'</span><span class="state-chip '+(p.enabled&&p.listener_ok&&p.route_ok?'good':p.enabled?'bad':'neutral')+'">'+(p.enabled?(p.listener_ok&&p.route_ok?'مسیر پاسخ‌گو':'بررسی لازم'):'خاموش')+'</span></div><strong>'+esc(p.status_text||p.status||'—')+'</strong><div class="small">Listener: '+(p.listener_ok?'فعال':'غیرفعال')+' · HTTP '+esc(p.http_status??'—')+' · '+esc(p.latency_ms??'—')+' ms</div><div class="small" style="margin-top:6px">'+esc(p.hint||'')+'</div></article>').join('')||'<div class="small">پروفایلی ثبت نشده است.</div>';if(events)events.innerHTML=(o.events||[]).slice(0,12).map(e=>'<article class="report-event"><span class="event-message">'+esc(e.message)+'</span><span class="event-meta">'+esc(e.at)+' · '+esc(e.level)+'</span></article>').join('')||'<div class="small">رویدادی ثبت نشده است.</div>'}catch(e){if(summary)summary.textContent='گزارش‌گیری ناموفق بود: '+e.message;if(issues)issues.innerHTML='<div class="report-issue bad">'+esc(e.message)+'</div>'}}

function renderClientProfileChoices(profiles){const el=document.getElementById('clientProfileChoices');if(!el)return;el.innerHTML=(profiles||[]).map(p=>'<label class="profile-setting" title="'+esc(p.label)+'"><input type="checkbox" name="clientProfile" value="'+esc(p.key)+'" '+(p.enabled?'checked':'')+(p.enabled?'':' disabled')+'><span>'+esc(p.label)+(p.enabled?'':' · غیرفعال')+'</span><span class="help-dot" title="این گزینه فقط همین پروفایل را برای این سرویس فعال می‌کند؛ پروفایل‌های خاموش سراسری قابل انتخاب نیستند.">؟</span></label>').join('')}

async function setProfile(key,enabled){try{const d=await api('/api/settings/profiles',{method:'PATCH',body:JSON.stringify({profiles:{[key]:enabled}})});renderSettings(d.profiles);renderProtocolCatalog(d.profiles);renderClientProfileChoices(d.profiles);await load()}catch(e){alert(e.message);await load()}}
let editingProfileClientId='';
async function editClientProfiles(id){const c=allClients.find(x=>x.id===id);if(!c)return;editingProfileClientId=id;document.getElementById('profilesClientName').textContent=c.name;try{const d=await api('/api/settings');let selected=null;try{selected=c.profile_keys?JSON.parse(c.profile_keys):null}catch(e){}document.getElementById('editClientProfileChoices').innerHTML=(d.profiles||[]).map(p=>'<label class="profile-setting"><input type="checkbox" name="editClientProfile" value="'+esc(p.key)+'" '+((selected===null?p.enabled:selected.includes(p.key))&&p.enabled?'checked':'')+(p.enabled?'':' disabled')+'><span>'+esc(p.label)+(p.enabled?'':' · غیرفعال')+'</span><span class="help-dot" title="این پروفایل برای همین سرویس فعال یا غیرفعال می‌شود.">؟</span></label>').join('');document.getElementById('profilesDialog').showModal()}catch(e){alert('دریافت پروفایل‌ها ناموفق بود: '+e.message)}}
async function saveClientProfiles(){const profiles=[...document.querySelectorAll('input[name="editClientProfile"]:checked')].map(x=>x.value);if(!profiles.length){alert('حداقل یک پروفایل فعال را انتخاب کن.');return}try{await api('/api/clients/'+editingProfileClientId,{method:'PATCH',body:JSON.stringify({profiles})});document.getElementById('profilesDialog').close();await load()}catch(e){alert('ذخیرهٔ پروفایل‌ها ناموفق بود: '+e.message)}}
function improveFieldLabels(){document.querySelectorAll('.workspace .fields > input[placeholder],.workspace .fields > select').forEach(el=>{if(el.closest('.field'))return;const title=el.getAttribute('placeholder')||el.getAttribute('aria-label')||el.options?.[el.selectedIndex]?.text||'تنظیم';const wrap=document.createElement('label');wrap.className='field';const caption=document.createElement('span');caption.textContent=title;if(el.dataset.i18nPlaceholder)caption.dataset.i18n=el.dataset.i18nPlaceholder;el.parentNode.insertBefore(wrap,el);wrap.append(caption,el);el.removeAttribute('placeholder')})}
async function load(){try{improveFieldLabels();applyLanguage();let d=await api('/api/overview');csrf=d.csrf;window.abyssRole=d.role;allClients=d.clients||[];const accountName=document.getElementById('accountUsername');if(accountName)accountName.textContent=d.user?.username||'مدیر پنل';const accountRole=document.getElementById('accountRole');if(accountRole)accountRole.textContent=d.user?.role==='owner'?'مدیر کل':d.user?.role==='reseller'?'نماینده':'مدیر';const backupCard=document.getElementById('backupCard'),settingsCard=document.getElementById('settingsCard');if(backupCard)backupCard.classList.toggle('hidden',d.role!=='root');if(settingsCard)settingsCard.classList.toggle('hidden',d.role!=='root');rootOnly(d.role==='root');const allocation=document.getElementById('allocationStatus');if(allocation)allocation.textContent=d.role==='root'?'مدیریت سهمیه و حساب‌های نمایندگی':('حجم باقی‌مانده برای تخصیص: '+(Number(d.remaining_bytes||0)/1073741824).toFixed(2)+' GB');renderResellers(d.resellers||[]);const total=document.getElementById('total'),active=document.getElementById('active'),xray=document.getElementById('xray'),events=document.getElementById('events');if(total)total.textContent=d.total;if(active)active.textContent=d.active;if(xray)xray.textContent=d.xray.running?tr('online'):d.xray.installed?tr('starting'):tr('notInstalled');if(events)events.innerHTML=(d.events||[]).map(e=>'<div class="small">'+esc(e.at)+' · '+esc(e.level)+' · '+esc(e.message)+'</div>').join('')||'—';const recent=document.getElementById('recentActivityList');if(recent)recent.innerHTML=(d.clients||[]).slice(0,4).map(c=>'<article class="report-event"><span class="event-message"><b>'+esc(c.name)+'</b><br><span class="small">'+esc(String(c.id||'').slice(0,8))+'</span></span><span class="event-meta">'+(c.enabled?'فعال':'متوقف')+'</span></article>').join('')||'<div class="small">هنوز سرویسی ساخته نشده است.</div>';renderClients();const settings=await api('/api/settings');renderSettings(settings.profiles);renderProtocolCatalog(settings.profiles);renderClientProfileChoices(settings.profiles);const status=document.getElementById('status');if(status)status.textContent=tr('connected');if(d.role==='root'){await Promise.all([loadAdminUsers(),loadApiKeys()])}await loadMetrics();loadDashboardHealth()}catch(e){const status=document.getElementById('status');if(status)status.textContent=tr('apiError')+e.message;else console.error('Abyss dashboard load failed:',e)}}
async function add(){const input=document.getElementById('name'),days=document.getElementById('days'),quota=document.getElementById('quota'),note=document.getElementById('note');if(!input||!days||!quota||!note){alert('فرم ساخت کاربر با اسکریپت داشبورد هماهنگ نیست. صفحه را یک‌بار کامل تازه‌سازی کن.');return}if(!input.value.trim()){input.focus();alert('برای ساخت سرویس، نام کاربر را وارد کن.');return}const profiles=[...document.querySelectorAll('input[name="clientProfile"]:checked')].map(x=>x.value);if(!profiles.length){alert('حداقل یک پروفایل فعال را انتخاب کن.');return}try{await api('/api/clients',{method:'POST',body:JSON.stringify({name:input.value.trim(),duration_days:days.value?Number(days.value):null,quota_gb:quota.value?Number(quota.value):null,note:note.value,profiles})});input.value='';days.value='';quota.value='';note.value='';await load()}catch(e){alert(tr('createError')+e.message)}}
async function toggle(id,enabled){try{await api('/api/clients/'+id,{method:'PATCH',body:JSON.stringify({enabled})});await load()}catch(e){alert(e.message)}}
async function revoke(id){if(!confirm(tr('confirmRevoke')))return;try{await api('/api/clients/'+id,{method:'DELETE'});await load()}catch(e){alert(e.message)}}
async function sub(id){try{const d=await api('/api/clients/'+id+'/subscription');const c=allClients.find(x=>x.id===id);const url=d.subscription_url||d.url||d.page_url;document.getElementById('subClientName').textContent=c?c.name:id;document.getElementById('pageUrl').value=url;document.getElementById('openPage').href=url;document.getElementById('subQr').src=d.qr_url||'';document.getElementById('subDialog').showModal()}catch(e){alert(tr('subscriptionError')+e.message)}}
function closeSub(){document.getElementById('subDialog').close()}
async function copyField(id,button){const el=document.getElementById(id);try{await navigator.clipboard.writeText(el.value);if(button){const before=button.innerHTML;button.classList.add('copied');button.innerHTML='✓';button.setAttribute('aria-label','کپی شد');setTimeout(()=>{button.innerHTML=before;button.classList.remove('copied')},1100)}else{const note=document.getElementById('copyStatus');if(note)note.textContent=tr('copied')}}catch(e){el.focus();el.select();const note=document.getElementById('copyStatus');if(note)note.textContent=tr('copyFail')}}
async function editClient(id){const c=allClients.find(x=>x.id===id);if(!c)return;const name=prompt(tr('editName'),c.name);if(name===null)return;const note=prompt(tr('editNote'),c.note||'');if(note===null)return;const daysNow=c.expires_at?Math.max(1,Math.ceil((Date.parse(c.expires_at)-Date.now())/86400000)):'';const days=prompt(tr('editDays'),String(daysNow));if(days===null)return;const quotaNow=c.quota_bytes===null?'':String((c.quota_bytes/1073741824).toFixed(2));const quota=prompt(tr('editQuota'),quotaNow);if(quota===null)return;const changes={};if(name!==c.name)changes.name=name;if(note!==(c.note||''))changes.note=note;if(days.trim()!==String(daysNow))changes.duration_days=days.trim()?Number(days):null;if(quota.trim()!==quotaNow)changes.quota_gb=quota.trim()?Number(quota):null;if(!Object.keys(changes).length)return;try{await api('/api/clients/'+id,{method:'PATCH',body:JSON.stringify(changes)});await load();alert(tr('editSuccess'))}catch(e){alert(tr('changeError')+e.message)}}
async function resetUsage(id){if(!confirm(tr('resetConfirm')))return;try{await api('/api/clients/'+id+'/reset-usage',{method:'POST'});await load();alert(tr('resetSuccess'))}catch(e){alert(e.message)}}
async function changePassword(){let current=prompt(tr('currentPassword'));if(current===null)return;let next=prompt(tr('newPassword'));if(next===null)return;if(next.length<14||!/[A-Za-z]/.test(next)||!/[0-9]/.test(next)){alert(tr('passwordRule'));return}try{await api('/api/password',{method:'POST',body:JSON.stringify({current_password:current,new_password:next})});alert(tr('passwordChanged'))}catch(e){alert(tr('changeError')+e.message)}}
function renderResellers(rows){const el=document.getElementById('resellerList');if(!rows.length){el.innerHTML='<div class="small">نماینده‌ای ساخته نشده است.</div>';return}el.innerHTML=rows.map(x=>'<div class="client"><div class="client-info"><b>'+esc(x.username)+'</b><div class="small">'+(x.enabled?'فعال':'متوقف')+' · تخصیص '+(Number(x.quota_bytes)/1073741824).toFixed(2)+' GB · مصرف تخصیص‌یافته '+(Number(x.allocated_bytes||0)/1073741824).toFixed(2)+' GB · باقی‌مانده '+(Number(x.remaining_bytes||0)/1073741824).toFixed(2)+' GB</div></div><div class="actions"><button onclick="editReseller(\''+x.id+'\',\''+esc(x.username)+'\','+(Number(x.quota_bytes)/1073741824).toFixed(2)+')">ویرایش</button><button onclick="toggleReseller(\''+x.id+'\','+(!x.enabled)+')">'+(x.enabled?'توقف':'فعال‌سازی')+'</button><button class="danger" onclick="removeReseller(\''+x.id+'\')">حذف نماینده</button></div></div>').join('')}
async function addReseller(){const username=document.getElementById('resellerUsername').value.trim(),password=document.getElementById('resellerPassword').value,quota=Number(document.getElementById('resellerQuota').value);try{await api('/api/resellers',{method:'POST',body:JSON.stringify({username,password,quota_gb:quota})});document.getElementById('resellerUsername').value='';document.getElementById('resellerPassword').value='';document.getElementById('resellerQuota').value='';await load();alert('نماینده ساخته شد. نام کاربری و رمز را امن به صاحب آن بده.')}catch(e){alert('ساخت نماینده ناموفق بود: '+e.message)}}
async function editReseller(id,currentUsername,currentQuota){const username=prompt('نام کاربری جدید:',currentUsername);if(username===null)return;const quotaText=prompt('سهمیه کل نماینده (GB):',String(currentQuota));if(quotaText===null)return;const quota=Number(quotaText);if(!Number.isFinite(quota)||quota<0.1){alert('سهمیه نامعتبر است.');return}const password=prompt('رمز جدید (حداقل ۱۴ نویسه، خالی برای حفظ رمز):','');if(password===null)return;const body={username:username.trim(),quota_gb:quota};if(password)body.password=password;try{await api('/api/resellers/'+id,{method:'PATCH',body:JSON.stringify(body)});await load();alert('اطلاعات نماینده به‌روزرسانی شد.')}catch(e){alert('ویرایش ناموفق بود: '+e.message)}}
async function toggleReseller(id,enabled){try{await api('/api/resellers/'+id,{method:'PATCH',body:JSON.stringify({enabled})});await load()}catch(e){alert(e.message)}}
async function removeReseller(id){if(!confirm('نماینده حذف شود؟ ابتدا باید سهمیه‌های تخصیص‌یافته‌اش صفر باشد.'))return;try{await api('/api/resellers/'+id,{method:'DELETE'});await load()}catch(e){alert(e.message)}}
async function restoreBackup(){const f=document.getElementById('restoreFile').files[0];if(!f){alert('ابتدا فایل پشتیبان را انتخاب کن.');return}if(!confirm('بازیابی، پایگاه داده فعلی را جایگزین می‌کند. قبل از ادامه مطمئن شو فایل درست است.'))return;try{const fd=new FormData();fd.append('backup',f);const r=await fetch('/api/backup/restore',{method:'POST',headers:{'X-CSRF-Token':csrf},body:fd});const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.detail||'Restore failed');alert(d.message||'بازیابی انجام شد.');await load()}catch(e){alert('بازیابی ناموفق بود: '+e.message)}}
function runGlobalSearch(){const box=document.getElementById('globalSearch'),target=document.getElementById('search');if(!target)return;showSection('clients');target.value=box?box.value.trim():'';renderClients();target.focus()}
function showPanelHelp(){const dialog=document.getElementById('panelHelpDialog');if(dialog&&!dialog.open)dialog.showModal()}
function showSection(name){document.querySelectorAll('[data-section-page]').forEach(el=>el.classList.toggle('nav-hidden',el.dataset.sectionPage!==name));document.querySelectorAll('[data-nav]').forEach(el=>el.classList.toggle('active',el.dataset.nav===name));const titles={dashboard:'نمای کلی',clients:'مدیریت کاربران',create:'ساخت سرویس',servers:'مدیریت سرورها',protocols:'پروتکل‌ها',reports:'گزارش‌ها',reseller:'حساب‌های نمایندگی و سهمیه',settings:'تنظیمات اتصال',diagnostics:'عیب‌یابی هوشمند',backup:'پشتیبان‌گیری و بازیابی',metrics:'پایش زنده سرویس',admins:'مدیریت مدیران داشبورد',apikeys:'API و اتصال ربات',events:'رویدادهای اخیر'};const title=document.getElementById('sectionTitle');if(title)title.textContent=titles[name]||'Abyss Tunnel';const side=document.getElementById('sidebar');if(side&&innerWidth<=850)side.classList.remove('open');if(name==='servers')loadServerStatus();if(name==='reports')loadReports();if(name==='protocols')loadProtocolCatalog()}
function toggleSidebar(){const side=document.getElementById('sidebar');if(side)side.classList.toggle('open')}
function rootOnly(show){document.querySelectorAll('[data-owner-only]').forEach(el=>el.classList.toggle('hidden',!show))}
async function loadMetrics(){try{const d=await api('/api/system/metrics'),m=d.current||{};const set=(id,value)=>{const el=document.getElementById(id);if(el)el.textContent=value};set('metricCpu',m.cpu_percent==null?'—':m.cpu_percent+'%');set('metricRam',m.memory_used_percent==null?'—':m.memory_used_percent+'%');set('metricDisk',m.disk_used_percent==null?'—':m.disk_used_percent+'%');set('metricSpeed',((Number(m.traffic_bytes_per_second)||0)/1048576).toFixed(3)+' MB/s');set('metricLoad',Array.isArray(m.load_average)?m.load_average.join(' / '):'—');set('metricTraffic',((Number(m.recorded_traffic_bytes)||0)/1073741824).toFixed(3)+' GB');set('dashCpu',m.cpu_percent==null?'—':m.cpu_percent+'%');set('dashRam',m.memory_used_percent==null?'—':m.memory_used_percent+'%');set('dashDisk',m.disk_used_percent==null?'—':m.disk_used_percent+'%');set('dashboardTraffic',((Number(m.recorded_traffic_bytes)||0)/1073741824).toFixed(3)+' GB');drawUsageSparkline(m)}catch(e){const el=document.getElementById('profileChecks');if(el)el.textContent='خطای پایش: '+e.message}}
const usageHistory=[];
function drawUsageSparkline(metrics){
 const c=document.getElementById('usageSparkline');if(!c)return;
 const m=metrics||{},now=Date.now();
 const values=[m.cpu_percent,m.memory_used_percent,m.traffic_bytes_per_second];
 const hasTelemetry=values.some(v=>v!==null&&v!==undefined&&v!==''&&Number.isFinite(Number(v)));
 const last=usageHistory[usageHistory.length-1];
 if(hasTelemetry&&(!last||now-last.at>=10000)){
  usageHistory.push({at:now,cpu:Math.max(0,Math.min(100,Number(m.cpu_percent)||0)),ram:Math.max(0,Math.min(100,Number(m.memory_used_percent)||0)),net:Math.max(0,Number(m.traffic_bytes_per_second)||0)});
  if(usageHistory.length>24)usageHistory.shift();
 }
 const w=Math.max(260,Math.floor(c.clientWidth||600)),h=Math.max(108,Math.floor(c.clientHeight||144)),dpr=Math.min(devicePixelRatio||1,1.25);
 c.width=Math.round(w*dpr);c.height=Math.round(h*dpr);
 const ctx=c.getContext('2d');if(!ctx)return;
 ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,w,h);
 const root=getComputedStyle(document.documentElement);
 const grid=root.getPropertyValue('--ab-line').trim()||'rgba(170,174,182,.18)';
 const cpuColor=root.getPropertyValue('--chart-cpu').trim()||'#c8cad0';
 const ramColor=root.getPropertyValue('--chart-ram').trim()||'#8e85b8';
 const netColor=root.getPropertyValue('--chart-net').trim()||'#a2b0ba';
 const left=8,right=w-8,top=12,bottom=h-16,plotH=bottom-top;
 ctx.strokeStyle=grid;ctx.lineWidth=.65;
 for(let i=0;i<5;i++){const y=top+i*plotH/4;ctx.beginPath();ctx.moveTo(left,y);ctx.lineTo(right,y);ctx.stroke()}
 const netMax=Math.max(1,...usageHistory.map(v=>v.net))*1.12;
 const series=[['cpu',cpuColor,100],['ram',ramColor,100],['net',netColor,netMax]];
 for(const [key,color,max] of series){
  if(!usageHistory.length)continue;
  ctx.beginPath();
  usageHistory.forEach((sample,i)=>{
   const px=usageHistory.length===1?right:left+i*(right-left)/(usageHistory.length-1);
   const value=Math.min(1,Math.max(0,(Number(sample[key])||0)/max));
   const py=bottom-value*plotH;
   if(i===0)ctx.moveTo(px,py);else ctx.lineTo(px,py);
  });
  ctx.strokeStyle=color;ctx.lineWidth=1.8;ctx.lineJoin='round';ctx.lineCap='round';ctx.stroke();
  const newest=usageHistory[usageHistory.length-1];
  const ny=bottom-Math.min(1,Math.max(0,(Number(newest[key])||0)/max))*plotH;
  ctx.beginPath();ctx.arc(right,ny,2.5,0,Math.PI*2);ctx.fillStyle=color;ctx.fill();
 }
 const note=document.getElementById('chartNote');
 if(note)note.textContent=usageHistory.length<3?'در حال جمع‌آوری نمونه‌های واقعی؛ نمودار با نمونه‌های بعدی کامل می‌شود.':'تاریخچهٔ واقعی ۲۴ نمونهٔ اخیر · به‌روزرسانی هر ۱۵ ثانیه';
 c.setAttribute('aria-label','نمودار واقعی CPU، RAM و نرخ ترافیک؛ تعداد نمونه‌ها: '+usageHistory.length);
}
async function runDiagnostics(){const summary=document.getElementById('diagnosticSummary'),out=document.getElementById('diagnosticResults');if(summary)summary.textContent='در حال بررسی تنظیمات، Xray، Nginx و همه مسیرها…';if(out)out.innerHTML='';try{const carrier=document.getElementById('diagnosticCarrier')?.value||'mci';const d=await api('/api/system/diagnostics?carrier='+encodeURIComponent(carrier));if(summary)summary.textContent=d.summary+' · اپراتور: '+d.carrier_label+' · مسیر داخلی است، نه پینگ واقعی تونل.';if(out)out.innerHTML=(d.profiles||[]).map(p=>'<div class="diag-item"><b>'+esc(p.label)+'</b><div class="small">حالت: '+esc(p.mode||p.network)+' · HTTP '+esc(p.http_status??'—')+' · '+esc(p.latency_ms??'—')+' ms · گزارش: '+esc(p.feedback_reports??0)+' · موفقیت: '+(p.feedback_success_rate==null?'—':esc(p.feedback_success_rate)+'%')+'</div><div class="'+(p.route_ok?'diag-ok':'diag-bad')+'">'+esc(p.status_text||p.hint||p.status)+'</div><div class="small">پیشنهاد: '+esc(p.recommendation||p.hint||'—')+'</div></div>').join('')}catch(e){if(summary)summary.textContent='خطای عیب‌یابی: '+e.message}}
async function repairDiagnostics(){if(!confirm('اعتبارسنجی تنظیمات و راه‌اندازی مجدد امن انجام شود؟'))return;const summary=document.getElementById('diagnosticSummary');if(summary)summary.textContent='در حال اعتبارسنجی و تعمیر…';try{const d=await api('/api/system/diagnostics/repair',{method:'POST',body:JSON.stringify({})});if(summary)summary.textContent=d.message||'تعمیر انجام شد.';await runDiagnostics();await load()}catch(e){if(summary)summary.textContent='تعمیر ناموفق بود: '+e.message}}
async function checkProfileRoutes(){const el=document.getElementById('profileChecks');if(el)el.textContent='در حال بررسی Xray، پورت‌ها و مسیرهای وب…';try{const d=await api('/api/system/diagnostics');const lines=['Xray: '+(d.xray_running?'در حال اجرا':d.xray_installed?'نصب شده ولی اجرا نیست':'نصب نیست'),'آزمون تنظیمات: '+(d.config_test?.ok?'موفق':d.config_test?.status||'نامشخص'),...(d.issues||[]).map(x=>'⚠ '+x),...(d.profiles||[]).map(x=>x.label+': '+(x.status==='disabled'?'غیرفعال':(x.listener_ok?'پورت باز':'پورت بسته')+' · '+(x.route_ok?'مسیر وب پاسخ داد':'خطای مسیر')+' · تونل واقعی: تست نشده'))];if(el)el.textContent=lines.join('\n')}catch(e){if(el)el.textContent='خطای بررسی هوشمند: '+e.message}} async function repairXray(){if(!confirm('تنظیمات Xray بررسی و سرویس در صورت امکان دوباره راه‌اندازی می‌شود؛ اتصال‌های فعال ممکن است برای چند ثانیه قطع شوند. ادامه؟'))return;const el=document.getElementById('profileChecks');if(el)el.textContent='در حال اعتبارسنجی تنظیمات و تلاش برای راه‌اندازی مجدد Xray…';try{const d=await api('/api/system/diagnostics/repair',{method:'POST',body:JSON.stringify({})});if(el)el.textContent=d.message||'عملیات ترمیم تمام شد.';await checkProfileRoutes()}catch(e){if(el)el.textContent='ترمیم انجام نشد: '+e.message}}
async function loadAdminUsers(){const el=document.getElementById('adminUsersList');if(!el)return;try{const d=await api('/api/admin/users');el.innerHTML=(d.users||[]).map(u=>'<div class="client"><div class="client-info"><b>'+esc(u.username)+'</b><div class="small">'+esc(u.role)+' · '+(u.enabled?'فعال':'غیرفعال')+'</div></div><div class="actions"><button onclick="togglePanelAdmin(\''+u.id+'\','+(!u.enabled)+')">'+(u.enabled?'غیرفعال‌کردن':'فعال‌کردن')+'</button></div></div>').join('')||'<div class="small">حساب دیگری ثبت نشده است.</div>'}catch(e){el.textContent='خطای دریافت مدیران: '+e.message}}
async function createPanelAdmin(){const username=document.getElementById('adminUsername').value.trim(),password=document.getElementById('adminPassword').value,role=document.getElementById('adminRole').value;if(!username||password.length<14||!/[A-Za-z]/.test(password)||!/[0-9]/.test(password)){alert('نام کاربری را وارد کن؛ رمز باید حداقل ۱۴ نویسه و شامل حرف و عدد باشد.');return}try{await api('/api/admin/users',{method:'POST',body:JSON.stringify({username,password,role})});document.getElementById('adminUsername').value='';document.getElementById('adminPassword').value='';await loadAdminUsers();alert('حساب مدیر ساخته شد.')}catch(e){alert('ساخت حساب ناموفق بود: '+e.message)}}
async function togglePanelAdmin(id,enabled){try{await api('/api/admin/users/'+id,{method:'PATCH',body:JSON.stringify({enabled})});await loadAdminUsers()}catch(e){alert(e.message)}}
async function loadApiKeys(){const el=document.getElementById('apiKeysList');if(!el)return;try{const d=await api('/api/admin/api-keys');el.innerHTML=(d.keys||[]).map(k=>'<div class="client"><div class="client-info"><b>'+esc(k.name)+'</b><div class="small">'+esc(k.token_prefix)+' · '+esc((k.scopes||[]).join(', '))+' · '+(k.enabled?'فعال':'لغوشده')+'</div></div>'+(k.enabled?'<button class="danger" onclick="revokeApiKey(\''+k.id+'\')">لغو کلید</button>':'')+'</div>').join('')||'<div class="small">کلیدی ساخته نشده است.</div>'}catch(e){el.textContent='خطای دریافت کلیدها: '+e.message}}
async function createApiKey(){const name=document.getElementById('apiKeyName').value.trim(),expiry=document.getElementById('apiKeyExpiry').value,scopes=[...document.querySelectorAll('.apiScope:checked')].map(x=>x.value);if(!name||!scopes.length){alert('نام کلید و حداقل یک مجوز را انتخاب کن.');return}try{const d=await api('/api/admin/api-keys',{method:'POST',body:JSON.stringify({name,scopes,expires_in_days:expiry?Number(expiry):null})});document.getElementById('apiKeyName').value='';alert('این کلید فقط همین یک بار نمایش داده می‌شود؛ آن را در جای امن ذخیره کن:\n\n'+d.token);await loadApiKeys()}catch(e){alert('ساخت کلید ناموفق بود: '+e.message)}}
async function revokeApiKey(id){if(!confirm('این کلید API لغو شود؟'))return;try{await api('/api/admin/api-keys/'+id,{method:'DELETE'});await loadApiKeys()}catch(e){alert(e.message)}}
applyLanguage();showSection('dashboard');load();setInterval(()=>{if(document.visibilityState==='visible')loadMetrics()},15000);'''


# Abyss visual themes: royal-black/gold, angelic-white, and restrained color atmospheres.
ABYSS_THEME_CSS = r"""<style id="abyss-theme-system">
:root{--ab-bg:#050505;--ab-panel:rgba(16,16,18,.94);--ab-line:rgba(150,154,162,.20);--ab-accent:#bfc3ca;--ab-accent-hi:#e7e9ed;--ab-text:#f0f1f3;--ab-muted:#9b9ea5;--ab-glass:rgba(255,255,255,.035);--ab-glow:rgba(160,164,172,.055);--ab-input:rgba(7,7,8,.92);color-scheme:dark}
html[data-abyss-theme="abyss"]{--ab-bg:#050505;--ab-panel:rgba(15,15,17,.96);--ab-line:rgba(158,162,170,.20);--ab-accent:#c0c3ca;--ab-accent-hi:#f0f1f4;--ab-text:#f0f1f3;--ab-muted:#a0a2a8;--ab-glass:rgba(255,255,255,.035);--ab-glow:rgba(165,169,177,.055);--ab-input:rgba(7,7,8,.94);color-scheme:dark}
html[data-abyss-theme="angel"]{--ab-bg:#f4f3ef;--ab-panel:rgba(255,255,253,.97);--ab-line:rgba(163,148,119,.24);--ab-accent:#a8956f;--ab-accent-hi:#c5b48f;--ab-text:#292a2d;--ab-muted:#77766f;--ab-glass:rgba(164,149,119,.055);--ab-glow:rgba(188,173,143,.075);--ab-input:rgba(255,255,252,.98);color-scheme:light}
html[data-abyss-theme="graphite"]{--ab-bg:#111214;--ab-panel:rgba(26,27,30,.98);--ab-line:rgba(185,187,192,.17);--ab-accent:#b8bbc2;--ab-accent-hi:#f0f1f3;--ab-text:#eceef1;--ab-muted:#a3a6ad;--ab-glass:rgba(255,255,255,.025);--ab-glow:rgba(255,255,255,.025);--ab-input:rgba(18,19,21,.98);color-scheme:dark}
html[data-abyss-theme="slate"]{--ab-bg:#121820;--ab-panel:rgba(25,33,43,.98);--ab-line:rgba(151,171,190,.18);--ab-accent:#aebdcb;--ab-accent-hi:#e6edf3;--ab-text:#edf2f6;--ab-muted:#a5b0bb;--ab-glass:rgba(255,255,255,.03);--ab-glow:rgba(151,171,190,.035);--ab-input:rgba(15,21,28,.98);color-scheme:dark}
html[data-abyss-theme="ocean"]{--ab-bg:#071216;--ab-panel:rgba(17,31,37,.98);--ab-line:rgba(117,176,195,.20);--ab-accent:#9ac4ce;--ab-accent-hi:#d8edf1;--ab-text:#eaf4f5;--ab-muted:#a0b8bf;--ab-glass:rgba(255,255,255,.03);--ab-glow:rgba(57,133,157,.05);--ab-input:rgba(7,17,21,.98);color-scheme:dark}
html[data-abyss-theme="emerald"]{--ab-bg:#0c130e;--ab-panel:rgba(20,32,24,.98);--ab-line:rgba(135,181,145,.20);--ab-accent:#b0c9a8;--ab-accent-hi:#e0eedb;--ab-text:#edf4ed;--ab-muted:#a8b8aa;--ab-glass:rgba(255,255,255,.03);--ab-glow:rgba(87,140,91,.05);--ab-input:rgba(8,15,10,.98);color-scheme:dark}
html[data-abyss-theme="paper"]{--ab-bg:#f3f4f5;--ab-panel:rgba(255,255,255,.98);--ab-line:rgba(65,74,84,.15);--ab-accent:#5e6b79;--ab-accent-hi:#34404b;--ab-text:#252a30;--ab-muted:#6f7881;--ab-glass:rgba(30,40,50,.025);--ab-glow:rgba(90,100,110,.035);--ab-input:rgba(255,255,255,.99);color-scheme:light}
html,body{min-height:100%;background:var(--ab-bg)!important;color:var(--ab-text)!important}
body{position:relative;background-image:radial-gradient(ellipse at 82% 14%,var(--ab-glow),transparent 37%),radial-gradient(ellipse at 14% 78%,var(--ab-glow),transparent 42%)!important;background-size:100% 100%;animation:none!important}
body:before{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.14;background:radial-gradient(ellipse at 18% 20%,var(--ab-glow),transparent 32%),radial-gradient(ellipse at 82% 80%,var(--ab-glow),transparent 38%);animation:none!important}
body:after{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.075;background-image:radial-gradient(1px 1px at 12% 18%,var(--ab-accent-hi) 98%,transparent),radial-gradient(1px 1px at 79% 32%,var(--ab-text) 98%,transparent),radial-gradient(1px 1px at 37% 72%,var(--ab-accent) 98%,transparent),radial-gradient(1px 1px at 88% 86%,var(--ab-text) 98%,transparent),radial-gradient(1px 1px at 55% 14%,var(--ab-accent-hi) 98%,transparent);background-size:370px 310px}
body>*{position:relative;z-index:1}
.app-shell,.workspace{background:transparent!important}
.sidebar,.card,.panel,.box,.hero,.metric,.extra-box,.metric-pill,.profile-setting,.profile,.carrier-tools,.client{background:var(--ab-panel)!important;border-color:var(--ab-line)!important;backdrop-filter:blur(8px) saturate(108%);-webkit-backdrop-filter:blur(8px) saturate(108%);box-shadow:0 10px 28px rgba(0,0,0,.08)}
.sidebar{background:linear-gradient(165deg,var(--ab-panel),color-mix(in srgb,var(--ab-bg) 80%,transparent))!important}
input,select,textarea,.linkbox{background:var(--ab-input)!important;color:var(--ab-text)!important;border-color:var(--ab-line)!important}
button,.btn,a.button,.button-link,.nav-item,.profile-marks button{background:var(--ab-glass)!important;color:var(--ab-text)!important;border:1px solid var(--ab-line)!important;backdrop-filter:blur(5px) saturate(108%);-webkit-backdrop-filter:blur(5px) saturate(108%);box-shadow:inset 0 1px 0 rgba(255,255,255,.025),0 5px 14px rgba(0,0,0,.06);transition:background .16s ease,border-color .16s ease,transform .16s ease,box-shadow .16s ease}
button.primary,.btn.primary,.button-link.primary{background:linear-gradient(135deg,var(--ab-glass),color-mix(in srgb,var(--ab-accent) 16%,transparent))!important;color:var(--ab-accent-hi)!important;border-color:color-mix(in srgb,var(--ab-accent) 58%,transparent)!important}
button:hover,.btn:hover,a.button:hover,.button-link:hover,.nav-item:hover,.profile:hover{border-color:color-mix(in srgb,var(--ab-accent) 68%,transparent)!important;background:color-mix(in srgb,var(--ab-accent) 15%,transparent)!important;transform:translateY(-1px)}
.nav-item.active{color:var(--ab-accent-hi)!important;border-color:var(--ab-line)!important;background:color-mix(in srgb,var(--ab-accent) 14%,transparent)!important;box-shadow:inset -3px 0 var(--ab-accent),0 8px 24px rgba(0,0,0,.08)!important}
.mint,.eyebrow,.brand,.side-brand,.nav-item.active,.profile-open,#status,.section-title{color:var(--ab-accent)!important}
.muted,small,.small,.side-caption,.field,.sub-field label{color:var(--ab-muted)!important}
.badge{color:var(--ab-accent-hi)!important;border-color:var(--ab-line)!important;background:var(--ab-glass)!important}
.gauge{background:conic-gradient(var(--ab-accent) calc(var(--value)*1%),var(--ab-line) 0)!important}.gauge:before{background:var(--ab-bg)!important;border-color:var(--ab-line)!important}
dialog{background:var(--ab-bg)!important;color:var(--ab-text)!important;border-color:var(--ab-line)!important}dialog::backdrop{background:rgba(0,0,0,.48)!important;backdrop-filter:blur(12px)}
#abyssThemeDock{display:inline-flex;align-items:center;gap:8px;max-width:100%;padding:6px 10px;border:1px solid var(--ab-line);border-radius:999px;background:var(--ab-glass);color:var(--ab-text);backdrop-filter:blur(18px) saturate(140%);-webkit-backdrop-filter:blur(18px) saturate(140%);box-shadow:0 8px 28px rgba(0,0,0,.10);font:12px system-ui,sans-serif;white-space:nowrap}
#abyssThemeDock .theme-mark{color:var(--ab-accent);font-size:14px}#abyssThemeSelect{width:auto;max-width:165px;min-width:0;margin:0;padding:4px 19px 4px 5px;border:0!important;outline:none;background:transparent!important;color:var(--ab-text)!important;font:inherit;box-shadow:none!important}#abyssThemeSelect option{background:var(--ab-bg);color:var(--ab-text)}
#abyssThemeDock.floating{position:fixed;top:14px;right:14px;z-index:9999}
@keyframes abyssAtmosphere{0%{background-position:0% 0%}100%{background-position:100% 100%}}@keyframes abyssOrbit{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
html[data-abyss-theme="angel"] body:before{opacity:.55;background:radial-gradient(circle at 72% 23%,transparent 0 49px,rgba(163,146,111,.27) 50px,transparent 54px),radial-gradient(circle at 72% 23%,transparent 0 82px,rgba(163,146,111,.16) 83px,transparent 85px),radial-gradient(ellipse at 48% 8%,rgba(255,255,255,.94),transparent 52%),radial-gradient(ellipse at 12% 86%,rgba(207,215,232,.60),transparent 40%)}
html[data-abyss-theme="angel"] body:after{opacity:.23;background-image:radial-gradient(1px 1px at 12% 18%,#b29c6b 98%,transparent),radial-gradient(1px 1px at 79% 32%,#a9b4c8 98%,transparent),radial-gradient(1px 1px at 37% 72%,#c1ad7b 98%,transparent)}
html[data-abyss-theme="angel"] .card,html[data-abyss-theme="angel"] .panel,html[data-abyss-theme="angel"] .hero,html[data-abyss-theme="angel"] .sidebar{box-shadow:0 18px 48px rgba(74,77,93,.08),inset 0 1px rgba(255,255,255,.75)}
@media(max-width:700px){#abyssThemeDock{gap:5px;padding:5px 8px}#abyssThemeSelect{max-width:130px;font-size:11px}#abyssThemeDock.floating{top:10px;right:10px}}
@media(prefers-reduced-motion:reduce){body{animation:none!important}body:before{animation:none!important}*,*:before,*:after{transition:none!important}}
.abyss-logo-mark{display:inline-block;width:24px;height:24px;flex:0 0 24px;border-radius:50%;position:relative;background:radial-gradient(circle at center,#050505 0 27%,transparent 29%);isolation:isolate}
.abyss-logo-mark:before{content:"";position:absolute;inset:-2px;border-radius:50%;background:repeating-conic-gradient(from 0deg,rgba(210,213,218,.6) 0deg .55deg,transparent .7deg 3.2deg);mask:radial-gradient(circle,transparent 0 27%,#000 30% 63%,transparent 76%);opacity:.62}
.abyss-brand-row{display:flex;align-items:center;gap:9px;letter-spacing:.14em}.abyss-brand-row .brand-name{display:grid;gap:2px}.abyss-brand-row small{font-size:9px;letter-spacing:.22em;opacity:.75}.login-brand{justify-content:center;margin:8px 0 22px;font-size:14px}.login-brand .abyss-logo-mark{width:48px;height:48px;flex-basis:48px}.login-brand .abyss-logo-mark:before{inset:-4px}
#abyssThemeDock{box-shadow:none!important;backdrop-filter:none!important;background:var(--ab-panel)!important}
#abyssParticleCanvas{position:fixed!important;inset:0;width:100%;height:100%;pointer-events:none;z-index:0!important;opacity:.52}
.abyss-utility-links{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-top:16px}
.abyss-utility-links a{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:8px 10px;min-height:34px;border:1px solid var(--ab-line);border-radius:10px;background:var(--ab-glass);color:var(--ab-muted);font-size:11px;text-decoration:none;transition:border-color .16s ease,color .16s ease}
.abyss-utility-links a:hover{border-color:var(--ab-accent);color:var(--ab-text)}
.help-dot{display:inline-grid;place-items:center;width:17px;height:17px;margin-inline-start:5px;border:1px solid var(--ab-line);border-radius:50%;font-size:10px;color:var(--ab-accent);cursor:help;vertical-align:middle}
.client .actions button{min-width:38px;padding:7px 9px;font-size:12px}
.copy-icon-btn{width:38px;min-width:38px!important;padding:6px!important}
.copy-icon-btn.copied{color:#72d7a0!important;border-color:#72d7a0!important}
#usageSparkline{width:100%;height:88px;display:block}
@media(min-width:851px){.app-shell{width:100%;max-width:none;grid-template-columns:260px minmax(0,1fr)}.workspace{width:100%;max-width:none;padding-inline:clamp(20px,2.2vw,42px)}.workspace>section.card,.workspace>.stats{width:100%}}
@media(max-width:850px){.abyss-utility-links a{min-height:40px}.workspace{max-width:100%}.sidebar{backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}}
@media(prefers-reduced-motion:reduce){#abyssParticleCanvas{display:none!important}}
</style>"""
ABYSS_THEME_POLISH_CSS = r"""<style id="abyss-theme-polish">
:root{--ab-radius-xl:25px;--ab-radius-lg:20px;--ab-radius-md:14px;--ab-radius-sm:11px;--ab-motion:.24s}
html{scroll-behavior:smooth;scroll-padding-top:20px}
body{background-image:radial-gradient(ellipse at 12% 8%,color-mix(in srgb,var(--ab-accent) 10%,transparent),transparent 36%),radial-gradient(ellipse at 88% 72%,var(--ab-glow),transparent 43%),radial-gradient(ellipse at 48% 110%,color-mix(in srgb,var(--ab-text) 4%,transparent),transparent 48%),linear-gradient(145deg,var(--ab-bg),color-mix(in srgb,var(--ab-bg) 82%,var(--ab-accent) 4%));background-size:160% 160%;animation:abyssGlowDrift 38s ease-in-out infinite alternate}
body:before{opacity:.43}
body:after{opacity:.13;background-size:370px 310px}
@keyframes abyssGlowDrift{0%{background-position:0% 0%}50%{background-position:65% 25%}100%{background-position:100% 100%}}
.card,.panel,.box,.section,.stat,.metric,.hero,.extra-box,.metric-pill,.profile-setting,.profile,.app,.client,.client-card,.section-head,.api-key-row{border-radius:var(--ab-radius-lg)!important;border-color:var(--ab-line)!important;background:linear-gradient(145deg,color-mix(in srgb,var(--ab-panel) 92%,var(--ab-accent) 3%),var(--ab-panel))!important;box-shadow:0 16px 42px rgba(0,0,0,.10),inset 0 1px 0 color-mix(in srgb,var(--ab-text) 5%,transparent)!important;transition:background var(--ab-motion) ease,border-color var(--ab-motion) ease,box-shadow var(--ab-motion) ease,transform var(--ab-motion) ease}
.card,.panel,.box,.hero,.extra-box,.metric,.metric-pill,.profile-setting,.profile,.app,.client,.client-card{backdrop-filter:blur(20px) saturate(125%);-webkit-backdrop-filter:blur(20px) saturate(125%)}
.card:hover,.panel:hover,.box:hover,.profile:hover,.app:hover,.client-card:hover{border-color:color-mix(in srgb,var(--ab-accent) 34%,var(--ab-line))!important;box-shadow:0 18px 46px rgba(0,0,0,.13),0 0 24px color-mix(in srgb,var(--ab-glow) 70%,transparent)!important}
.stats>.card:first-child,.stats>.card:nth-child(3),.hero,.subscription-hero,.usage-card,.highlight,.featured,.metric-pill{background:radial-gradient(ellipse at 95% 0%,color-mix(in srgb,var(--ab-accent) 12%,transparent),transparent 62%),linear-gradient(145deg,color-mix(in srgb,var(--ab-panel) 86%,var(--ab-accent) 6%),var(--ab-panel))!important;border-color:color-mix(in srgb,var(--ab-accent) 32%,var(--ab-line))!important;box-shadow:0 16px 42px rgba(0,0,0,.12),0 0 28px color-mix(in srgb,var(--ab-glow) 55%,transparent),inset 0 1px 0 color-mix(in srgb,var(--ab-text) 7%,transparent)!important}
.sidebar{border-radius:0!important;box-shadow:inset -1px 0 color-mix(in srgb,var(--ab-line) 80%,transparent),10px 0 42px rgba(0,0,0,.08)!important}
.section-heading,.section-title,.section-head h2{letter-spacing:-.015em}
.section-title:before,.section-heading:before,.section-head h2:before{content:"";display:inline-block;width:4px;height:1em;margin-left:10px;vertical-align:-.13em;border-radius:99px;background:var(--ab-accent);box-shadow:0 0 14px var(--ab-glow)}
button,.btn,a.button,.button-link,.nav-item,.profile-marks button{min-height:40px;border-radius:13px!important;transition:background var(--ab-motion) ease,border-color var(--ab-motion) ease,box-shadow var(--ab-motion) ease,transform var(--ab-motion) ease!important}
button:hover,.btn:hover,a.button:hover,.button-link:hover,.nav-item:hover,.profile:hover{transform:translateY(-1px)}
button.primary,.btn.primary,.button-link.primary{box-shadow:0 8px 24px color-mix(in srgb,var(--ab-glow) 80%,transparent),inset 0 1px 0 rgba(255,255,255,.08)!important}
input,select,textarea,.linkbox{border-radius:13px!important;min-height:42px;transition:border-color var(--ab-motion) ease,box-shadow var(--ab-motion) ease,background var(--ab-motion) ease}
input:focus,select:focus,textarea:focus,.linkbox:focus{border-color:color-mix(in srgb,var(--ab-accent) 68%,var(--ab-line))!important;box-shadow:0 0 0 3px color-mix(in srgb,var(--ab-accent) 13%,transparent)!important;outline:none}
:focus-visible{outline:2px solid var(--ab-accent)!important;outline-offset:3px}
.badge,.pill,.tag{border-radius:999px!important}
dialog{border-radius:25px!important;box-shadow:0 28px 100px rgba(0,0,0,.25),0 0 40px color-mix(in srgb,var(--ab-glow) 55%,transparent)!important}
#abyssThemeDock{border-radius:999px!important}
html[data-abyss-theme="angel"] body:before{opacity:.28}
html[data-abyss-theme="angel"] body:after{opacity:.075}
html[data-abyss-theme="angel"] .card,html[data-abyss-theme="angel"] .panel,html[data-abyss-theme="angel"] .box,html[data-abyss-theme="angel"] .hero,html[data-abyss-theme="angel"] .profile,html[data-abyss-theme="angel"] .app{box-shadow:0 15px 40px rgba(75,79,96,.075),inset 0 1px 0 rgba(255,255,255,.78)!important}
html[data-abyss-theme="angel"] button.primary,html[data-abyss-theme="angel"] .btn.primary,html[data-abyss-theme="angel"] .button-link.primary{color:var(--ab-accent)!important;border-color:color-mix(in srgb,var(--ab-accent) 45%,transparent)!important;background:linear-gradient(135deg,rgba(255,255,255,.85),color-mix(in srgb,var(--ab-accent) 10%,white))!important}
@media(max-width:700px){:root{--ab-radius-xl:22px;--ab-radius-lg:18px}.card,.panel,.box,.hero,.extra-box,.metric,.profile,.app,.client,.client-card{padding:clamp(12px,3.5vw,18px)}button,.btn,a.button,.button-link{min-height:42px}.stats>.card:first-child,.stats>.card:nth-child(3){box-shadow:0 12px 30px rgba(0,0,0,.10),0 0 18px color-mix(in srgb,var(--ab-glow) 50%,transparent)!important}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}body{animation:none!important}*,*:before,*:after{transition:none!important;animation:none!important;scroll-behavior:auto!important}}
.diag-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-top:12px}.diag-item{padding:13px;border:1px solid var(--ab-line);border-radius:15px;background:var(--ab-panel);min-width:0}.diag-item b{display:block;margin-bottom:7px;overflow-wrap:anywhere}.diag-ok{color:#8de8b0}.diag-bad{color:#ffb2b2}
/* Reference-led finish: Abyss is true black/graphite; Angel is ivory with aged gold and silver. */
html[data-abyss-theme="abyss"] body{
 background-image:
  linear-gradient(118deg,transparent 0 18%,rgba(190,194,202,.022) 18.1%,transparent 18.35% 56%,rgba(190,194,202,.028) 56.1%,transparent 56.4%),
  linear-gradient(164deg,transparent 0 38%,rgba(255,255,255,.018) 38.1%,transparent 38.32% 76%,rgba(180,184,192,.02) 76.1%,transparent 76.35%),
  radial-gradient(ellipse at 12% 10%,rgba(185,189,198,.055),transparent 34%),
  radial-gradient(ellipse at 88% 78%,rgba(110,113,120,.045),transparent 38%),
  linear-gradient(145deg,#030303,#09090a 58%,#040404)!important;
 background-size:180% 180%;animation:abyssGlowDrift 42s ease-in-out infinite alternate!important
}
html[data-abyss-theme="abyss"] body:before{
 opacity:.34!important;
 background-image:linear-gradient(128deg,transparent 0 24%,rgba(190,194,202,.055) 24.08%,transparent 24.22% 68%,rgba(190,194,202,.04) 68.08%,transparent 68.24%),radial-gradient(ellipse at 82% 12%,rgba(210,213,220,.07),transparent 42%)!important
}
html[data-abyss-theme="abyss"] .card,
html[data-abyss-theme="abyss"] .panel,
html[data-abyss-theme="abyss"] .hero,
html[data-abyss-theme="abyss"] .metric,
html[data-abyss-theme="abyss"] .profile,
html[data-abyss-theme="abyss"] .client,
html[data-abyss-theme="abyss"] .sidebar{
 border-color:rgba(174,178,187,.19)!important;
 background:linear-gradient(145deg,rgba(20,20,22,.96),rgba(8,8,9,.97))!important;
 box-shadow:0 20px 55px rgba(0,0,0,.30),inset 0 1px 0 rgba(255,255,255,.035)!important
}
html[data-abyss-theme="abyss"] .mint,
html[data-abyss-theme="abyss"] .brand,
html[data-abyss-theme="abyss"] .side-brand,
html[data-abyss-theme="abyss"] .nav-item.active,
html[data-abyss-theme="abyss"] .section-title,
html[data-abyss-theme="abyss"] .profile-open{color:#d0d2d7!important}
html[data-abyss-theme="abyss"] button.primary,
html[data-abyss-theme="abyss"] .btn.primary,
html[data-abyss-theme="abyss"] .button-link.primary{
 color:#f0f0f2!important;border-color:rgba(196,199,205,.42)!important;
 background:linear-gradient(145deg,rgba(225,227,232,.13),rgba(95,97,103,.08))!important
}
html[data-abyss-theme="abyss"] .nav-item.active{box-shadow:inset -3px 0 #c4c7cd,0 8px 24px rgba(0,0,0,.15)!important}
html[data-abyss-theme="abyss"] .abyss-logo-mark:before{background:repeating-conic-gradient(from 0deg,rgba(213,216,222,.7) 0deg .55deg,transparent .7deg 3.2deg)}
html[data-abyss-theme="angel"] body{
 background-image:linear-gradient(122deg,transparent 0 20%,rgba(174,151,104,.045) 20.1%,transparent 20.3% 62%,rgba(172,179,193,.055) 62.1%,transparent 62.35%),radial-gradient(ellipse at 78% 5%,rgba(255,255,255,.98),transparent 44%),radial-gradient(ellipse at 12% 86%,rgba(209,214,225,.46),transparent 42%),linear-gradient(145deg,#faf9f5,#efede6 68%,#f8f7f2)!important
}
html[data-abyss-theme="angel"] body:before{
 opacity:.4!important;background-image:linear-gradient(128deg,transparent 0 25%,rgba(170,146,99,.10) 25.08%,transparent 25.22% 70%,rgba(164,174,190,.12) 70.08%,transparent 70.24%),radial-gradient(ellipse at 76% 20%,rgba(255,255,255,.95),transparent 52%)!important
}
html[data-abyss-theme="angel"] .card,
html[data-abyss-theme="angel"] .panel,
html[data-abyss-theme="angel"] .hero,
html[data-abyss-theme="angel"] .metric,
html[data-abyss-theme="angel"] .profile,
html[data-abyss-theme="angel"] .client,
html[data-abyss-theme="angel"] .sidebar{
 border-color:rgba(160,139,97,.24)!important;
 background:linear-gradient(145deg,rgba(255,255,253,.98),rgba(247,245,238,.97))!important;
 box-shadow:0 18px 48px rgba(91,83,65,.09),inset 0 1px 0 rgba(255,255,255,.94)!important
}
html[data-abyss-theme="angel"] .mint,
html[data-abyss-theme="angel"] .brand,
html[data-abyss-theme="angel"] .side-brand,
html[data-abyss-theme="angel"] .nav-item.active,
html[data-abyss-theme="angel"] .section-title,
html[data-abyss-theme="angel"] .profile-open{color:#9d875d!important}
html[data-abyss-theme="angel"] button.primary,
html[data-abyss-theme="angel"] .btn.primary,
html[data-abyss-theme="angel"] .button-link.primary{
 color:#887249!important;border-color:rgba(164,141,95,.4)!important;
 background:linear-gradient(145deg,rgba(255,255,255,.98),rgba(228,218,193,.35))!important
}
html[data-abyss-theme="angel"] .nav-item.active{box-shadow:inset -3px 0 #b5a071,0 8px 24px rgba(100,90,67,.06)!important}
html[data-abyss-theme="angel"] input,
html[data-abyss-theme="angel"] select,
html[data-abyss-theme="angel"] textarea,
html[data-abyss-theme="angel"] .linkbox{background:rgba(255,255,252,.98)!important;border-color:rgba(160,139,97,.25)!important}
html[data-abyss-theme="angel"] .abyss-logo-mark{background:radial-gradient(circle at center,#f6f4ed 0 27%,transparent 29%)}
html[data-abyss-theme="angel"] .abyss-logo-mark:before{background:repeating-conic-gradient(from 0deg,rgba(166,144,100,.72) 0deg .55deg,transparent .7deg 3.2deg)}
/* Login and subscription pages use the same theme tokens as the dashboard. */
html[data-abyss-theme="abyss"] body:has(.login-brand) .card{
 background:linear-gradient(150deg,rgba(19,19,21,.98),rgba(5,5,6,.98))!important;border-color:rgba(174,178,187,.22)!important
}
html[data-abyss-theme="abyss"] body:has(.login-brand) button{
 color:#f0f0f2!important;background:linear-gradient(145deg,rgba(225,227,232,.14),rgba(95,97,103,.08))!important;border:1px solid rgba(196,199,205,.38)!important
}
html[data-abyss-theme="angel"] body:has(.login-brand) .card{
 background:linear-gradient(150deg,rgba(255,255,253,.99),rgba(245,242,233,.98))!important;border-color:rgba(160,139,97,.25)!important
}
html[data-abyss-theme="angel"] body:has(.login-brand) button{
 color:#887249!important;background:linear-gradient(145deg,#fff,#e8dfca)!important;border:1px solid rgba(164,141,95,.4)!important
}
@media(max-width:700px){
 body{animation:none!important;background-size:100% 100%!important}
 #abyssParticleCanvas{opacity:.2!important}
 .card,.panel,.hero,.metric,.profile,.client{backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
}
</style>"""
ABYSS_THEME_JS = r"""<script id="abyss-theme-controller">(()=>{const presets={abyss:'Abyss · مشکی و خاکستری',angel:'Angel · سفید و طلایی کمرنگ',graphite:'Graphite · خاکستری ساده',slate:'Slate · ذغالی ساده',ocean:'Ocean · آبی ساده',emerald:'Emerald · سبز ساده',paper:'Paper · روشن ساده'};let saved='abyss';try{saved=localStorage.getItem('abyss-visual-theme')||'abyss'}catch(e){}if(!presets[saved])saved='abyss';const apply=t=>{if(!presets[t])t='abyss';document.documentElement.dataset.abyssTheme=t;try{localStorage.setItem('abyss-visual-theme',t)}catch(e){}const meta=document.querySelector('meta[name="theme-color"]');if(meta)meta.content=(t==='angel'||t==='paper')?(t==='angel'?'#f4f3ef':'#f3f4f5'):t==='slate'?'#121820':t==='graphite'?'#111214':t==='ocean'?'#071216':t==='emerald'?'#0c130e':'#050505'};apply(saved);const init=()=>{if(document.getElementById('abyssThemeDock'))return;const dock=document.createElement('label');dock.id='abyssThemeDock';dock.innerHTML='<span class="theme-mark" aria-hidden="true">◉</span><span>تم</span><select id="abyssThemeSelect" aria-label="انتخاب تم">'+Object.entries(presets).map(([k,v])=>'<option value="'+k+'">'+v+'</option>').join('')+'</select>';const target=document.querySelector('.top .tools')||document.querySelector('.top');if(target)target.appendChild(dock);else{dock.classList.add('floating');document.body.appendChild(dock)}const select=dock.querySelector('select');select.value=document.documentElement.dataset.abyssTheme;select.addEventListener('change',()=>apply(select.value));if(!document.getElementById('abyssParticleCanvas')&&!matchMedia('(prefers-reduced-motion: reduce)').matches){const canvas=document.createElement('canvas');canvas.id='abyssParticleCanvas';canvas.setAttribute('aria-hidden','true');document.body.prepend(canvas);const ctx=canvas.getContext('2d',{alpha:true});if(ctx){let w=0,h=0,points=[],raf=0,dirty=true;const resize=()=>{const coarse=matchMedia('(pointer:coarse), (max-width:700px)').matches;const dpr=Math.min(devicePixelRatio||1,coarse?1:1.25);w=innerWidth;h=innerHeight;canvas.width=Math.floor(w*dpr);canvas.height=Math.floor(h*dpr);canvas.style.width=w+'px';canvas.style.height=h+'px';ctx.setTransform(dpr,0,0,dpr,0,0);const count=coarse?9:Math.min(28,Math.max(12,Math.round(w*h/52000)));points=Array.from({length:count},()=>({x:Math.random()*w,y:Math.random()*h,r:.45+Math.random()*.7,a:.12+Math.random()*.22,dx:(Math.random()-.5)*.08,dy:(Math.random()-.5)*.08}));dirty=true};let ripple=null;const paint=()=>{raf=0;ctx.clearRect(0,0,w,h);const theme=document.documentElement.dataset.abyssTheme;const light=theme==='angel'||theme==='paper';for(const p of points){p.x+=p.dx;p.y+=p.dy;if(p.x<0||p.x>w)p.dx*=-1;if(p.y<0||p.y>h)p.dy*=-1;ctx.beginPath();ctx.fillStyle=light?'rgba(145,130,99,'+p.a*.38+')':'rgba(195,199,207,'+p.a+')';ctx.arc(p.x,p.y,p.r,0,Math.PI*2);ctx.fill()}if(ripple){ripple.r+=2.2;ripple.a*=.965;ctx.beginPath();ctx.strokeStyle=light?'rgba(166,148,108,'+ripple.a+')':'rgba(195,199,207,'+ripple.a+')';ctx.lineWidth=1;ctx.arc(ripple.x,ripple.y,ripple.r,0,Math.PI*2);ctx.stroke();if(ripple.a<.025)ripple=null}if(document.visibilityState==='visible')raf=requestAnimationFrame(paint)};resize();addEventListener('resize',()=>{cancelAnimationFrame(raf);resize()},{passive:true});document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible'&&!raf)raf=requestAnimationFrame(paint);else if(document.visibilityState!=='visible'&&raf){cancelAnimationFrame(raf);raf=0}},{passive:true});document.addEventListener('click',e=>{if(e.target.closest('button,a,select,input,label')){ripple={x:e.clientX,y:e.clientY,r:2,a:.24}}},{passive:true});raf=requestAnimationFrame(paint)}}};if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init()})();</script>"""
ABYSS_LAYOUT_REPAIR_CSS = r"""<style id="abyss-layout-repair">
/* Abyss reference-led layout: absolute black, quiet contrast, one section at a time. */
:root{--chart-cpu:#c8cad0;--chart-ram:#8e85b8;--chart-net:#a2b0ba;--ab-bg:#020202;--ab-panel:rgba(13,13,14,.94);--ab-line:rgba(178,181,187,.18);--ab-accent:#b9bbc1;--ab-accent-hi:#f0f0f2;--ab-text:#eeeef0;--ab-muted:#a2a2a7;--ab-glass:rgba(230,230,235,.035);--ab-glow:rgba(180,182,189,.055);--ab-input:rgba(5,5,6,.95)}
html[data-abyss-theme="abyss"]{--ab-bg:#020202;--ab-panel:rgba(13,13,14,.94);--ab-line:rgba(178,181,187,.18);--ab-accent:#b9bbc1;--ab-accent-hi:#f0f0f2;--ab-text:#eeeef0;--ab-muted:#a2a2a7;--ab-glass:rgba(230,230,235,.035);--ab-glow:rgba(180,182,189,.055);--ab-input:rgba(5,5,6,.95)}
html,body{min-height:100%;background-color:#020202!important}
html{scroll-behavior:auto!important;scroll-padding-top:12px}
body{overflow-x:hidden!important;overflow-y:auto!important;background-color:var(--ab-bg)!important;background-image:radial-gradient(ellipse at 22% 8%,rgba(160,163,170,.035),transparent 32%),radial-gradient(ellipse at 82% 76%,rgba(126,128,134,.028),transparent 38%),linear-gradient(145deg,#020202,#070707 58%,#030303)!important;animation:none!important}
body:before{content:"";position:fixed;inset:-5%;z-index:0!important;pointer-events:none;opacity:.36;background-image:linear-gradient(118deg,transparent 0 16%,rgba(200,202,208,.045) 16.08%,transparent 16.24% 43%,rgba(185,188,194,.025) 43.08%,transparent 43.24% 72%,rgba(220,221,225,.035) 72.08%,transparent 72.22%),linear-gradient(164deg,transparent 0 28%,rgba(190,193,199,.027) 28.08%,transparent 28.22% 61%,rgba(210,212,216,.023) 61.08%,transparent 61.25%);background-size:100% 100%;will-change:transform;animation:abyssStreakDrift 34s ease-in-out infinite alternate!important}
body:after{z-index:0!important;opacity:.075}
@keyframes abyssStreakDrift{0%{transform:translate3d(-.7%,-.25%,0)}50%{transform:translate3d(.55%,.4%,0)}100%{transform:translate3d(-.25%,.7%,0)}}
body>*{position:relative;z-index:1}
.app-shell{display:block!important;width:100%!important;max-width:none!important;min-height:100dvh;background:transparent!important}
.workspace{width:100%!important;max-width:1540px!important;margin:0 auto!important;padding:78px clamp(12px,2.4vw,36px) 42px!important;min-width:0}
.sidebar{position:fixed!important;top:0!important;left:0!important;right:auto!important;bottom:0!important;z-index:10011!important;width:min(330px,88vw)!important;height:100dvh!important;overflow-y:auto!important;overscroll-behavior:contain;background:rgba(9,9,10,.97)!important;border-right:1px solid rgba(185,188,194,.2)!important;border-left:0!important;border-radius:0!important;backdrop-filter:blur(16px)!important;-webkit-backdrop-filter:blur(16px)!important;transform:translateX(-105%)!important;transition:transform .22s cubic-bezier(.2,.75,.25,1)!important;box-shadow:18px 0 60px rgba(0,0,0,.32)!important}
.sidebar.open{transform:translateX(0)!important}
#menuToggle{display:inline-flex!important;position:fixed!important;top:14px!important;left:14px!important;right:auto!important;z-index:10021!important;align-items:center!important;justify-content:center!important;gap:9px!important;width:auto!important;min-width:48px!important;min-height:44px!important;margin:0!important;padding:10px 15px!important;border:1px solid rgba(194,197,204,.25)!important;border-radius:14px!important;background:rgba(14,14,15,.93)!important;color:#ececef!important;box-shadow:0 9px 30px rgba(0,0,0,.28)!important;backdrop-filter:blur(12px)!important;-webkit-backdrop-filter:blur(12px)!important;cursor:pointer}
#abyssMenuShade{position:fixed;inset:0;z-index:10010;background:rgba(0,0,0,.56);opacity:0;visibility:hidden;pointer-events:none;transition:opacity .2s ease,visibility .2s ease;backdrop-filter:blur(2px);-webkit-backdrop-filter:blur(2px)}
body.abyss-menu-open #abyssMenuShade{opacity:1;visibility:visible;pointer-events:auto}
body.abyss-menu-open{overflow:hidden}
.nav-item{width:100%;min-height:44px;white-space:normal;line-height:1.5}
.nav-item.active{border-color:rgba(195,198,205,.28)!important;background:rgba(205,207,213,.085)!important;box-shadow:inset 3px 0 #c7c9ce!important}
.top{padding-top:6px}
.section-heading{font-size:clamp(20px,2.2vw,25px)!important}
.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.workspace [data-section-page]{min-width:0;scroll-margin-top:14px}
.workspace .card,.workspace .panel,.workspace .box{background:linear-gradient(145deg,rgba(16,16,17,.96),rgba(8,8,9,.97))!important;border-color:rgba(165,168,175,.16)!important;box-shadow:0 12px 32px rgba(0,0,0,.22),inset 0 1px 0 rgba(255,255,255,.018)!important;backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
.workspace button,.workspace .button-link,.nav-item{backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
.workspace table{width:100%;font-size:13px}
.workspace .client{gap:12px}
.workspace .client-info{min-width:0;overflow-wrap:anywhere}
.workspace input,.workspace select,.workspace textarea{max-width:100%;min-width:0}
.workspace .fields{grid-template-columns:repeat(auto-fit,minmax(min(100%,210px),1fr))}
.workspace .profile-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
.abyss-brand-row{letter-spacing:.12em}
.abyss-logo-svg{display:block;width:48px;height:48px;flex:0 0 48px;filter:drop-shadow(0 0 12px rgba(190,192,199,.13))}
.sidebar .abyss-logo-svg{width:30px;height:30px;flex-basis:30px}
.login-brand .abyss-logo-svg{width:54px;height:54px;flex-basis:54px}
.login-layout{position:relative;display:grid;grid-template-columns:minmax(0,1.05fr) minmax(360px,.95fr);gap:clamp(22px,4vw,64px);align-items:stretch;width:min(1220px,100%);min-height:min(740px,calc(100dvh - 52px));margin:auto;direction:rtl}
.login-visual{position:relative;isolation:isolate;overflow:hidden;display:flex;flex-direction:column;justify-content:center;align-items:flex-start;padding:clamp(28px,5vw,72px);border:1px solid rgba(174,177,184,.12);border-radius:30px;background:linear-gradient(145deg,rgba(13,13,14,.72),rgba(4,4,4,.62));box-shadow:inset 0 1px rgba(255,255,255,.025),0 30px 100px rgba(0,0,0,.26);min-width:0}
.login-visual:before{content:"";position:absolute;inset:-10%;z-index:-1;background:radial-gradient(ellipse at 45% 43%,rgba(185,188,195,.09),transparent 25%),linear-gradient(133deg,transparent 0 37%,rgba(198,200,206,.05) 37.1%,transparent 37.4% 65%,rgba(200,202,208,.035) 65.1%,transparent 65.4%);transform:rotate(-4deg)}
.login-visual .visual-eyebrow{font-size:10px;letter-spacing:.23em;color:#aeb0b6;font-weight:800;direction:ltr}
.login-visual h2{font-size:clamp(30px,4vw,50px);line-height:1.5;letter-spacing:-.035em;margin:24px 0 12px;color:#f0f0f2}
.login-visual p{max-width:410px;line-height:2.05;color:#a7a8ae;font-size:14px}
.login-visual .visual-orbit{width:min(245px,70%);aspect-ratio:1;position:relative;align-self:center;margin:0 auto 40px;border-radius:50%;border:1px solid rgba(185,188,196,.14);box-shadow:0 0 60px rgba(180,183,190,.035),inset 0 0 50px rgba(180,183,190,.025)}
.login-visual .visual-orbit:before,.login-visual .visual-orbit:after{content:"";position:absolute;inset:12%;border:1px solid rgba(188,191,198,.23);border-radius:50%;transform:rotate(-27deg) scaleX(.54)}
.login-visual .visual-orbit:after{inset:22% 35%;border-color:rgba(225,226,230,.48);transform:rotate(21deg) scaleX(1.3);box-shadow:0 0 24px rgba(205,207,214,.08)}
.login-layout>.card{width:100%;max-width:560px;align-self:center;margin:0;padding:clamp(24px,4vw,48px);border-radius:27px;background:linear-gradient(155deg,rgba(17,17,18,.97),rgba(7,7,8,.97))!important;border-color:rgba(179,182,189,.19)!important;box-shadow:0 30px 100px rgba(0,0,0,.37),inset 0 1px rgba(255,255,255,.025)!important;backdrop-filter:none!important}
.login-layout>.card h1{font-size:clamp(28px,3vw,38px);letter-spacing:-.025em}
.login-layout>.card form{margin-top:25px}
.login-layout>.card input{min-height:48px}
.login-layout>.card button{min-height:48px;background:linear-gradient(145deg,#d0d1d5,#9c9ea5)!important;color:#101011!important;border:1px solid rgba(255,255,255,.22)!important;box-shadow:0 10px 28px rgba(180,182,189,.1)!important}
html[data-abyss-theme="angel"] .login-visual,html[data-abyss-theme="paper"] .login-visual{background:linear-gradient(145deg,rgba(255,255,255,.73),rgba(249,246,237,.8));border-color:rgba(166,148,109,.2)}
html[data-abyss-theme="angel"] .login-visual h2,html[data-abyss-theme="paper"] .login-visual h2{color:#3b3529}
html[data-abyss-theme="angel"] .login-visual p,html[data-abyss-theme="paper"] .login-visual p{color:#746d60}
@media(max-width:900px){.login-layout{grid-template-columns:minmax(0,1fr) minmax(310px,.9fr);gap:18px;min-height:calc(100dvh - 36px)}.login-visual{padding:26px}.login-visual .visual-orbit{width:min(190px,70%);margin-bottom:22px}}
@media(max-width:700px){body{overflow:auto!important}.login-layout{display:block;width:min(480px,100%);min-height:0;margin:28px auto 16px;padding:0}.login-visual{display:none}.login-layout>.card{width:100%;max-width:none;padding:24px 20px;border-radius:22px}.login-brand{margin-top:4px}.workspace{padding:70px 12px 30px!important}.stats{grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.stats>.card{padding:13px!important}.workspace>section.card{padding:15px!important}.workspace .profile-grid{grid-template-columns:1fr}.workspace .fields{grid-template-columns:minmax(0,1fr)}.workspace .top .tools{gap:7px}.workspace .top .tools>*{max-width:100%;flex:0 1 auto}#abyssThemeDock.floating{top:14px;right:10px;left:auto;max-width:calc(100vw - 140px)}#abyssThemeSelect{max-width:95px}}
@media(max-width:390px){.stats{grid-template-columns:minmax(0,1fr)}.workspace{padding-inline:10px!important}.workspace .card{padding:12px!important}#menuToggle{top:10px!important;left:10px!important;right:auto!important}#abyssThemeDock.floating{right:10px;left:auto;top:10px}}
@media(hover:none),(pointer:coarse){.workspace .card,.workspace .panel,.workspace .box,.login-layout>.card{backdrop-filter:none!important;-webkit-backdrop-filter:none!important}.workspace button:hover,.nav-item:hover{transform:none!important}}
/* Reference correction: centered login card over a full-screen black, atmospheric background. */
.login-layout{position:relative!important;isolation:isolate!important;display:grid!important;grid-template-columns:minmax(0,1fr)!important;place-items:center!important;align-content:center!important;gap:0!important;width:100%!important;max-width:none!important;min-height:100dvh!important;margin:0!important;padding:30px 14px!important;direction:rtl!important}
.login-visual{position:fixed!important;inset:0!important;z-index:0!important;display:block!important;pointer-events:none!important;padding:0!important;border:0!important;border-radius:0!important;background:transparent!important;box-shadow:none!important;overflow:hidden!important;backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
.login-visual .visual-eyebrow,.login-visual h2,.login-visual p{display:none!important}
.login-visual .visual-orbit{position:absolute!important;top:4%!important;left:4%!important;width:min(56vw,610px)!important;max-width:none!important;aspect-ratio:1!important;margin:0!important;opacity:.21!important;border-color:rgba(184,187,195,.11)!important;box-shadow:0 0 110px rgba(178,181,190,.03),inset 0 0 80px rgba(178,181,190,.02)!important}
.login-visual .visual-orbit:before{inset:10%!important;border-color:rgba(194,196,202,.13)!important}
.login-visual .visual-orbit:after{inset:24% 39%!important;border-color:rgba(218,220,225,.18)!important;box-shadow:none!important}
.login-layout>.card{position:relative!important;z-index:2!important;align-self:center!important;width:min(432px,calc(100vw - 28px))!important;max-width:432px!important;margin:0 auto!important;padding:clamp(24px,4vw,38px)!important;border-radius:25px!important;background:linear-gradient(155deg,rgba(16,16,17,.93),rgba(6,6,7,.96))!important;border-color:rgba(183,186,192,.21)!important;box-shadow:0 30px 100px rgba(0,0,0,.46),inset 0 1px 0 rgba(255,255,255,.025)!important;backdrop-filter:blur(12px)!important;-webkit-backdrop-filter:blur(12px)!important}
.login-layout>.card .login-brand{margin:0 auto 24px!important}
.login-layout>.card .login-brand .abyss-logo-svg{width:58px!important;height:58px!important;flex-basis:58px!important}
.login-layout>.card h1{font-size:clamp(27px,4vw,35px)!important;text-align:center!important;margin-top:10px!important}
.login-layout>.card>p{text-align:center!important}
.login-layout>.card label{margin-top:17px!important}
.login-layout>.card input{min-height:47px!important}
.login-layout>.card button{min-height:48px!important;background:linear-gradient(145deg,#d3d4d8,#9699a1)!important;color:#0a0a0b!important;border:1px solid rgba(255,255,255,.22)!important;box-shadow:0 10px 28px rgba(180,182,189,.08)!important}
.workspace{display:grid!important;grid-template-columns:repeat(12,minmax(0,1fr))!important;gap:15px!important;align-content:start!important}
.workspace>.top{grid-column:1/-1!important;width:100%!important;min-width:0!important;margin:0!important}
.workspace>section{min-width:0!important;margin:0!important;grid-column:1/-1}
.workspace>#overviewStats{grid-column:1/-1!important;display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;gap:13px!important;margin:0!important}
.workspace>#overviewStats>.card{min-width:0!important;margin:0!important;padding:19px!important}
.workspace>#dashboardUsageCard{grid-column:span 8!important;min-width:0!important}
.workspace>#panelHealthCard{grid-column:span 4!important;min-width:0!important;display:flex;align-items:flex-start}
.workspace>#dashboardUsageCard .stats{grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:10px!important}
.workspace>#dashboardUsageCard .stats>.card{min-width:0!important;margin:0!important;padding:13px!important}
.workspace>#usageSparkline{display:block;width:100%;max-width:100%;height:144px;margin-top:10px}.chart-legend{display:flex;gap:15px;flex-wrap:wrap;margin-top:8px;color:var(--ab-muted);font-size:11px}.chart-legend span{display:inline-flex;align-items:center;gap:6px}.chart-legend i{display:inline-block;width:8px;height:8px;border-radius:50%}.chart-legend .cpu{background:var(--chart-cpu,#c8cad0)}.chart-legend .ram{background:var(--chart-ram,#8e85b8)}.chart-legend .net{background:var(--chart-net,#a2b0ba)}
.workspace .section-title{line-height:1.6}
.workspace #panelHealthCard #status{line-height:2!important;overflow-wrap:anywhere}
@media(max-width:980px){
 .workspace>#overviewStats{grid-template-columns:repeat(2,minmax(0,1fr))!important}
 .workspace>#dashboardUsageCard,.workspace>#panelHealthCard{grid-column:1/-1!important}
}
@media(max-width:700px){
 .login-layout{min-height:100svh!important;padding:76px 12px 22px!important}
 .login-layout>.card{width:min(440px,100%)!important;padding:23px 19px!important;border-radius:21px!important}
 .login-visual .visual-orbit{top:5%!important;left:-18%!important;width:84vw!important;opacity:.16!important}
 .workspace{grid-template-columns:minmax(0,1fr)!important;gap:11px!important;padding:72px 11px 26px!important}
 .workspace>.top,.workspace>section,.workspace>#overviewStats,.workspace>#dashboardUsageCard,.workspace>#panelHealthCard{grid-column:1/-1!important}
 .workspace>#overviewStats{grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:9px!important}
 .workspace>#overviewStats>.card{padding:13px!important;min-height:88px}
 .workspace>#dashboardUsageCard .stats{grid-template-columns:repeat(3,minmax(0,1fr))!important}
 .workspace>#dashboardUsageCard .stats>.card{padding:10px 8px!important}
 .workspace #dashboardUsageCard .num{font-size:clamp(18px,5vw,24px)}
 .workspace .top{display:flex;align-items:flex-start;flex-direction:column!important;gap:10px!important}
 .workspace .top .tools{width:100%;display:flex;gap:7px!important;flex-wrap:wrap!important}
 .workspace .top .tools button{flex:1 1 auto!important;width:auto!important}
}
@media(max-width:380px){
 .workspace>#overviewStats{grid-template-columns:minmax(0,1fr)!important}
 .workspace>#dashboardUsageCard .stats{grid-template-columns:repeat(3,minmax(0,1fr))!important}
 .login-layout>.card{padding:21px 16px!important}
}
@media(hover:none),(pointer:coarse){
 .login-layout>.card{backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
 .workspace .card:hover,.workspace button:hover{transform:none!important}
}
/* Low-contrast marble atmosphere: soft smoke veins, never a blue/navy wash. */
/* Angel stays genuinely light: warm ivory, aged gold, and the same restrained composition. */
html[data-abyss-theme="angel"],html[data-abyss-theme="paper"]{--chart-cpu:#9c8859;--chart-ram:#9e9ab1;--chart-net:#718675}
html[data-abyss-theme="angel"] body,html[data-abyss-theme="paper"] body{background-color:#f1eee6!important;background-image:linear-gradient(145deg,#f6f4ee,#e7e1d4 58%,#f4f1e9)!important;color:#332e25!important}
html[data-abyss-theme="angel"] body:before,html[data-abyss-theme="paper"] body:before{opacity:.3!important;background-image:linear-gradient(118deg,transparent 0 16%,rgba(156,132,82,.055) 16.08%,transparent 16.24% 43%,rgba(145,124,79,.035) 43.08%,transparent 43.24% 72%,rgba(160,138,91,.045) 72.08%,transparent 72.22%),linear-gradient(164deg,transparent 0 28%,rgba(160,139,94,.03) 28.08%,transparent 28.22% 61%,rgba(160,139,94,.025) 61.08%,transparent 61.25%)}
html[data-abyss-theme="angel"] body:after,html[data-abyss-theme="paper"] body:after{opacity:.055!important;mix-blend-mode:multiply;background-image:radial-gradient(ellipse at 14% 23%,rgba(157,126,62,.11),transparent 30%),radial-gradient(ellipse at 78% 60%,rgba(171,148,102,.075),transparent 35%),repeating-linear-gradient(137deg,transparent 0 96px,rgba(126,102,55,.02) 97px,transparent 100px 181px)}
html[data-abyss-theme="angel"] .login-visual:before,html[data-abyss-theme="paper"] .login-visual:before{background:radial-gradient(ellipse at 14% 30%,rgba(165,137,79,.105),transparent 34%),radial-gradient(ellipse at 83% 63%,rgba(154,130,82,.075),transparent 32%),linear-gradient(127deg,transparent 0 21%,rgba(180,157,104,.075) 21.1%,transparent 21.45% 48%,rgba(151,130,81,.045) 48.1%,transparent 48.45% 72%,rgba(180,157,104,.045) 72.1%,transparent 72.35%)!important}
html[data-abyss-theme="angel"] .login-visual .visual-orbit,html[data-abyss-theme="paper"] .login-visual .visual-orbit{border-color:rgba(160,131,67,.2)!important;box-shadow:0 0 90px rgba(160,131,67,.045),inset 0 0 70px rgba(160,131,67,.025)!important}
html[data-abyss-theme="angel"] .login-layout>.card,html[data-abyss-theme="paper"] .login-layout>.card{background:linear-gradient(155deg,rgba(255,254,250,.97),rgba(243,239,229,.97))!important;border-color:rgba(166,140,78,.29)!important;color:#302b22!important;box-shadow:0 28px 85px rgba(82,67,37,.13),inset 0 1px rgba(255,255,255,.8)!important}
html[data-abyss-theme="angel"] .login-layout>.card h1,html[data-abyss-theme="paper"] .login-layout>.card h1{color:#312b21!important}
html[data-abyss-theme="angel"] .login-layout>.card .small,html[data-abyss-theme="paper"] .login-layout>.card .small,html[data-abyss-theme="angel"] .login-layout>.card label,html[data-abyss-theme="paper"] .login-layout>.card label{color:#766b54!important}
html[data-abyss-theme="angel"] .login-layout>.card input,html[data-abyss-theme="paper"] .login-layout>.card input{background:rgba(255,255,255,.72)!important;color:#302b22!important;border-color:rgba(155,132,80,.27)!important}
html[data-abyss-theme="angel"] .login-layout>.card button,html[data-abyss-theme="paper"] .login-layout>.card button{background:linear-gradient(145deg,#c5ad73,#a58b4e)!important;color:#17130b!important;border-color:rgba(125,100,48,.25)!important;box-shadow:0 8px 24px rgba(149,121,57,.11)!important}
html[data-abyss-theme="angel"] .workspace .card,html[data-abyss-theme="paper"] .workspace .card,html[data-abyss-theme="angel"] .workspace .panel,html[data-abyss-theme="paper"] .workspace .panel,html[data-abyss-theme="angel"] .workspace .box,html[data-abyss-theme="paper"] .workspace .box{background:linear-gradient(145deg,rgba(255,254,250,.97),rgba(241,237,227,.96))!important;border-color:rgba(164,140,83,.22)!important;color:#332e25!important;box-shadow:0 10px 28px rgba(75,63,37,.075),inset 0 1px rgba(255,255,255,.9)!important}
html[data-abyss-theme="angel"] .workspace .small,html[data-abyss-theme="paper"] .workspace .small{color:#756b58!important}
html[data-abyss-theme="angel"] .workspace input,html[data-abyss-theme="paper"] .workspace input,html[data-abyss-theme="angel"] .workspace select,html[data-abyss-theme="paper"] .workspace select,html[data-abyss-theme="angel"] .workspace textarea,html[data-abyss-theme="paper"] .workspace textarea{background:rgba(255,255,255,.83)!important;color:#302b22!important;border-color:rgba(160,137,84,.3)!important}
html[data-abyss-theme="angel"] .sidebar,html[data-abyss-theme="paper"] .sidebar{background:rgba(246,243,234,.985)!important;border-right:1px solid rgba(164,140,83,.23)!important;color:#332e25!important;box-shadow:18px 0 60px rgba(67,54,29,.12)!important}
html[data-abyss-theme="angel"] .nav-item,html[data-abyss-theme="paper"] .nav-item{color:#4b4538!important}
html[data-abyss-theme="angel"] .nav-item.active,html[data-abyss-theme="paper"] .nav-item.active{background:rgba(175,147,83,.13)!important;border-color:rgba(164,140,83,.25)!important;box-shadow:inset 3px 0 #a38a50!important}
html[data-abyss-theme="angel"] #menuToggle,html[data-abyss-theme="paper"] #menuToggle{background:rgba(250,248,241,.96)!important;color:#3b3529!important;border-color:rgba(164,140,83,.3)!important}

body{display:block!important;place-items:initial!important;padding:0!important}

body:after{opacity:.105!important;mix-blend-mode:screen;background-image:radial-gradient(ellipse at 13% 21%,rgba(195,197,204,.075),transparent 27%),radial-gradient(ellipse at 78% 18%,rgba(145,148,155,.055),transparent 24%),radial-gradient(ellipse at 63% 77%,rgba(168,170,177,.05),transparent 31%),radial-gradient(ellipse at 26% 83%,rgba(130,132,139,.038),transparent 25%),repeating-linear-gradient(137deg,transparent 0 96px,rgba(214,216,221,.015) 97px,transparent 100px 181px);background-size:100% 100%}
.login-visual:before{content:""!important;position:absolute!important;inset:-8%!important;z-index:0!important;pointer-events:none!important;opacity:.88!important;background:radial-gradient(ellipse at 14% 30%,rgba(186,189,196,.09),transparent 34%),radial-gradient(ellipse at 83% 63%,rgba(126,128,136,.065),transparent 32%),radial-gradient(ellipse at 52% 46%,rgba(130,132,139,.035),transparent 42%),linear-gradient(127deg,transparent 0 21%,rgba(220,222,227,.055) 21.1%,transparent 21.45% 48%,rgba(190,192,199,.035) 48.1%,transparent 48.45% 72%,rgba(225,226,230,.035) 72.1%,transparent 72.35%),linear-gradient(163deg,transparent 0 37%,rgba(200,202,208,.035) 37.1%,transparent 37.4% 69%,rgba(170,172,180,.035) 69.1%,transparent 69.4%);background-size:100% 100%;animation:abyssStreakDrift 34s ease-in-out infinite alternate!important}
.login-visual .visual-orbit{z-index:1!important}
@media(prefers-reduced-motion:reduce){body:before{animation:none!important}#abyssParticleCanvas{display:none!important}*,*:before,*:after{transition:none!important;animation:none!important}}

/* Reference-led finishing pass: split desktop login, eclipse/ray mark, and compact reusable page grids. */
.login-layout{display:grid!important;grid-template-columns:minmax(0,1fr) minmax(350px,.96fr)!important;place-items:stretch!important;align-content:stretch!important;width:min(1380px,100%)!important;max-width:none!important;min-height:100svh!important;margin:0 auto!important;padding:clamp(22px,4vw,58px)!important;gap:clamp(24px,4.2vw,72px)!important;direction:ltr!important}
.login-visual{position:relative!important;inset:auto!important;z-index:1!important;display:flex!important;pointer-events:auto!important;flex-direction:column!important;justify-content:center!important;align-items:center!important;text-align:center!important;min-width:0!important;padding:24px!important;border:0!important;border-radius:0!important;background:transparent!important;box-shadow:none!important;overflow:visible!important;direction:ltr!important}
.login-visual:before{content:""!important;position:absolute!important;inset:-8%!important;z-index:-1!important;pointer-events:none!important;opacity:.9!important;background:radial-gradient(ellipse at 48% 45%,rgba(188,190,197,.09),transparent 33%),radial-gradient(ellipse at 15% 20%,rgba(130,132,140,.035),transparent 35%),linear-gradient(133deg,transparent 0 35%,rgba(205,207,214,.035) 35.1%,transparent 35.35% 65%,rgba(205,207,214,.025) 65.1%,transparent 65.35%)!important}
.login-visual .visual-eyebrow,.login-visual h2,.login-visual p{display:block!important}
.login-visual .visual-eyebrow{direction:ltr!important;font-size:11px!important;letter-spacing:.24em!important;color:var(--ab-muted)!important}
.login-visual h2{margin:24px 0 5px!important;font-size:clamp(28px,3vw,42px)!important;line-height:1.45!important;letter-spacing:.12em!important;color:var(--ab-text)!important;direction:ltr!important}
.login-visual p{max-width:100%!important;margin:5px 0 0!important;color:var(--ab-muted)!important;font-size:11px!important;letter-spacing:.14em!important;line-height:1.8!important;direction:ltr!important}
.login-visual .visual-orbit{position:relative!important;top:auto!important;left:auto!important;width:min(340px,78%)!important;max-width:340px!important;aspect-ratio:1!important;align-self:center!important;margin:0 auto 14px!important;border:1px solid rgba(190,192,199,.14)!important;border-radius:50%!important;opacity:.98!important;background:radial-gradient(circle at center,#020202 0 11%,rgba(4,4,5,.98) 11.8% 12.8%,transparent 13.5%),repeating-conic-gradient(from 0deg,rgba(208,210,216,.38) 0deg .36deg,transparent .7deg 3deg)!important;box-shadow:0 0 80px rgba(188,190,197,.055),inset 0 0 38px rgba(188,190,197,.035)!important;mask-image:radial-gradient(circle,#000 0 65%,rgba(0,0,0,.78) 76%,transparent 100%)!important}
.login-visual .visual-orbit:before{inset:12%!important;border:1px solid rgba(199,201,207,.17)!important;box-shadow:0 0 34px rgba(185,187,195,.04)!important;background:transparent!important}
.login-visual .visual-orbit:after{inset:39%!important;border:1px solid rgba(215,216,222,.2)!important;background:#020202!important;box-shadow:0 0 25px rgba(0,0,0,.9)!important;transform:none!important}
.login-layout>.card{position:relative!important;z-index:2!important;align-self:center!important;justify-self:center!important;width:min(460px,100%)!important;max-width:460px!important;margin:0!important;direction:rtl!important}
.login-layout>.card .login-brand{justify-content:center!important}
@media(max-width:900px){.login-layout{grid-template-columns:minmax(0,1fr) minmax(300px,.95fr)!important;gap:18px!important;padding:22px!important}.login-visual{padding:10px!important}.login-visual .visual-orbit{width:min(280px,82%)!important}}
@media(max-width:700px){.login-layout{display:grid!important;grid-template-columns:minmax(0,1fr)!important;width:100%!important;min-height:100svh!important;padding:76px 12px 22px!important;gap:0!important}.login-visual{display:none!important}.login-layout>.card{width:min(440px,100%)!important;max-width:440px!important;padding:23px 19px!important;border-radius:21px!important}}
@media(prefers-reduced-motion:reduce){.login-visual .visual-orbit{animation:none!important}}
/* Dashboard detail pages share the same black glass, restrained silver highlight, and responsive grid. */
.workspace .reference-page-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.workspace .reference-page-head .small{max-width:780px;line-height:1.9}
.workspace .reference-page-head button{width:auto;min-width:120px}
.server-identity{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:14px 0;padding:17px 19px;border:1px solid var(--ab-line);border-radius:16px;background:var(--ab-glass)}
.server-identity strong{font-size:clamp(17px,2vw,23px);letter-spacing:.015em;overflow-wrap:anywhere}
.server-grid,.protocol-catalog,.report-profiles{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}
.server-state,.protocol-state,.report-state{min-width:0;padding:16px;border:1px solid var(--ab-line);border-radius:15px;background:var(--ab-panel);box-shadow:0 12px 30px rgba(0,0,0,.12)}
.server-state .state-title,.protocol-state .state-title,.report-state .state-title{display:flex;justify-content:space-between;align-items:center;gap:10px;font-size:13px;font-weight:750}
.server-state strong,.protocol-state strong,.report-state strong{display:block;margin:11px 0 6px;font-size:18px;overflow-wrap:anywhere}
.state-chip{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;border:1px solid var(--ab-line);border-radius:999px;font-size:10px;white-space:nowrap}
.state-chip:before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;box-shadow:0 0 10px currentColor}
.state-chip.good{color:#73cba0}.state-chip.bad{color:#e48e8e}.state-chip.neutral{color:var(--ab-muted)}
.protocol-state{display:grid;align-content:start;gap:7px}
.protocol-state .protocol-meta{display:flex;flex-wrap:wrap;gap:6px}
.protocol-state .protocol-meta span{display:inline-block;padding:5px 8px;border:1px solid var(--ab-line);border-radius:8px;color:var(--ab-muted);font-size:10px;overflow-wrap:anywhere}
.protocol-state .protocol-switch{display:flex;align-items:center;justify-content:space-between;gap:10px;padding-top:10px;border-top:1px solid var(--ab-line);font-size:12px}
.protocol-state .protocol-switch input{width:18px;min-height:18px;accent-color:var(--ab-accent);cursor:pointer}
.protocol-state .experimental-label{color:#d7b87a;font-size:10px}
.report-summary{padding:15px;border:1px solid var(--ab-line);border-radius:15px;background:var(--ab-glass);line-height:1.9;margin-bottom:14px}
.report-issues{display:grid;gap:8px;margin:10px 0 18px}
.report-issue{padding:11px 13px;border:1px solid var(--ab-line);border-radius:11px;background:var(--ab-panel);line-height:1.75;overflow-wrap:anywhere}
.report-issue.good{border-color:rgba(115,203,160,.24)}.report-issue.bad{border-color:rgba(228,142,142,.34)}
.report-events{display:grid;gap:8px;margin-top:10px}
.report-event{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:7px 14px;padding:11px 12px;border:1px solid var(--ab-line);border-radius:11px;background:var(--ab-panel);min-width:0}
.report-event .event-message{overflow-wrap:anywhere}.report-event .event-meta{font-size:10px;color:var(--ab-muted);white-space:nowrap}
@media(max-width:980px){.server-grid,.protocol-catalog,.report-profiles{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:700px){.server-grid,.protocol-catalog,.report-profiles{grid-template-columns:minmax(0,1fr)}.server-state,.protocol-state,.report-state{padding:14px}.report-event{grid-template-columns:minmax(0,1fr)}.report-event .event-meta{white-space:normal}.server-identity{align-items:flex-start;flex-direction:column}}
html[data-abyss-theme="angel"] .server-state,html[data-abyss-theme="angel"] .protocol-state,html[data-abyss-theme="angel"] .report-state,html[data-abyss-theme="angel"] .report-issue,html[data-abyss-theme="angel"] .report-event{background:rgba(255,254,250,.91);box-shadow:0 10px 28px rgba(74,60,33,.05)}

.login-input-wrap{position:relative!important;display:flex!important;align-items:center!important;min-width:0!important;margin:0!important}
.login-input-wrap input{width:100%!important;padding-left:48px!important;padding-right:13px!important}
.login-input-icon{position:absolute!important;z-index:2!important;left:15px!important;top:50%!important;transform:translateY(-50%)!important;color:var(--ab-muted)!important;pointer-events:none!important;font-size:15px!important;line-height:1!important}
.login-password-toggle{position:absolute!important;z-index:3!important;left:5px!important;top:50%!important;transform:translateY(-50%)!important;width:36px!important;min-width:36px!important;height:36px!important;min-height:36px!important;margin:0!important;padding:0!important;border:1px solid transparent!important;border-radius:9px!important;background:transparent!important;color:var(--ab-muted)!important;box-shadow:none!important;font-size:15px!important;line-height:1!important}
.login-password-toggle:hover{transform:translateY(-50%)!important;background:var(--ab-glass)!important;filter:none!important}

.users-search-actions{display:flex;align-items:center;gap:8px;min-width:min(100%,300px);flex-wrap:wrap}
.users-search-actions input{flex:1 1 170px;min-width:0}
.users-search-actions button{flex:0 0 auto;width:auto;min-height:40px;margin:0}
.dashboard-component-list{display:grid;gap:8px;margin-top:13px}
.dashboard-component{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:9px 10px;border:1px solid var(--ab-line);border-radius:10px;background:var(--ab-glass);font-size:12px}
.dashboard-component .component-state{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.dashboard-component .component-state:before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 8px currentColor}
.dashboard-component .component-state.good{color:#73cba0}
.dashboard-component .component-state.bad{color:#e48e8e}
.server-table-wrap{width:100%;max-width:100%;overflow-x:auto;border:1px solid var(--ab-line);border-radius:14px;margin:12px 0 18px}
.workspace table.server-table{display:table!important;width:100%;min-width:560px;border-collapse:collapse;overflow:visible;background:transparent!important}
.server-table th,.server-table td{padding:13px 12px;text-align:right;white-space:nowrap;border-bottom:1px solid var(--ab-line);font-size:12px}
.server-table th{font-weight:650;color:var(--ab-muted);background:var(--ab-glass)}
.server-table tbody tr:last-child td{border-bottom:0}
.server-table td button{margin:0;padding:7px 10px;min-height:34px;width:auto;white-space:nowrap}
html[data-abyss-theme="angel"] .dashboard-component,html[data-abyss-theme="angel"] .server-table th{background:rgba(255,254,250,.85)}
@media(max-width:700px){.users-search-actions{width:100%;min-width:0}.users-search-actions button{flex:1 1 100%}.dashboard-component{font-size:11px}.server-table th,.server-table td{padding:11px 9px}}

.top .tools{align-items:center!important;gap:8px!important}
.top-tools-search{width:clamp(145px,18vw,230px)!important;min-width:130px!important;height:39px!important;min-height:39px!important;margin:0!important;padding:9px 12px!important;border:1px solid var(--ab-line)!important;border-radius:12px!important;background:var(--ab-glass)!important;color:var(--ab-text)!important;font-size:12px!important}
.toolbar-icon{display:inline-grid!important;place-items:center!important;flex:0 0 38px!important;width:38px!important;min-width:38px!important;height:38px!important;min-height:38px!important;margin:0!important;padding:0!important;border:1px solid var(--ab-line)!important;border-radius:12px!important;background:var(--ab-glass)!important;color:var(--ab-text)!important;font-size:15px!important}
.toolbar-icon svg{width:17px;height:17px;display:block}
.account-badge{display:inline-flex;align-items:center;gap:8px;min-width:0;padding:5px 8px;border:1px solid var(--ab-line);border-radius:12px;background:var(--ab-glass);color:var(--ab-text)}
.account-avatar{display:grid;place-items:center;flex:0 0 30px;width:30px;height:30px;border:1px solid var(--ab-line);border-radius:50%;color:var(--ab-accent);font-size:16px}
.account-copy{display:grid;gap:2px;min-width:0}.account-copy b{max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px}.account-copy small{font-size:9px;white-space:nowrap}
#panelHelpDialog{width:min(560px,calc(100vw - 24px));max-width:560px;padding:20px;border:1px solid var(--ab-line);border-radius:20px;background:var(--ab-bg);color:var(--ab-text)}
.help-dialog-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:14px}
.help-dialog-grid article{padding:13px;border:1px solid var(--ab-line);border-radius:13px;background:var(--ab-glass)}
.help-dialog-grid article b{font-size:12px;color:var(--ab-accent)}.help-dialog-grid article p{margin:7px 0 0;line-height:1.8}
html[data-abyss-theme="angel"] .top-tools-search,html[data-abyss-theme="angel"] .toolbar-icon,html[data-abyss-theme="angel"] .account-badge,html[data-abyss-theme="angel"] .help-dialog-grid article{background:rgba(255,254,250,.82)!important}
@media(max-width:700px){.top .tools{display:flex!important;align-items:center;gap:7px!important}.top-tools-search{width:100%!important;min-width:0!important;flex:1 1 100%!important;order:-1}.account-badge{flex:1 1 auto;justify-content:center}.account-copy b{max-width:90px}.help-dialog-grid{grid-template-columns:minmax(0,1fr)}}

.login-layout>.card form>label[for="username"],.login-layout>.card form>label[for="password"]{position:absolute!important;width:1px!important;height:1px!important;padding:0!important;margin:-1px!important;overflow:hidden!important;clip:rect(0,0,0,0)!important;white-space:nowrap!important;border:0!important}
.login-layout>.card .login-input-wrap{margin-top:12px!important}
.login-layout>.card .login-input-wrap input::placeholder{color:var(--ab-muted)!important;opacity:.95}
.login-extra-row{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:13px;font-size:11px}
.login-extra-row .remember-option{display:flex!important;align-items:center;gap:8px;margin:0!important;color:var(--ab-muted);cursor:pointer}
.login-extra-row .remember-option input{width:15px!important;min-width:15px!important;height:15px!important;min-height:15px!important;margin:0!important;padding:0!important;accent-color:var(--ab-accent);cursor:pointer}
.login-extra-row a{color:var(--ab-muted);text-decoration:none;border-bottom:1px solid var(--ab-line);padding-bottom:2px}
.login-extra-row a:hover{color:var(--ab-text);border-color:var(--ab-accent)}
#loginHelpDialog{width:min(440px,calc(100vw - 24px));max-width:440px;padding:20px;border:1px solid var(--ab-line);border-radius:20px;background:var(--ab-bg);color:var(--ab-text)}

/* Reference login eclipse: a dark solar disc with fine monochrome corona rays. */
.login-visual{background-color:#030303!important;background-image:radial-gradient(ellipse at 50% 50%,rgba(230,231,234,.045),transparent 48%),radial-gradient(1px 1px at 12% 16%,rgba(235,236,239,.8) 98%,transparent),radial-gradient(1px 1px at 81% 23%,rgba(235,236,239,.65) 98%,transparent),radial-gradient(1px 1px at 74% 82%,rgba(235,236,239,.55) 98%,transparent),radial-gradient(1px 1px at 26% 77%,rgba(235,236,239,.5) 98%,transparent),linear-gradient(145deg,#050505,#010101 68%,#070707)!important;background-size:100% 100%,310px 260px,370px 300px,290px 330px,410px 350px,100% 100%!important}
.login-visual .visual-orbit{border:0!important;box-shadow:none!important;background:repeating-conic-gradient(from -4deg at 50% 50%,rgba(214,216,221,.26) 0deg .22deg,transparent .24deg 3.4deg);filter:drop-shadow(0 0 18px rgba(220,222,226,.07));}
.login-visual .visual-orbit:before{inset:0!important;border:0!important;border-radius:50%!important;transform:none!important;background:radial-gradient(circle at 50% 50%,#000 0 15.5%,rgba(0,0,0,.97) 16% 18%,transparent 18.7%);box-shadow:inset 0 0 32px rgba(0,0,0,.95),0 0 0 1px rgba(235,236,239,.08);}
.login-visual .visual-orbit:after{inset:13%!important;border:1px solid rgba(220,222,226,.14)!important;border-radius:50%!important;transform:none!important;box-shadow:0 0 26px rgba(225,226,230,.08),inset 0 0 22px rgba(220,222,226,.035)!important;background:transparent!important;}
.login-visual .visual-eyebrow{letter-spacing:.25em}
@media(max-width:700px){.login-visual{display:none!important}}

/* Desktop reference layout: persistent left rail; drawer only on mobile. */
@media(min-width:851px){
 #menuToggle{display:none!important} #abyssMenuShade{display:none!important}
 .app-shell{display:block!important;min-height:100vh!important}
 .sidebar{position:fixed!important;left:0!important;right:auto!important;top:0!important;bottom:0!important;width:248px!important;height:100dvh!important;max-height:100dvh!important;transform:translateX(0)!important;visibility:visible!important;overflow-y:auto!important;border-right:1px solid rgba(185,188,194,.18)!important;padding:22px 14px!important;z-index:100!important}
 .workspace{width:calc(100% - 248px)!important;max-width:none!important;margin:0 0 0 248px!important;padding:28px clamp(18px,2vw,34px) 42px!important;min-width:0!important}
 .workspace .top{display:flex;align-items:center;gap:18px;flex-wrap:wrap;padding-top:0!important;margin-bottom:22px}
 .workspace .top .abyss-brand-row{margin-right:auto}
 .workspace .top .section-heading{flex:1 0 100%;margin:8px 0 0}
 .workspace .top .tools{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
 .stats{grid-template-columns:repeat(4,minmax(0,1fr))!important;gap:12px!important}
 .workspace [data-section-page],.workspace .card,.workspace .panel,.workspace .box{min-width:0}
}
@media(min-width:851px) and (max-width:1150px){
 .sidebar{width:220px!important}
 .workspace{width:calc(100% - 220px)!important;margin-left:220px!important;padding-inline:18px!important}
 .stats{grid-template-columns:repeat(2,minmax(0,1fr))!important}
}
@media(max-width:850px){
 #menuToggle{display:inline-flex!important}
 .sidebar{transform:translateX(-105%)!important;visibility:visible!important}
 .sidebar.open{transform:translateX(0)!important}
 .workspace{width:100%!important;max-width:none!important;margin:0!important}
}
@media(prefers-reduced-motion:reduce){.sidebar,#menuToggle,#abyssMenuShade{transition:none!important}}
</style>"""
ABYSS_LAYOUT_REPAIR_JS = r"""<script id="abyss-layout-repair-js">
(()=> {
  const init=()=>{
    const sidebar=document.getElementById('sidebar');
    const menu=document.getElementById('menuToggle');
    if(!sidebar || !menu) return;
    let shade=document.getElementById('abyssMenuShade');
    if(!shade){shade=document.createElement('div');shade.id='abyssMenuShade';shade.setAttribute('aria-hidden','true');document.body.appendChild(shade);}
    const setOpen=(open)=>{
      sidebar.classList.toggle('open',open);
      document.body.classList.toggle('abyss-menu-open',open);
      menu.setAttribute('aria-expanded',String(open));
      menu.setAttribute('aria-label',open?'بستن منو':'باز کردن منو');
      menu.innerHTML=open?'✕ <span>بستن</span>':'☰ <span>منو</span>';
    };
    window.toggleSidebar=()=>setOpen(!sidebar.classList.contains('open'));
    menu.removeAttribute('onclick');menu.addEventListener('click',e=>{e.preventDefault();setOpen(!sidebar.classList.contains('open'));});
    shade.addEventListener('click',()=>setOpen(false));
    sidebar.querySelectorAll('[data-nav]').forEach(item=>item.addEventListener('click',()=>setOpen(false)));
    document.addEventListener('keydown',e=>{if(e.key==='Escape')setOpen(false);});
    const original=window.showSection;
    if(typeof original==='function'){
      window.showSection=(name)=>{original(name);setOpen(false);};
      original('dashboard');
    } else {
      document.querySelectorAll('[data-section-page]').forEach(el=>el.classList.toggle('nav-hidden',el.dataset.sectionPage!=='dashboard'));
    }
    menu.style.display='inline-flex';
  };
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init();
})();
</script>"""
LOGIN = LOGIN.replace('<body><main class="card">','<body><div class="login-layout"><aside class="login-visual" aria-label="Abyss Tunnel"><div class="visual-orbit" aria-hidden="true"></div><div class="visual-eyebrow">ABYSS TUNNEL</div><h2>• I T A •</h2><p>Secure · Private · Unlimited</p></aside><main class="card">').replace('</form></main></body>','</form></main><dialog id="loginHelpDialog"><div class="modal-top"><div><h2>بازیابی رمز عبور</h2><div class="small">راهنمای دسترسی امن</div></div><button type="button" onclick="document.getElementById(\'loginHelpDialog\').close()" aria-label="بستن">✕</button></div><p class="small">بازیابی از طریق ایمیل در این استقرار پیکربندی نشده است. اگر رمز عبور را تغییر داده‌ای و فراموش کرده‌ای، از مالک پنل برای بازنشانی امن کمک بگیر.</p></dialog></div></body>')
ABYSS_FINAL_LAYOUT_CSS = r"""<style id="abyss-final-layout">
/* Final cascade layer: deliberately last so the reference layout wins over legacy inline templates. */
.login-layout{position:relative!important;isolation:isolate!important;display:grid!important;grid-template-columns:minmax(0,1fr)!important;place-items:center!important;align-content:center!important;gap:0!important;width:100%!important;max-width:none!important;min-height:100dvh!important;margin:0!important;padding:28px 14px!important;direction:rtl!important}
.login-visual{position:fixed!important;inset:0!important;z-index:0!important;display:block!important;pointer-events:none!important;padding:0!important;border:0!important;border-radius:0!important;background:transparent!important;box-shadow:none!important;overflow:hidden!important;backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
.login-visual .visual-eyebrow,.login-visual h2,.login-visual p{display:none!important}
.login-visual .visual-orbit{position:absolute!important;top:4%!important;left:4%!important;width:min(56vw,610px)!important;max-width:none!important;aspect-ratio:1!important;margin:0!important;opacity:.21!important;pointer-events:none!important}
.login-layout>.card{position:relative!important;z-index:2!important;width:min(100%,430px)!important;max-width:430px!important;margin:0 auto!important;justify-self:center!important;align-self:center!important}
.login-layout:before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background:radial-gradient(circle at 50% 42%,rgba(205,207,213,.075),transparent 38%),radial-gradient(circle at 50% 50%,#050505 0,#020202 72%)}
[data-section-page].nav-hidden{display:none!important}
[data-section-page]:not(.nav-hidden){display:block}
#abyssMenuShade{position:fixed;inset:0;z-index:49;background:rgba(0,0,0,.62);opacity:0;pointer-events:none;transition:opacity .2s ease}
body.abyss-menu-open #abyssMenuShade{opacity:1;pointer-events:auto}
@media(max-width:850px){.login-layout{padding:20px 14px!important}.login-layout>.card{width:min(100%,420px)!important}.login-visual .visual-orbit{width:90vw!important;left:-20vw!important;top:-8%!important;opacity:.15!important}}
/* Ensure the section state wins over legacy display:grid!important rules. */
html body .workspace [data-section-page].nav-hidden,
html body .workspace .stats[data-section-page].nav-hidden,
html body .workspace section.card[data-section-page].nav-hidden{display:none!important;visibility:hidden!important;pointer-events:none!important}
html body .workspace [data-section-page]:not(.nav-hidden){visibility:visible}
html body .workspace #overviewStats[data-section-page="dashboard"]{display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important}
html body .workspace #dashboardUsageCard[data-section-page="dashboard"]{display:block!important;width:100%;max-width:100%;margin-top:16px}
html body .workspace #dashboardUsageCard>.stats{display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important}
html body .workspace #dashboardUsageCard>.stats>.card{min-width:0!important}
html body .workspace #dashboardUsageCard canvas{display:block;width:100%!important;max-width:100%!important}
@media(max-width:850px){
 html body .workspace #overviewStats[data-section-page="dashboard"]{grid-template-columns:repeat(2,minmax(0,1fr))!important}
 html body .workspace #dashboardUsageCard>.stats{grid-template-columns:repeat(3,minmax(0,1fr))!important}
}
@media(min-width:851px) and (max-width:1150px){html body .workspace #overviewStats[data-section-page="dashboard"]{grid-template-columns:repeat(2,minmax(0,1fr))!important}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;animation-duration:.01ms!important;transition-duration:.01ms!important}}
/* Final screenshot-driven repairs: keep the dashboard health panel readable and prevent mobile overflow. */
:root{--ab-mint:#a9b9b0!important;--abyss-mint:#a9b9b0!important}
html,body{max-width:100%;overflow-x:clip!important}
input[type=checkbox],input[type=radio],.profile-option input{accent-color:#a9b9b0!important}
.login-layout>.card{border-top-color:rgba(205,208,214,.22)!important}
.login-layout>.card button{background:linear-gradient(145deg,#c8c9cc,#96989e)!important;color:#09090a!important}
.workspace>#dashboardUsageCard{grid-column:1/-1!important;width:100%!important}
.workspace>#panelHealthCard{grid-column:1/-1!important;width:100%!important;display:block!important;min-width:0!important;overflow:hidden!important}
.workspace>#panelHealthCard #status{display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;gap:10px!important;width:100%!important;min-width:0!important}
.workspace>#panelHealthCard #status>*{min-width:0!important;max-width:100%!important;overflow-wrap:anywhere!important;white-space:normal!important}
.workspace>#panelHealthCard .section-title,.workspace>#panelHealthCard .small{max-width:100%!important;overflow-wrap:anywhere!important}
.workspace>#dashboardUsageCard>.stats{margin-top:14px!important}
.workspace>#dashboardUsageCard>.stats>.card{border-radius:16px!important}
@media(max-width:850px){
 body:not(.abyss-menu-open) .sidebar{transform:translateX(-110%)!important;visibility:hidden!important;pointer-events:none!important}
 body.abyss-menu-open .sidebar{transform:translateX(0)!important;visibility:visible!important;pointer-events:auto!important}
 .workspace{width:100%!important;max-width:100%!important;min-width:0!important;margin:0!important;overflow-x:clip!important}
 .workspace .top,.workspace .top>*{max-width:100%!important;min-width:0!important}
 .workspace .abyss-brand-row{max-width:100%!important;overflow:hidden!important}
 .workspace .brand-name{min-width:0!important;max-width:100%!important}
 .workspace .top .tools{min-width:0!important}
 .workspace .top .tools>*{min-width:0!important;max-width:100%!important}
 .workspace>#panelHealthCard #status{grid-template-columns:repeat(2,minmax(0,1fr))!important}
}
@media(max-width:390px){
 .workspace{padding-left:10px!important;padding-right:10px!important}
 .workspace .brand-name b{font-size:14px!important;letter-spacing:.08em!important}
 .workspace .top .tools button{flex:1 1 calc(33.333% - 7px)!important}
 .workspace>#panelHealthCard #status{grid-template-columns:repeat(2,minmax(0,1fr))!important}
}

</style>"""
LOGIN = LOGIN.replace("</head>", ABYSS_THEME_CSS + ABYSS_THEME_POLISH_CSS + ABYSS_LAYOUT_REPAIR_CSS + "</head>").replace("</body>", ABYSS_THEME_JS + ABYSS_LAYOUT_REPAIR_JS + ABYSS_FINAL_LAYOUT_CSS + "</body>")
DASH = DASH.replace("</head>", ABYSS_THEME_CSS + ABYSS_THEME_POLISH_CSS + ABYSS_LAYOUT_REPAIR_CSS + "</head>").replace("</body>", ABYSS_THEME_JS + ABYSS_LAYOUT_REPAIR_JS + ABYSS_FINAL_LAYOUT_CSS + "</body>")

@app.get("/dashboard.js",response_class=PlainTextResponse)
async def dashboard_js():
    return PlainTextResponse(DASH_JS,media_type="application/javascript",headers={"Cache-Control":"no-store"})

@app.get("/",response_class=HTMLResponse)
async def home(r:Request):
    if r.session.get("admin") is True or r.session.get("reseller_id"):
        return HTMLResponse(DASH,headers={"Cache-Control":"no-store, max-age=0","Pragma":"no-cache","Vary":"Cookie"})
    return RedirectResponse("/login",303)
@app.get("/login",response_class=HTMLResponse)
async def login_page(r:Request):
    t=secrets.token_urlsafe(24); r.session["login_csrf"]=t
    return HTMLResponse(LOGIN.replace("{{ERROR}}","").replace("{{CSRF}}",t))
@app.post("/login")
async def login(r:Request,username:str=Form(...),password:str=Form(...)):
    f=await r.form(); a=str(f.get("csrf_token","")); b=str(r.session.get("login_csrf",""))
    if not a or not b or not hmac.compare_digest(a,b):
        token=secrets.token_urlsafe(24); r.session["login_csrf"]=token
        return HTMLResponse(LOGIN.replace("{{ERROR}}","نشست منقضی شده؛ دوباره تلاش کن.").replace("{{CSRF}}",token),status_code=403)
    ip=r.client.host if r.client else "unknown"
    if not rate_check(r,"login:"+ip):
        token=secrets.token_urlsafe(24); r.session["login_csrf"]=token
        return HTMLResponse(LOGIN.replace("{{ERROR}}","تلاش‌های زیادی انجام شده؛ پنج دقیقه صبر کن.").replace("{{CSRF}}",token),status_code=429)
    if len(username)>64 or len(password)>256:
        row=None; account_type="admin"
    else:
        with db() as c:
            row=c.execute("SELECT id,username,password_hash,role,enabled,password_changed_at FROM panel_admins WHERE username=?",(username.strip(),)).fetchone()
            account_type="admin"
            if not row:
                row=c.execute("SELECT id,password_hash,enabled FROM resellers WHERE username=?",(username.strip(),)).fetchone()
                account_type="reseller"
    if not row or not row["enabled"] or not verify_password(password,row["password_hash"]):
        event("WARNING","Rejected administrator sign-in attempt.")
        token=secrets.token_urlsafe(24); r.session["login_csrf"]=token
        return HTMLResponse(LOGIN.replace("{{ERROR}}","نام کاربری یا رمز عبور اشتباه است.").replace("{{CSRF}}",token),status_code=401)
    r.session.clear(); r.session["csrf"]=secrets.token_urlsafe(32); r.session["remember_me"]=str(f.get("remember_me","")).strip().lower() in {"on","true","1","yes"}
    if account_type=="admin":
        r.session["admin"]=True; r.session["admin_id"]=row["id"]; r.session["admin_username"]=row["username"]; r.session["admin_role"]=row["role"]; r.session["admin_password_changed_at"]=row["password_changed_at"]
        event("INFO",f"Administrator signed in as {row['username']} ({row['role']}).")
    else:
        r.session["reseller_id"]=row["id"]; event("INFO",f"Reseller {username!r} signed in.")
    return RedirectResponse("/",303)
@app.get("/logout")
async def logout(r:Request): r.session.clear(); return RedirectResponse("/login",303)
@app.get("/api/overview")
async def overview(r:Request):
    require_admin(r); owner=owner_id_for(r)
    with db() as c:
        if owner is None:
            total=c.execute("SELECT COUNT(*) n FROM clients").fetchone()["n"]; active=c.execute("SELECT COUNT(*) n FROM clients WHERE enabled=1").fetchone()["n"]
            children=[dict(x) for x in c.execute("SELECT id,username,quota_bytes,enabled,created_at,parent_id FROM resellers ORDER BY created_at DESC")]
        else:
            total=c.execute("SELECT COUNT(*) n FROM clients WHERE owner_id=?",(owner,)).fetchone()["n"]; active=c.execute("SELECT COUNT(*) n FROM clients WHERE owner_id=? AND enabled=1",(owner,)).fetchone()["n"]
            children=[dict(x) for x in c.execute("SELECT id,username,quota_bytes,enabled,created_at,parent_id FROM resellers WHERE parent_id=? ORDER BY created_at DESC",(owner,))]
        events=[dict(x) for x in c.execute("SELECT at,level,message FROM events ORDER BY id DESC LIMIT 8")] if owner is None else []
    for child in children:
        child["allocated_bytes"]=reseller_allocated_for(child["id"])
        child["remaining_bytes"]=child["quota_bytes"]-child["allocated_bytes"]
    remaining=None if owner is None else reseller_remaining(owner)
    return {"csrf":r.session.get("csrf",""),"role":"root" if is_root(r) else ("reseller" if not r.session.get("admin") else r.session.get("admin_role","admin")),"user":{"username":r.session.get("admin_username", "reseller" if not r.session.get("admin") else "admin"),"role":r.session.get("admin_role","owner") if r.session.get("admin") else "reseller"},"remaining_bytes":remaining,"total":total,"active":active,"clients":get_clients(owner_id=owner,scoped=owner is not None),"resellers":children,"events":events,"xray":{"installed":Path(XRAY_BIN).exists(),"running":bool(xray_proc and xray_proc.poll() is None)}}
@app.get("/api/settings")
async def read_settings(r:Request):
    require_admin(r)
    flags=get_profile_flags()
    return {"profiles":[{"key":p["key"],"label":p["label"],"enabled":flags[p["key"]],"protocol":p.get("protocol","vless"),"network":p.get("network","—"),"path":p.get("path","—"),"mode":p.get("mode"),"port":p.get("port"),"experimental":bool(p.get("experimental",False))} for p in PROFILES]}

@app.patch("/api/settings/profiles")
async def update_profile_settings(r:Request):
    require_role(r,"owner","admin"); require_csrf(r); body=await r.json()
    profiles=body.get("profiles") if isinstance(body,dict) else None
    keys={p["key"] for p in PROFILES}
    if not isinstance(profiles,dict) or not profiles or set(profiles)-keys or any(not isinstance(v,bool) for v in profiles.values()):
        raise HTTPException(422,"profiles must contain supported profile keys and boolean values")
    current=get_profile_flags()
    updated={**current,**profiles}
    if not any(updated.values()): raise HTTPException(422,"At least one connection profile must remain enabled")
    with db() as c:
        previous={row["key"]:row["value"] for row in c.execute("SELECT key,value FROM settings WHERE key LIKE 'profile:%'")}
        for key,value in profiles.items():
            c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",("profile:"+key,"1" if value else "0"))
    try:
        await start_xray()
    except Exception as e:
        with db() as c:
            for key in profiles:
                setting="profile:"+key
                if setting in previous: c.execute("UPDATE settings SET value=? WHERE key=?",(previous[setting],setting))
                else: c.execute("DELETE FROM settings WHERE key=?",(setting,))
        try: await start_xray()
        except Exception as restore_error: event("ERROR",f"Xray recovery after failed profile update also failed: {restore_error}")
        event("ERROR",f"Profile update rolled back because Xray update failed: {e}")
        raise HTTPException(503,"Profile settings were not saved because Xray could not apply the configuration")
    event("INFO","Updated enabled connection profiles.")
    return {"profiles":[{"key":p["key"],"label":p["label"],"enabled":updated[p["key"]],"protocol":p.get("protocol","vless"),"network":p.get("network","—"),"path":p.get("path","—"),"mode":p.get("mode"),"port":p.get("port"),"experimental":bool(p.get("experimental",False))} for p in PROFILES]}

@app.post("/api/clients")
async def create_client(r:Request):
    require_admin(r); require_csrf(r); b=await r.json(); name=valid_name(b.get("name")); note=b.get("note","")
    if not isinstance(note,str) or len(note)>300: raise HTTPException(422,"Note must be at most 300 characters")
    days=b.get("duration_days"); quota=b.get("quota_gb"); selected_profiles=b.get("profiles")
    known_profiles={p["key"] for p in PROFILES}
    if selected_profiles is not None and (not isinstance(selected_profiles,list) or not selected_profiles or any(not isinstance(k,str) or k not in known_profiles for k in selected_profiles) or len(set(selected_profiles))!=len(selected_profiles)):
        raise HTTPException(422,"profiles must be a non-empty list of supported profile keys")
    profile_keys=json.dumps(selected_profiles,separators=(",",":")) if selected_profiles is not None else None
    if days is not None and (not isinstance(days,(int,float)) or isinstance(days,bool) or not float(days).is_integer() or days<1 or days>3650): raise HTTPException(422,"duration_days must be a whole number from 1 to 3650")
    if quota is not None and (not isinstance(quota,(int,float)) or isinstance(quota,bool) or not 1<=quota<=100000): raise HTTPException(422,"quota_gb must be 1–100000")
    expires=(datetime.now(timezone.utc)+timedelta(days=int(days))).isoformat(timespec="seconds") if days is not None else None
    owner=owner_id_for(r); quota_bytes=int(float(quota)*1024**3) if quota is not None else None
    if owner is not None and quota_bytes is None:
        raise HTTPException(422,"Resellers must assign a finite quota to every client")
    cid,uid,token=str(uuid.uuid4()),str(uuid.uuid4()),secrets.token_urlsafe(32)
    with db() as c:
        # Serialize allocation checks and inserts to prevent concurrent requests
        # from spending the same remaining reseller quota twice.
        c.execute("BEGIN IMMEDIATE")
        if owner is not None:
            assert_reseller_chain_enabled(c,owner)
            parent=c.execute("SELECT quota_bytes FROM resellers WHERE id=?",(owner,)).fetchone()
            allocated=reseller_allocated(c,owner)
            if quota_bytes>int(parent["quota_bytes"])-allocated:
                raise HTTPException(422,"Client quota exceeds your remaining allocation")
        c.execute("INSERT INTO clients(id,name,client_uuid,sub_token,enabled,created_at,note,expires_at,quota_bytes,used_bytes,owner_id,profile_keys) VALUES(?,?,?,?,1,?,?,?,?,0,?,?)",(cid,name,uid,token,utc_now(),note.strip(),expires,quota_bytes,owner,profile_keys))
    try:
        await start_xray()
    except Exception as e:
        # Do not leave a client marked active when Xray rejected its config.
        with db() as c: c.execute("DELETE FROM clients WHERE id=?",(cid,))
        try: await start_xray()
        except Exception as restore_error: event("ERROR",f"Xray recovery after failed client creation also failed: {restore_error}")
        event("ERROR",f"Client creation rolled back because Xray update failed: {e}")
        raise HTTPException(503,"Client was not created because Xray could not apply the configuration")
    event("INFO",f"Created client {name!r} ({cid[:8]})."); return {"id":cid,"name":name,"enabled":True}
@app.patch("/api/clients/{cid}")
async def update_client(cid:str,r:Request):
    require_admin(r); require_csrf(r); require_client_access(r,cid); b=await r.json()
    allowed={"enabled","name","note","duration_days","quota_gb","profiles"}
    if not isinstance(b,dict) or not b or set(b)-allowed: raise HTTPException(422,"Provide supported client fields only")
    if "enabled" in b and not isinstance(b["enabled"],bool): raise HTTPException(422,"enabled must be true or false")
    if "name" in b: b["name"]=valid_name(b["name"])
    if "note" in b and (not isinstance(b["note"],str) or len(b["note"])>300): raise HTTPException(422,"Note must be at most 300 characters")
    if "duration_days" in b and b["duration_days"] is not None and (not isinstance(b["duration_days"],(int,float)) or isinstance(b["duration_days"],bool) or not float(b["duration_days"]).is_integer() or not 1<=b["duration_days"]<=3650): raise HTTPException(422,"duration_days must be a whole number from 1 to 3650, or null")
    if "quota_gb" in b and b["quota_gb"] is not None and (not isinstance(b["quota_gb"],(int,float)) or isinstance(b["quota_gb"],bool) or not 1<=b["quota_gb"]<=100000): raise HTTPException(422,"quota_gb must be 1–100000, or null")
    if "profiles" in b:
        known_profiles={p["key"] for p in PROFILES}; selected=b["profiles"]
        if not isinstance(selected,list) or not selected or any(not isinstance(k,str) or k not in known_profiles for k in selected) or len(set(selected))!=len(selected):
            raise HTTPException(422,"profiles must be a non-empty list of supported profile keys")
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        owner=owner_id_for(r)
        if owner is not None:
            assert_reseller_chain_enabled(c,owner)
        row=c.execute("SELECT * FROM clients WHERE id=?",(cid,)).fetchone()
        if not row: raise HTTPException(404,"Client not found")
        previous=dict(row)
        updates={}
        if "enabled" in b: updates["enabled"]=int(b["enabled"])
        if "name" in b: updates["name"]=b["name"]
        if "note" in b: updates["note"]=b["note"].strip()
        if "duration_days" in b:
            updates["expires_at"]=(datetime.now(timezone.utc)+timedelta(days=int(b["duration_days"]))).isoformat(timespec="seconds") if b["duration_days"] is not None else None
        if "quota_gb" in b: updates["quota_bytes"]=int(float(b["quota_gb"])*1024**3) if b["quota_gb"] is not None else None
        if "profiles" in b: updates["profile_keys"]=json.dumps(b["profiles"],separators=(",",":"))
        if not updates: raise HTTPException(422,"No fields to update")
        if owner is not None and "quota_bytes" in updates:
            new_quota=updates["quota_bytes"]
            if new_quota is None: raise HTTPException(422,"Reseller clients must have a finite quota")
            allocated=int(c.execute("SELECT COALESCE(SUM(quota_bytes),0) n FROM clients WHERE owner_id=? AND id<>?",(owner,cid)).fetchone()["n"] or 0)
            children=int(c.execute("SELECT COALESCE(SUM(quota_bytes),0) n FROM resellers WHERE parent_id=?",(owner,)).fetchone()["n"] or 0)
            parent=c.execute("SELECT quota_bytes FROM resellers WHERE id=?",(owner,)).fetchone()
            if allocated+children+new_quota>int(parent["quota_bytes"]): raise HTTPException(422,"Updated quota exceeds your remaining allocation")
        c.execute("UPDATE clients SET "+", ".join(f"{key}=?" for key in updates)+" WHERE id=?",(*updates.values(),cid))  # nosec B608: keys originate only from the explicit allowed-field mapping above
    if ("enabled" in updates and updates["enabled"] != previous["enabled"]) or "profile_keys" in updates:
        try:
            await start_xray()
        except Exception as e:
            rollback={key:previous[key] for key in ("enabled","profile_keys") if key in updates}
            if rollback:
                with db() as c: c.execute("UPDATE clients SET "+", ".join(f"{key}=?" for key in rollback)+" WHERE id=?",(*rollback.values(),cid))  # nosec B608: keys are restricted to fixed enabled/profile_keys fields
            try: await start_xray()
            except Exception as restore_error: event("ERROR",f"Xray recovery after failed client update also failed: {restore_error}")
            event("ERROR",f"Client update rolled back because Xray update failed: {e}")
            raise HTTPException(503,"Client settings were not changed because Xray could not apply the configuration")
    event("INFO",f"Updated client {cid[:8]}."); return {"ok":True}

@app.post("/api/clients/{cid}/reset-usage")
async def reset_client_usage(cid:str,r:Request):
    require_admin(r); require_csrf(r); require_client_access(r,cid)
    with db() as c:
        row=c.execute("SELECT name FROM clients WHERE id=?",(cid,)).fetchone()
        if not row: raise HTTPException(404,"Client not found")
    if Path(XRAY_BIN).exists() and xray_proc and xray_proc.poll() is None:
        try: apply_xray_stats(read_xray_stats())
        except Exception as e: raise HTTPException(503,"Could not synchronize live usage before resetting it") from e
    with db() as c: c.execute("UPDATE clients SET used_bytes=0 WHERE id=?",(cid,))
    event("INFO",f"Reset usage for client {row['name']!r} ({cid[:8]}).")
    return {"ok":True}
@app.delete("/api/clients/{cid}")
async def delete_client(cid:str,r:Request):
    require_admin(r); require_csrf(r); require_client_access(r,cid)
    with db() as c:
        row=c.execute("SELECT * FROM clients WHERE id=?",(cid,)).fetchone()
        if not row: raise HTTPException(404,"Client not found")
        previous=dict(row)
        c.execute("DELETE FROM clients WHERE id=?",(cid,))
    try:
        await start_xray()
    except Exception as e:
        with db() as c:
            c.execute("INSERT OR REPLACE INTO clients(id,name,client_uuid,sub_token,enabled,created_at,note,expires_at,quota_bytes,used_bytes,owner_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                      (previous["id"],previous["name"],previous["client_uuid"],previous["sub_token"],previous["enabled"],previous["created_at"],previous["note"],previous["expires_at"],previous["quota_bytes"],previous["used_bytes"],previous.get("owner_id")))
        try: await start_xray()
        except Exception as restore_error: event("ERROR",f"Xray recovery after failed client revocation also failed: {restore_error}")
        event("ERROR",f"Client revocation rolled back because Xray update failed: {e}")
        raise HTTPException(503,"Client was not revoked because Xray could not apply the configuration")
    event("INFO",f"Revoked client {cid[:8]}."); return {"ok":True}
def get_base_url(r=None):
    if BASE_URL: return BASE_URL
    if PUBLIC_DOMAIN: return "https://"+PUBLIC_DOMAIN
    if r: return f"{r.headers.get('x-forwarded-proto','https')}://{r.headers.get('x-forwarded-host') or r.headers.get('host','localhost')}"
    return "https://YOUR-RAILWAY-DOMAIN"

def active_subscription_client(token):
    if len(token)>100: raise HTTPException(404,"Not found")
    with db() as c: client=c.execute("SELECT * FROM clients WHERE sub_token=? AND enabled=1",(token,)).fetchone()
    if not client or not client_is_active(dict(client)):
        raise HTTPException(404,"Subscription not found, expired, or disabled")
    return dict(client)

def make_subscription_links(client, r):
    try: selected_profiles=json.loads(client.get("profile_keys") or "null")
    except (TypeError,ValueError): selected_profiles=None
    base=get_base_url(r)
    host=urlsplit(base).hostname or PUBLIC_DOMAIN or "YOUR-RAILWAY-DOMAIN"
    links=[]
    flags=get_profile_flags()
    for profile in PROFILES:
        if not flags[profile["key"]]: continue
        if selected_profiles is not None and profile["key"] not in selected_profiles: continue
        network,path,mode=profile["network"],profile["path"],profile["mode"]
        proto=profile.get("protocol","vless")
        label=profile.get("subscription_label",profile["key"].replace("_","-"))
        common=f"type={network}&security=tls&sni={host}&fp=chrome&host={host}&path={quote(path,safe='')}"
        if mode: common+=f"&mode={quote(mode,safe='')}"
        uid=client["client_uuid"]
        title=quote("abysstunnel-"+client["name"]+"-"+label)
        if proto=="vless":
            url=f"vless://{uid}@{host}:443?{common}&encryption=none#{title}"
        elif proto=="trojan":
            url=f"trojan://{uid}@{host}:443?{common}#{title}"
        elif proto=="vmess":
            vmess={"v":"2","ps":"abysstunnel-"+client["name"]+"-"+label,"add":host,"port":"443","id":uid,"aid":"0","scy":"auto","net":"ws","type":"none","host":host,"path":path,"tls":"tls","sni":host,"alpn":""}
            url="vmess://"+base64.b64encode(json.dumps(vmess,separators=(",",":")).encode()).decode()
        elif proto=="shadowsocks":
            ss_password=base64.b64encode(hashlib.sha256(uid.encode()).digest()[:16]).decode()
            combined_password=get_ss2022_server_password()+":"+ss_password
            # SIP022 requires the AEAD-2022 method and a percent-encoded server:user PSK pair.
            userinfo="2022-blake3-aes-128-gcm:"+quote(combined_password,safe="")
            plugin=quote("v2ray-plugin;tls;host="+host+";path="+path,safe="")
            url=f"ss://{userinfo}@{host}:443/?plugin={plugin}#{title}"
        else:
            continue
        links.append({"key":profile["key"],"label":profile["label"],"url":url})
    return links

def subscription_text(links):
    return base64.b64encode("\n".join(item["url"] for item in links).encode()).decode()

def subscription_userinfo(client):
    """Standard subscription metadata consumed by compatible clients."""
    used=max(0,int(client.get("used_bytes") or 0))
    quota=0 if client.get("quota_bytes") is None else max(0,int(client["quota_bytes"]))
    expire=0
    value=client.get("expires_at")
    if value:
        try:
            dt=datetime.fromisoformat(str(value).replace("Z","+00:00"))
            if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)
            expire=max(0,int(dt.timestamp()))
        except (TypeError,ValueError,OverflowError):
            expire=0
    return f"upload=0; download={used}; total={quota}; expire={expire}"

def render_subscription_page(client, links, sub_url, qr_url):
    quota=client["quota_bytes"]
    used_bytes=max(0,int(client["used_bytes"] or 0))
    usage=used_bytes/1024**3
    quota_text="نامحدود" if quota is None else f"{quota/1024**3:.2f} GB"
    usage_pct=0 if quota is None or int(quota)<=0 else min(100,round(used_bytes/int(quota)*100))
    remaining_text="نامحدود" if quota is None else f"{max(0,int(quota)-used_bytes)/1024**3:.2f} GB"
    expiry=client["expires_at"] or "بدون انقضا"
    cards="".join(
        '<div class="profile-choice" data-profile-choice="'+html_escape(item["key"],quote=True)+'"><a class="profile" href="'+html_escape(item["url"],quote=True)+'"><span class="profile-icon">↗</span><span><b>'+html_escape(item["label"])+'</b><small>TLS · '+html_escape(item["label"])+'</small></span><span class="profile-open">باز کردن</span></a><div class="profile-marks"><button type="button" data-mark="ok" data-profile="'+html_escape(item["key"],quote=True)+'">✓ کار کرد</button><button type="button" data-mark="fail" data-profile="'+html_escape(item["key"],quote=True)+'">× کار نکرد</button><small data-result="'+html_escape(item["key"],quote=True)+'"></small></div></div>'
        for item in links
    )
    template="""<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="dark"><meta name="theme-color" content="#080b12"><title>Abyss Tunnel · اشتراک خصوصی</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 50% -15%,#163a43 0,transparent 48%),#080b12;color:#edf5f7;font:15px system-ui,-apple-system,sans-serif}.shell{width:min(820px,100%);margin:auto;padding:28px 16px 44px}.top,.row,.profile{display:flex;align-items:center;justify-content:space-between;gap:14px}.brand{font-size:12px;letter-spacing:.18em;color:#8de8d6;font-weight:800}.badge{font-size:11px;color:#8de8d6;border:1px solid #275c58;padding:7px 10px;border-radius:99px}.hero{margin:25px 0 16px;padding:25px;border:1px solid #25434b;border-radius:24px;background:linear-gradient(135deg,rgba(18,39,49,.96),rgba(13,20,32,.97));box-shadow:0 22px 70px #0005}.eyebrow{font-size:11px;color:#8de8d6;letter-spacing:.12em}.hero h1{font-size:clamp(25px,6vw,38px);line-height:1.2;margin:12px 0 8px;overflow-wrap:anywhere}.muted,small{color:#91a3b4;line-height:1.8}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:14px 0}.metric,.panel{background:#101722;border:1px solid #222f3f;border-radius:16px;padding:16px;min-width:0}.metric small{display:block;font-size:11px}.metric b{display:block;font-size:16px;margin-top:7px;overflow-wrap:anywhere}.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 12px}.section-head h2{font-size:16px;margin:0}.profiles{display:grid;gap:9px}.profile{padding:13px;text-decoration:none;color:#edf5f7;border:1px solid #263447;border-radius:13px;background:#0b111b;min-width:0}.profile:hover{border-color:#76e4d1;background:#101e27}.profile-icon{width:34px;height:34px;display:grid;place-items:center;border-radius:10px;background:#173b3c;color:#8de8d6;flex-shrink:0}.profile>span:nth-child(2){flex:1;min-width:0}.profile b,.profile small{display:block;overflow-wrap:anywhere}.profile-open{font-size:12px;color:#8de8d6;white-space:nowrap}.profile-marks{display:flex;flex-wrap:wrap;align-items:center;gap:6px;padding:6px 2px 2px}.profile-marks button{border:1px solid #2a3a4c;background:#101923;color:#b9c9d7;border-radius:8px;padding:6px 9px;font:inherit;font-size:11px;cursor:pointer}.profile-marks button[data-selected="true"][data-mark="ok"]{border-color:#4f9e87;color:#8de8d6;background:#102b26}.profile-marks button[data-selected="true"][data-mark="fail"]{border-color:#9c5a60;color:#ffb4b4;background:#2b151a}.profile-marks small{font-size:10px}.carrier-tools{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.6fr);gap:12px;align-items:center;margin-bottom:13px;padding:13px;border:1px solid #263748;border-radius:12px;background:#0b111b}.carrier-tools label{font-size:12px;color:#9aabbd}.carrier-tools select{width:100%;margin-top:6px;padding:10px;border:1px solid #2a3b4d;border-radius:9px;background:#080d15;color:#edf5f7}.share{display:grid;grid-template-columns:minmax(0,1fr) 160px;gap:16px;align-items:center}.linkbox{direction:ltr;text-align:left;width:100%;background:#080d15;color:#c6d6df;border:1px solid #2a3b4d;border-radius:10px;padding:12px;font:12px ui-monospace,monospace;overflow-wrap:anywhere}.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;margin-top:9px;padding:11px 14px;border-radius:10px;border:1px solid #2b4651;background:#152630;color:#eaf8f6;font:inherit;cursor:pointer;text-decoration:none}.btn.primary{background:#8de8d6;color:#061412;border-color:#8de8d6;font-weight:800}.qr{display:block;width:160px;max-width:100%;padding:9px;border-radius:13px;background:#fff;aspect-ratio:1}.footer{text-align:center;font-size:11px;color:#65778a;margin-top:24px;line-height:1.9}.warning{color:#d8c58a;font-size:12px;margin-top:12px;line-height:1.8}.usage-panel{margin:0 0 14px}.usage-track{height:7px;margin:12px 0;border-radius:99px;background:var(--ab-line);overflow:hidden}.usage-track span{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--ab-accent),var(--ab-accent-hi));transition:width .2s ease}.usage-visual{display:grid;grid-template-columns:150px minmax(0,1fr);gap:20px;align-items:center}.usage-gauge{width:142px;max-width:100%;aspect-ratio:1;border-radius:50%;display:grid;place-items:center;background:conic-gradient(var(--ab-accent) calc(var(--usage)*1%),var(--ab-line) 0);box-shadow:0 8px 22px rgba(0,0,0,.09),inset 0 1px rgba(255,255,255,.06);position:relative}.usage-gauge:before{content:"";position:absolute;inset:10px;border-radius:50%;background:var(--ab-panel);border:1px solid var(--ab-line)}.usage-gauge>span{position:relative;z-index:1;font-size:21px;font-weight:800;text-align:center}.usage-gauge small{display:block;font-size:10px;font-weight:500}.usage-detail{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.usage-detail>div{padding:14px;border:1px solid var(--ab-line);border-radius:13px;background:var(--ab-glass)}.usage-detail small,.usage-detail b{display:block}.usage-detail b{margin-top:7px;font-size:17px;overflow-wrap:anywhere}@media(max-width:500px){.usage-visual{grid-template-columns:105px minmax(0,1fr);gap:12px}.usage-gauge{width:104px}.usage-gauge:before{inset:7px}.usage-gauge>span{font-size:17px}.usage-detail{grid-template-columns:1fr}.usage-detail>div{padding:10px}}@media(max-width:560px){.shell{padding:18px 11px 30px}.hero{padding:19px;border-radius:19px}.grid{grid-template-columns:1fr 1fr}.share{grid-template-columns:1fr}.qr{width:145px;margin:8px auto 0}.profile{gap:9px;padding:11px}.profile-open{font-size:11px}.metric,.panel{padding:13px}}@media(max-width:360px){.grid{grid-template-columns:1fr}.profile-open{display:none}}
</style><style id="abyss-premium-upgrade">
:root{color-scheme:dark;--abyss-bg:#070a10;--abyss-panel:#101722;--abyss-line:#263748;--abyss-mint:#8de8d6;--abyss-text:#edf3fb;--abyss-muted:#9aabbd}
html{scroll-behavior:smooth}body{background-color:var(--abyss-bg)}body:before{content:"";position:fixed;inset:0;pointer-events:none;z-index:-1;background:radial-gradient(ellipse at 80% -10%,rgba(43,130,125,.16),transparent 42%),radial-gradient(ellipse at 0% 40%,rgba(37,66,107,.13),transparent 42%)}
.card,.panel,.box,.section,.stat,.metric,.client-card{border-color:var(--abyss-line)!important;box-shadow:0 12px 36px rgba(0,0,0,.14);transition:border-color .18s ease,transform .18s ease,box-shadow .18s ease}
button,.btn,a.button{transition:filter .15s ease,transform .15s ease,box-shadow .15s ease}button:hover,.btn:hover,a.button:hover{filter:brightness(1.08);transform:translateY(-1px)}
button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--abyss-mint);outline-offset:3px}
input,select,textarea{max-width:100%;min-width:0}table{display:block;max-width:100%;overflow-x:auto;border-collapse:collapse}main,.container,.wrap{min-width:0}
@media(max-width:600px){body{font-size:14px}main,.container,.wrap{padding-left:12px!important;padding-right:12px!important}.card,.panel,.box{border-radius:15px!important}.row{flex-wrap:wrap}.row>*{max-width:100%}button,.btn{min-height:42px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style></head><body data-sub-url="__SUB_URL__"><main class="shell"><header class="top"><div class="abyss-brand-row"><span class="abyss-logo-mark" aria-hidden="true"></span><span class="brand-name">ABYSS TUNNEL<small>• I T A •</small></span></div><span class="badge">PRIVATE SUBSCRIPTION</span></header><section class="hero"><div class="eyebrow">YOUR CONNECTION · YOUR CONTROL</div><h1>اشتراک خصوصی شما</h1><p class="muted">پروفایل موردنظرت را انتخاب کن یا لینک اشتراک را در کلاینت سازگار وارد کن.</p><div class="row"><div><small>نام سرویس</small><div style="font-size:19px;font-weight:800;overflow-wrap:anywhere">__CLIENT_NAME__</div></div><button class="btn primary" onclick="copySub()">کپی لینک اشتراک</button></div></section><section class="grid"><div class="metric"><small>مصرف‌شده</small><b>__USED__ GB</b></div><div class="metric"><small>حجم کل</small><b>__QUOTA__</b></div><div class="metric"><small>باقی‌مانده</small><b>__REMAINING__</b></div><div class="metric"><small>اعتبار تا</small><b>__EXPIRY__</b></div></section><section class="panel usage-panel"><div class="row"><b>مصرف ترافیک <span class="help-dot" title="نمودار درصد حجم مصرف‌شده از سقف مجاز سرویس را نشان می‌دهد.">؟</span></b><span>__USAGE_PERCENT__٪</span></div><div class="usage-visual"><div class="usage-gauge" style="--usage:__USAGE_PERCENT__" role="img" aria-label="مصرف __USAGE_PERCENT__ درصد"><span>__USAGE_PERCENT__٪<small>مصرف‌شده</small></span></div><div class="usage-detail"><div><small>حجم مصرف‌شده</small><b>__USED__ GB</b></div><div><small>حجم باقی‌مانده</small><b>__REMAINING__</b></div></div></div><div class="usage-track" role="progressbar" aria-label="مصرف ترافیک" aria-valuemin="0" aria-valuemax="100" aria-valuenow="__USAGE_PERCENT__"><span style="width:__USAGE_PERCENT__%"></span></div><small class="muted">حجم مصرفی از آمار ثبت‌شدهٔ Xray محاسبه می‌شود؛ ممکن است با تأخیر کوتاهی به‌روز شود.</small></section><section class="panel"><div class="section-head"><h2>پروفایل‌های اتصال</h2><span class="badge">__COUNT__ PROFILES</span></div><div class="carrier-tools"><div><label for="carrierSelect">شبکه‌ای که الان با آن تست می‌کنی</label><select id="carrierSelect"><option value="auto">انتخاب خودکار</option><option value="mci">همراه اول</option><option value="irancell">ایرانسل</option><option value="rightel">رایتل</option><option value="wifi">وای‌فای / سایر</option></select></div><div><small>نتیجهٔ هر پروفایل را روی همین دستگاه ثبت کن تا پروفایل‌های موفق برای همین شبکه بالاتر نمایش داده شوند.</small><br><small>نتیجه روی همین دستگاه ذخیره و به‌صورت آماری برای پیشنهادهای اپراتور ثبت می‌شود.</small></div></div><div class="profiles" id="profileChoices">__PROFILES__</div><p class="warning">اگر کلاینت شما از لینک اشتراک پشتیبانی می‌کند، لینک اصلی را وارد کنید تا همه پروفایل‌ها یکجا اضافه شوند.</p></section><section class="panel" style="margin-top:14px"><div class="section-head"><h2>لینک واحد اشتراک</h2><span class="badge">ONE LINK</span></div><p class="muted">همین یک لینک را هم در مرورگر باز کن و هم در برنامهٔ سازگار وارد کن؛ مرورگر صفحه مدیریت اشتراک را می‌بیند و برنامه، فهرست پروفایل‌ها و اطلاعات حجم را دریافت می‌کند.</p><div class="share"><div><input class="linkbox" readonly value="__SUB_URL__" aria-label="Subscription URL"><button class="btn primary" onclick="copySub()">کپی لینک واحد</button></div><img class="qr" src="__QR_URL__" alt="QR code for subscription link" width="160" height="160"></div></section><footer class="footer">ABYSS TUNNEL · PRIVATE BY DESIGN<br>این صفحه را فقط با صاحب سرویس به اشتراک بگذار؛ لینک اشتراک مانند رمز دسترسی عمل می‌کند.<div class="abyss-utility-links" style="justify-content:center"><a href="https://github.com/bodisbos-cmd/Void" target="_blank" rel="noopener">⌘ GitHub</a><a href="https://github.com/bodisbos-cmd/Void/stargazers" target="_blank" rel="noopener">☆ ستاره دادن</a><a href="#support-link-not-configured" onclick="if(this.getAttribute('href')==='#support-link-not-configured'){alert('لینک حمایت مالی هنوز در تنظیمات سرویس ثبت نشده است.');return false}">◇ حمایت از پروژه</a></div></footer></main><script>async function copySub(){const u=document.body.dataset.subUrl;try{await navigator.clipboard.writeText(u);alert('لینک اشتراک کپی شد')}catch(e){const x=document.querySelector('.linkbox');x.focus();x.select();alert('لینک را به‌صورت دستی کپی کن')}}</script><script id="abyss-profile-results">(()=>{const select=document.getElementById('carrierSelect'),list=document.getElementById('profileChoices');if(!select||!list)return;const prefix='abyss-profile-results:';const storageKey=()=>prefix+select.value;const read=()=>{try{return JSON.parse(localStorage.getItem(storageKey())||'{}')}catch(e){return {}}};function paint(){const data=read();list.querySelectorAll('[data-profile-choice]').forEach(card=>{const key=card.dataset.profileChoice,value=data[key]||'';card.querySelectorAll('[data-mark]').forEach(b=>b.dataset.selected=String(b.dataset.mark===value));const out=card.querySelector('[data-result]');if(out)out.textContent=value==='ok'?'برای این شبکه موفق بود':value==='fail'?'برای این شبکه ناموفق بود':''});const cards=[...list.querySelectorAll('[data-profile-choice]')];cards.sort((a,b)=>{const rank=x=>({ok:0,'':1,fail:2})[data[x.dataset.profileChoice]||''];return rank(a)-rank(b)});cards.forEach(x=>list.appendChild(x))}select.value=localStorage.getItem(prefix+'carrier')||'auto';select.addEventListener('change',()=>{localStorage.setItem(prefix+'carrier',select.value);paint()});list.querySelectorAll('[data-mark]').forEach(b=>b.addEventListener('click',async()=>{const d=read();d[b.dataset.profile]=b.dataset.mark;localStorage.setItem(storageKey(),JSON.stringify(d));paint();try{await fetch(location.pathname+'/feedback',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({carrier:select.value,profile_key:b.dataset.profile,result:b.dataset.mark})})}catch(e){}}));paint()})();</script></body></html>"""
    return (template.replace("__SUB_URL__",html_escape(sub_url,quote=True))
        .replace("__CLIENT_NAME__",html_escape(client["name"]))
        .replace("__USED__",f"{usage:.3f}")
        .replace("__QUOTA__",html_escape(quota_text))
        .replace("__REMAINING__",html_escape(remaining_text))
        .replace("__USAGE_PERCENT__",str(usage_pct))
        .replace("__EXPIRY__",html_escape(expiry))
        .replace("__PROFILES__",cards)
        .replace("__COUNT__",str(len(links)))
        .replace("__QR_URL__",html_escape(qr_url,quote=True))
        .replace("__SUB_JSON__",json.dumps(sub_url))).replace("</head>",ABYSS_THEME_CSS+ABYSS_THEME_POLISH_CSS+"</head>").replace("</body>",ABYSS_THEME_JS+"</body>")

@app.get("/api/clients/{cid}/subscription")
async def subscription_link(cid:str,r:Request):
    require_admin(r); require_client_access(r,cid)
    with db() as c: row=c.execute("SELECT sub_token FROM clients WHERE id=?",(cid,)).fetchone()
    if not row: raise HTTPException(404,"Client not found")
    base=get_base_url(r); token=row["sub_token"]
    single_url=f"{base}/sub/{token}"
    return JSONResponse({"url":single_url,"page_url":single_url,"subscription_url":single_url,"qr_url":f"{single_url}/qr"},headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"})

@app.get("/sub/{token}")
async def subscription(token:str,r:Request):
    """One shareable URL: browsers get the branded page; subscription clients get Base64."""
    client=active_subscription_client(token)
    links=make_subscription_links(client,r)
    accept=r.headers.get("accept","").lower()
    agent=r.headers.get("user-agent","").lower()
    browser_request=("text/html" in accept and any(x in agent for x in ("mozilla","chrome","safari","firefox","edg/","opr/")))
    headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow","Vary":"Accept, User-Agent","Subscription-Userinfo":subscription_userinfo(client),"Profile-Update-Interval":"6"}
    if browser_request:
        base=get_base_url(r)
        page=render_subscription_page(client,links,f"{base}/sub/{token}",f"{base}/sub/{token}/qr")
        return HTMLResponse(page,headers=headers)
    return PlainTextResponse(subscription_text(links),headers=headers)

@app.post("/sub/{token}/feedback")
async def submit_profile_feedback(token:str,r:Request):
    client=active_subscription_client(token)
    if not rate_check(r,"profile-feedback:"+client["id"],limit=30,window=60):
        raise HTTPException(429,"Too many feedback reports")
    body=await r.json()
    if not isinstance(body,dict):
        raise HTTPException(422,"JSON object required")
    carrier=body.get("carrier")
    profile_key=body.get("profile_key")
    result=body.get("result")
    if carrier not in {"auto","mci","irancell","rightel","wifi"}:
        raise HTTPException(422,"Unsupported carrier")
    if profile_key not in {p["key"] for p in PROFILES}:
        raise HTTPException(422,"Unsupported profile")
    if result not in {"ok","fail"}:
        raise HTTPException(422,"Result must be ok or fail")
    with db() as c:
        c.execute("INSERT INTO profile_feedback(client_id,carrier,profile_key,result,created_at,user_agent) VALUES(?,?,?,?,?,?) ON CONFLICT(client_id,carrier,profile_key) DO UPDATE SET result=excluded.result,created_at=excluded.created_at,user_agent=excluded.user_agent",(client["id"],carrier,profile_key,result,utc_now(),r.headers.get("user-agent","")[:160]))
    return {"ok":True,"message":"نتیجه برای پیشنهادهای همین اپراتور ثبت شد."}

@app.get("/sub/{token}/qr")
async def subscription_qr(token:str,r:Request):
    client=active_subscription_client(token)
    url=f"{get_base_url(r)}/sub/{token}"
    qr=qrcode.make(url,image_factory=SvgPathImage,box_size=7,border=2)
    buffer=io.BytesIO(); qr.save(buffer)
    return Response(buffer.getvalue(),media_type="image/svg+xml",headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"})

@app.get("/s/{token}",response_class=HTMLResponse)
async def subscription_page(token:str,r:Request):
    client=active_subscription_client(token)
    links=make_subscription_links(client,r)
    base=get_base_url(r); sub_url=f"{base}/sub/{token}"
    page=render_subscription_page(client,links,sub_url,f"{base}/sub/{token}/qr")
    return HTMLResponse(page,headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow","Subscription-Userinfo":subscription_userinfo(client),"Profile-Update-Interval":"6"})

@app.get("/api/backup/sqlite")
async def backup_database(r:Request):
    require_root(r)
    target=DATA_DIR/("abyss-backup-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")+".sqlite3")
    with db() as source:
        dest=sqlite3.connect(target)
        try: source.backup(dest)
        finally: dest.close()
    event("INFO","Administrator created a database backup.")
    return FileResponse(target,media_type="application/vnd.sqlite3",filename=target.name,headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"})

@app.post("/api/restore")
async def restore_database(r:Request):
    require_root(r); require_csrf(r)
    raw=await r.body()
    if not raw or len(raw)>100*1024*1024: raise HTTPException(413,"Backup must be between 1 byte and 100 MB")
    async with restore_lock:
        candidate=DATA_DIR/(".restore-candidate-"+uuid.uuid4().hex+".sqlite3")
        candidate.write_bytes(raw)
        old=None
        try:
            check=sqlite3.connect(candidate)
            try:
                try:
                    if check.execute("PRAGMA integrity_check").fetchone()[0]!="ok":
                        raise HTTPException(422,"Backup database integrity check failed")
                    tables={x[0] for x in check.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    if not {"admins","clients","settings"}.issubset(tables):
                        raise HTTPException(422,"Incompatible Void backup")
                    required_columns={
                        "admins":{"id","password_hash","password_changed_at"},
                        "clients":{"id","name","client_uuid","sub_token","enabled","created_at"},
                        "settings":{"key","value"},
                    }
                    for table,required in required_columns.items():
                        columns={row[1] for row in check.execute("PRAGMA table_info("+table+")")}
                        if not required.issubset(columns):
                            raise HTTPException(422,"Backup schema is incompatible with this release")
                except sqlite3.DatabaseError as exc:
                    raise HTTPException(422,"Backup is not a valid SQLite database") from exc
            finally:
                check.close()
            stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            old=DATA_DIR/("pre-restore-"+stamp+".sqlite3")
            if DB_PATH.exists():
                src=sqlite3.connect(DB_PATH,timeout=30)
                dst=sqlite3.connect(old,timeout=30)
                try:
                    src.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    src.backup(dst)
                finally:
                    dst.close()
                    src.close()
            candidate.replace(DB_PATH)
            Path(str(DB_PATH)+"-wal").unlink(missing_ok=True)
            Path(str(DB_PATH)+"-shm").unlink(missing_ok=True)
            try:
                init_db()
                await start_xray()
            except Exception:
                # If the restored configuration cannot be applied, put the prior
                # database back while retaining its dated backup for manual recovery.
                if old and old.exists():
                    rollback=DATA_DIR/".restore-rollback.sqlite3"
                    shutil.copy2(old,rollback)
                    rollback.replace(DB_PATH)
                    Path(str(DB_PATH)+"-wal").unlink(missing_ok=True)
                    Path(str(DB_PATH)+"-shm").unlink(missing_ok=True)
                    init_db()
                    try:
                        await start_xray()
                    except Exception as rollback_error:
                        LOG.exception("Xray failed after restoring the previous database: %s",rollback_error)
                raise
            event("WARNING","Database restore completed; a pre-restore database copy was retained.")
            return {"ok":True,"message":"Restore completed; a pre-restore database copy was retained."}
        except HTTPException:
            raise
        except Exception as e:
            LOG.exception("Database restore failed")
            raise HTTPException(500,"Restore failed; previous database retained when available") from e
        finally:
            candidate.unlink(missing_ok=True)

@app.get("/api/resellers")
async def list_resellers(r:Request):
    require_admin(r); owner=owner_id_for(r)
    with db() as c:
        rows=[dict(x) for x in c.execute("SELECT id,username,quota_bytes,enabled,created_at,parent_id FROM resellers ORDER BY created_at DESC")] if owner is None else [dict(x) for x in c.execute("SELECT id,username,quota_bytes,enabled,created_at,parent_id FROM resellers WHERE parent_id=? ORDER BY created_at DESC",(owner,))]
        for row in rows: row["allocated_bytes"]=reseller_allocated(c,row["id"]); row["remaining_bytes"]=row["quota_bytes"]-row["allocated_bytes"]
    return {"resellers":rows}
@app.post("/api/resellers")
async def create_reseller(r:Request):
    require_admin(r); require_csrf(r); body=await r.json(); owner=owner_id_for(r)
    username=str(body.get("username","")).strip(); password=str(body.get("password","")); quota=body.get("quota_gb")
    if not username or len(username)>48 or not username.replace("_","").replace("-","").isalnum() or username=="admin": raise HTTPException(422,"Invalid username")
    if len(password)<14 or len(password)>256 or not any(x.isalpha() for x in password) or not any(x.isdigit() for x in password): raise HTTPException(422,"Password must be at least 14 characters and include letters and numbers")
    if not isinstance(quota,(int,float)) or isinstance(quota,bool) or not 0.1<=quota<=100000: raise HTTPException(422,"Invalid quota allocation")
    quota_bytes=int(float(quota)*1024**3)
    rid=str(uuid.uuid4())
    try:
        with db() as c:
            c.execute("BEGIN IMMEDIATE")
            if owner is not None:
                assert_reseller_chain_enabled(c,owner)
                parent=c.execute("SELECT quota_bytes FROM resellers WHERE id=?",(owner,)).fetchone()
                if quota_bytes>int(parent["quota_bytes"])-reseller_allocated(c,owner):
                    raise HTTPException(422,"Allocation exceeds your remaining quota")
            c.execute("INSERT INTO resellers(id,username,password_hash,quota_bytes,enabled,parent_id,created_at) VALUES(?,?,?,?,1,?,?)",(rid,username,password_hash(password),quota_bytes,owner,utc_now()))
    except sqlite3.IntegrityError: raise HTTPException(409,"Username already exists")
    event("INFO",f"Created reseller {username!r} with quota allocation.")
    return {"id":rid,"username":username,"quota_bytes":quota_bytes}
@app.patch("/api/resellers/{rid}")
async def update_reseller(rid:str,r:Request):
    require_admin(r); require_csrf(r); body=await r.json(); owner=owner_id_for(r)
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        if owner is not None:
            assert_reseller_chain_enabled(c,owner)
        row=c.execute("SELECT * FROM resellers WHERE id=?",(rid,)).fetchone()
        if not row or (owner is not None and row["parent_id"]!=owner): raise HTTPException(404,"Reseller not found")
        updates={}
        if "username" in body:
            username=str(body["username"]).strip()
            if not username or len(username)>48 or not username.replace("_","").replace("-","").isalnum() or username=="admin":
                raise HTTPException(422,"Invalid username")
            updates["username"]=username
        if "password" in body and body["password"] is not None and str(body["password"]):
            password=str(body["password"])
            if len(password)<14 or len(password)>256 or not any(x.isalpha() for x in password) or not any(x.isdigit() for x in password):
                raise HTTPException(422,"Password must be at least 14 characters and include letters and numbers")
            updates["password_hash"]=password_hash(password)
        if "enabled" in body:
            if not isinstance(body["enabled"],bool): raise HTTPException(422,"enabled must be boolean")
            updates["enabled"]=int(body["enabled"])
        if "quota_gb" in body:
            q=body["quota_gb"]
            if not isinstance(q,(int,float)) or isinstance(q,bool) or not 0.1<=q<=100000: raise HTTPException(422,"Invalid quota")
            amount=int(float(q)*1024**3)
            if amount<reseller_allocated(c,rid): raise HTTPException(422,"Cannot lower allocation below already delegated volume")
            if owner is not None:
                siblings=int(c.execute("SELECT COALESCE(SUM(quota_bytes),0) n FROM resellers WHERE parent_id=? AND id<>?",(owner,rid)).fetchone()["n"] or 0)
                clients=int(c.execute("SELECT COALESCE(SUM(quota_bytes),0) n FROM clients WHERE owner_id=?",(owner,)).fetchone()["n"] or 0)
                parent=c.execute("SELECT quota_bytes,enabled FROM resellers WHERE id=?",(owner,)).fetchone()
                if not parent or not parent["enabled"]: raise HTTPException(403,"Parent reseller account is disabled")
                if siblings+clients+amount>int(parent["quota_bytes"]): raise HTTPException(422,"Allocation exceeds parent quota")
            updates["quota_bytes"]=amount
        if not updates: raise HTTPException(422,"No supported changes")
        try:
            c.execute("UPDATE resellers SET "+", ".join(k+"=?" for k in updates)+" WHERE id=?",(*updates.values(),rid))  # nosec B608: keys are added only by fixed-field validation branches above
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409,"Username already exists") from exc
    return {"ok":True}
@app.delete("/api/resellers/{rid}")
async def delete_reseller(rid:str,r:Request):
    require_admin(r); require_csrf(r); owner=owner_id_for(r)
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        row=c.execute("SELECT * FROM resellers WHERE id=?",(rid,)).fetchone()
        if not row or (owner is not None and row["parent_id"]!=owner): raise HTTPException(404,"Reseller not found")
        has_clients=c.execute("SELECT 1 FROM clients WHERE owner_id=? LIMIT 1",(rid,)).fetchone()
        has_children=c.execute("SELECT 1 FROM resellers WHERE parent_id=? LIMIT 1",(rid,)).fetchone()
        if has_clients or has_children or reseller_allocated(c,rid):
            raise HTTPException(409,"Delete this reseller's clients and child resellers before deleting the account")
        c.execute("DELETE FROM resellers WHERE id=?",(rid,))
    return {"ok":True}

@app.get("/health")
async def health():
    with db() as c:
        c.execute("SELECT 1").fetchone()
    # If Xray is part of this image, a healthy HTTP process alone is not
    # sufficient: report unhealthy until the actual tunnel engine is running.
    xray_required=Path(XRAY_BIN).exists()
    xray_running=bool(not xray_required or (xray_proc is not None and xray_proc.poll() is None))
    payload={"ok":xray_running,"xray":"running" if xray_running else "stopped"}
    return JSONResponse(payload,status_code=200 if xray_running else 503)
@app.exception_handler(Exception)
async def unhandled(r:Request,e:Exception):
    LOG.exception("Unhandled error: %s",e)
    if r.url.path.startswith("/api/"): return JSONResponse({"detail":"Internal server error"},status_code=500)
    return HTMLResponse("<h1>Internal server error</h1>",status_code=500)


@app.post("/api/password")
async def change_password(r: Request):
    require_admin(r)
    require_csrf(r,allow_viewer=True)
    body = await r.json()
    current = str(body.get("current_password", ""))
    new = str(body.get("new_password", ""))
    if len(new) < 14 or len(new) > 256 or not any(ch.isalpha() for ch in new) or not any(ch.isdigit() for ch in new):
        raise HTTPException(400, "New password must be 14–256 characters and include letters and numbers")
    if r.session.get("admin") is True:
        admin_id=r.session.get("admin_id","owner-admin")
        with db() as c:
            row=c.execute("SELECT password_hash FROM panel_admins WHERE id=?",(admin_id,)).fetchone()
            if not row or not verify_password(current,row["password_hash"]):
                raise HTTPException(403,"Current password is incorrect")
            changed=utc_now(); hashed=password_hash(new)
            c.execute("UPDATE panel_admins SET password_hash=?,password_changed_at=? WHERE id=?",(hashed,changed,admin_id))
            if is_root(r):
                c.execute("UPDATE admins SET password_hash=?,password_changed_at=? WHERE id=1",(hashed,changed))
        r.session["admin_password_changed_at"]=changed
        if is_root(r):
            try: (DATA_DIR/"INITIAL_ADMIN_PASSWORD.txt").unlink(missing_ok=True)
            except OSError: event("WARNING","Could not remove the initial administrator password file.")
    else:
        with db() as c:
            row=c.execute("SELECT id,password_hash FROM resellers WHERE id=?",(owner_id_for(r),)).fetchone()
            if not row or not verify_password(current,row["password_hash"]):
                raise HTTPException(403,"Current password is incorrect")
            c.execute("UPDATE resellers SET password_hash=? WHERE id=?",(password_hash(new),owner_id_for(r)))
    event("INFO","Account password changed.")
    return {"ok":True}
# Register the optional platform extension after the core app and helpers are defined.
try:
    from app.extended import install_extended
except ModuleNotFoundError:
    import importlib.util
    _extension_spec = importlib.util.spec_from_file_location("abyss_extended", Path(__file__).with_name("extended.py"))
    _extension_module = importlib.util.module_from_spec(_extension_spec)
    _extension_spec.loader.exec_module(_extension_module)
    install_extended = _extension_module.install_extended
install_extended(app, globals())
@app.get("/api-docs",response_class=HTMLResponse)
async def protected_api_docs(r:Request):
    require_admin(r)
    return HTMLResponse("""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Void API Docs</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css"></head><body style="margin:0;background:#080b12"><div id="swagger-ui"></div><script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:'/api-docs/openapi.json',dom_id:'#swagger-ui',deepLinking:true,persistAuthorization:false})</script></body></html>""",headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"})

@app.get("/api-docs/redoc",response_class=HTMLResponse)
async def protected_redoc_docs(r:Request):
    require_admin(r)
    return HTMLResponse("""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Void API Reference</title></head><body style="margin:0;background:#080b12"><redoc spec-url="/api-docs/openapi.json"></redoc><script src="https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js"></script></body></html>""",headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"})

@app.get("/api-docs/openapi.json")
async def protected_openapi_schema(r:Request):
    require_admin(r)
    return app.openapi()

