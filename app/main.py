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
from starlette.middleware.sessions import SessionMiddleware

APP_NAME="AbyssPanel-Test"
PROFILES=[
    {"key":"ws","label":"WebSocket","network":"ws","path":"/ws","port":10001,"mode":None},
    {"key":"httpupgrade","label":"HTTPUpgrade","network":"httpupgrade","path":"/httpupgrade","port":10002,"mode":None},
    {"key":"xhttp_auto","label":"XHTTP · auto","network":"xhttp","path":"/xhttp","port":10003,"mode":"auto"},
    {"key":"xhttp_packet_up","label":"XHTTP · packet-up","network":"xhttp","path":"/xhttp-packet","port":10004,"mode":"packet-up"},
    {"key":"xhttp_stream_up","label":"XHTTP · stream-up","network":"xhttp","path":"/xhttp-stream-up","port":10005,"mode":"stream-up"},
    {"key":"xhttp_stream_one","label":"XHTTP · stream-one","protocol":"vless","network":"xhttp","path":"/xhttp-stream-one","port":10006,"mode":"stream-one"},
    {"key":"trojan_ws","label":"Trojan · WebSocket TLS","protocol":"trojan","network":"ws","path":"/trojan-ws","port":10007,"mode":None},
    {"key":"vmess_ws","label":"VMess · WebSocket TLS","protocol":"vmess","network":"ws","path":"/vmess-ws","port":10008,"mode":None},
    {"key":"ss_ws","label":"Shadowsocks · WebSocket TLS","protocol":"shadowsocks","network":"ws","path":"/ss-ws","port":10009,"mode":None},
]
DATA_DIR=Path(os.getenv("DATA_DIR","/data")); DATA_DIR.mkdir(parents=True,exist_ok=True)
DB_PATH=DATA_DIR/"panel.sqlite3"; XRAY_CONFIG=DATA_DIR/"xray.json"
XRAY_BIN=os.getenv("XRAY_BIN","/usr/local/bin/xray"); PUBLIC_DOMAIN=os.getenv("RAILWAY_PUBLIC_DOMAIN","").strip()
BASE_URL=os.getenv("BASE_URL","").strip().rstrip("/")
LOG=logging.getLogger("abysspanel"); logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO").upper())
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
        CREATE INDEX IF NOT EXISTS idx_clients_created ON clients(created_at DESC);
        """)
        if not c.execute("SELECT id FROM admins WHERE id=1").fetchone():
            # Generate a unique first-login credential; never ship admin/admin defaults.
            pw="admin" if os.getenv("ABYSS_TEST_MODE")=="1" else secrets.token_urlsafe(18); c.execute("INSERT INTO admins VALUES(1,?,?)",(password_hash(pw),utc_now()))
            p=DATA_DIR/"INITIAL_ADMIN_PASSWORD.txt"; p.write_text(f"Username: admin\nPassword: {pw}\n",encoding="utf-8")
            try: p.chmod(0o600)
            except OSError: pass
            if os.getenv("ABYSS_TEST_MODE")!="1": LOG.warning("INITIAL ADMIN CREDENTIAL username=admin password=%s; change immediately in Settings",pw)
        # Migrate the existing single-admin credential without changing its password.
        legacy=c.execute("SELECT password_hash,password_changed_at FROM admins WHERE id=1").fetchone()
        if legacy and not c.execute("SELECT id FROM panel_admins WHERE username='admin'").fetchone():
            c.execute("INSERT INTO panel_admins(id,username,password_hash,role,enabled,created_at,password_changed_at) VALUES(?,?,?,?,1,?,?)",
                ("owner-admin","admin",legacy["password_hash"],"owner",legacy["password_changed_at"],legacy["password_changed_at"]))
        # Safe in-place migration for persistent databases created by older releases.
        cols={row["name"] for row in c.execute("PRAGMA table_info(clients)")}
        for name, declaration in (("expires_at","TEXT"),("quota_bytes","INTEGER"),("used_bytes","INTEGER NOT NULL DEFAULT 0")):
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
    cols="id,name,client_uuid,enabled,created_at,note,expires_at,quota_bytes,used_bytes,owner_id" if include_client_uuid else "id,name,enabled,created_at,note,expires_at,quota_bytes,used_bytes,owner_id"
    with db() as c:
        if scoped: return [dict(r) for r in c.execute(f"SELECT {cols} FROM clients WHERE owner_id=? ORDER BY created_at DESC",(owner_id,))]
        return [dict(r) for r in c.execute(f"SELECT {cols} FROM clients ORDER BY created_at DESC")]
def get_profile_flags():
    with db() as c:
        saved={row["key"]:row["value"] for row in c.execute("SELECT key,value FROM settings WHERE key LIKE 'profile:%'")}
    return {p["key"]:saved.get("profile:"+p["key"],"1")=="1" for p in PROFILES}

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
    clients=[{"id":x["client_uuid"],"email":f"client-{x['id']}"} for x in get_clients(True) if client_is_active(x)]
    ins=[{"tag":"api","listen":"127.0.0.1","port":10085,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":10085,"network":"tcp"}}]
    flags=get_profile_flags()
    for profile in PROFILES:
        if not flags[profile["key"]]: continue
        port,network,path=profile["port"],profile["network"],profile["path"]
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
            settings={"method":"2022-blake3-aes-128-gcm","password":ss_clients[0]["password"] if ss_clients else base64.b64encode(secrets.token_bytes(16)).decode(),"network":"tcp","clients":ss_clients}
        else:
            raise ValueError("Unsupported profile protocol: "+protocol)
        inbound={"tag":f"in-{profile['key']}","listen":"127.0.0.1","port":port,"protocol":protocol,"settings":settings,"streamSettings":stream}
        ins.append(inbound)
    return {"log":{"loglevel":"debug" if os.getenv("ABYSS_TEST_MODE")=="1" else "warning"},"api":{"tag":"api","services":["StatsService"]},"stats":{},"policy":{"levels":{"0":{"statsUserUplink":True,"statsUserDownlink":True}}},"inbounds":ins,"outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"},{"protocol":"freedom","tag":"api"}],"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]}}
def validate_and_write_xray():
    tmp=XRAY_CONFIG.with_suffix(".tmp"); tmp.write_text(json.dumps(make_xray_config(),indent=2),encoding="utf-8"); tmp.replace(XRAY_CONFIG)
    if Path(XRAY_BIN).exists():
        r=subprocess.run([XRAY_BIN,"run","-test","-config",str(XRAY_CONFIG)],capture_output=True,text=True,timeout=15)
        if r.returncode: raise RuntimeError("Xray config test failed: "+(r.stderr or r.stdout)[-1000:])
async def start_xray():
    global xray_proc
    async with xray_lock:
        validate_and_write_xray()
        if not Path(XRAY_BIN).exists(): event("WARNING","Xray is not installed; control panel remains available."); return
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
sf=DATA_DIR/".session_secret"
if not sf.exists():
    sf.write_text(secrets.token_urlsafe(48),encoding="ascii")
    try: sf.chmod(0o600)
    except OSError: pass
app.add_middleware(SessionMiddleware,secret_key=sf.read_text().strip(),session_cookie="abyss_session",max_age=28800,same_site="strict",https_only=os.getenv("COOKIE_SECURE","1")!="0")
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

LOGIN='''<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="dark"><title>AbyssPanel · ورود</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;min-height:100dvh;display:grid;place-items:center;padding:18px;background:radial-gradient(ellipse at 50% 0,#163a43 0,transparent 52%),#080b12;color:#edf2ff;font:15px system-ui,-apple-system,sans-serif}.card{width:min(420px,100%);padding:clamp(22px,6vw,34px);border:1px solid #263b49;border-radius:22px;background:rgba(16,22,34,.96);box-shadow:0 24px 90px #0006}h1{margin:12px 0 8px;font-size:clamp(26px,7vw,34px)}p{line-height:1.9}.mint{color:#8de8d6;letter-spacing:.13em;font-size:11px;font-weight:800}.muted{color:#91a3b4}label{display:block;margin:16px 0 7px;font-size:13px}input{width:100%;min-width:0;padding:13px;border-radius:10px;border:1px solid #2a3548;background:#090e17;color:white;font:inherit}input:focus{outline:2px solid #76e4d1;outline-offset:1px}button{width:100%;padding:13px;margin-top:16px;background:#8de8d6;color:#061412;border:0;border-radius:10px;font:inherit;font-weight:800;cursor:pointer}.err{color:#ff9f9f;font-size:12px;overflow-wrap:anywhere}.symbol{display:grid;place-items:center;width:44px;height:44px;border:1px solid #2c5958;border-radius:13px;background:#102b30;color:#8de8d6;font-size:23px;margin-top:24px}</style><style id="abyss-premium-upgrade">
:root{color-scheme:dark;--abyss-bg:#070a10;--abyss-panel:#101722;--abyss-line:#263748;--abyss-mint:#8de8d6;--abyss-text:#edf3fb;--abyss-muted:#9aabbd}
html{scroll-behavior:smooth}body{background-color:var(--abyss-bg)}body:before{content:"";position:fixed;inset:0;pointer-events:none;z-index:-1;background:radial-gradient(ellipse at 80% -10%,rgba(43,130,125,.16),transparent 42%),radial-gradient(ellipse at 0% 40%,rgba(37,66,107,.13),transparent 42%)}
.card,.panel,.box,.section,.stat,.metric,.client-card{border-color:var(--abyss-line)!important;box-shadow:0 12px 36px rgba(0,0,0,.14);transition:border-color .18s ease,transform .18s ease,box-shadow .18s ease}
button,.btn,a.button{transition:filter .15s ease,transform .15s ease,box-shadow .15s ease}button:hover,.btn:hover,a.button:hover{filter:brightness(1.08);transform:translateY(-1px)}
button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--abyss-mint);outline-offset:3px}
input,select,textarea{max-width:100%;min-width:0}table{display:block;max-width:100%;overflow-x:auto;border-collapse:collapse}main,.container,.wrap{min-width:0}
@media(max-width:600px){body{font-size:14px}main,.container,.wrap{padding-left:12px!important;padding-right:12px!important}.card,.panel,.box{border-radius:15px!important}.row{flex-wrap:wrap}.row>*{max-width:100%}button,.btn{min-height:42px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style></head><body><main class="card"><div class="mint">◈ ABYSSPANEL · PRIVATE CONTROL</div><div class="symbol">A</div><h1>خوش برگشتی.</h1><p class="muted">برای مدیریت سرویس‌ها وارد پنل شو.</p><form method="post"><input type="hidden" name="csrf_token" value="{{CSRF}}"><label for="username">نام کاربری</label><input id="username" name="username" value="admin" autocomplete="username" required><label for="password">رمز عبور</label><input id="password" type="password" name="password" autocomplete="current-password" required><p class="err">{{ERROR}}</p><button>ورود به پنل ↗</button></form></main></body></html>'''
DASH='''<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AbyssPanel</title><style>
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
</style></head><body><main class="wrap">
<header class="top"><div><b>A / ABYSSPANEL</b><div class="mint" data-i18n="tagline">پنل مدیریت خصوصی</div></div><div class="tools"><button id="langBtn" onclick="toggleLanguage()">English</button><button onclick="changePassword()" data-i18n="changePassword">تغییر رمز عبور</button><button onclick="load()" data-i18n="refresh">به‌روزرسانی</button><button onclick="location.href='/logout'" data-i18n="logout">خروج</button></div></header>
<section class="stats"><div class="card"><span data-i18n="total">کل کاربران</span><div class="num" id="total">—</div></div><div class="card"><span data-i18n="active">کاربران فعال</span><div class="num" id="active">—</div></div><div class="card"><span data-i18n="xray">وضعیت Xray</span><div class="num" id="xray">—</div></div></section>
<section class="card"><div class="row"><div><div class="section-title" data-i18n="clients">مدیریت کاربران</div><div class="small" data-i18n="clientHelp">ساخت سرویس، کنترل دسترسی و مدیریت لینک اشتراک</div></div><div style="min-width:min(100%,260px)"><input id="search" placeholder="جست‌وجوی نام یا شناسه…" oninput="renderClients()" data-i18n-placeholder="search"></div></div>
<div class="fields"><input id="name" maxlength="64" placeholder="نام کاربر" data-i18n-placeholder="name"><input id="days" type="number" min="1" max="3650" placeholder="مدت (روز، اختیاری)" data-i18n-placeholder="days"><input id="quota" type="number" min="1" max="100000" placeholder="حجم (GB، اختیاری)" data-i18n-placeholder="quota"><input id="note" maxlength="300" placeholder="یادداشت (اختیاری)" data-i18n-placeholder="note"></div><div class="row" style="margin-top:9px"><span class="small" data-i18n="optional">خالی گذاشتن مدت و حجم یعنی نامحدود.</span><button class="primary" onclick="add()" data-i18n="create">+ ساخت کاربر</button></div><div id="clients" style="margin-top:12px"></div></section>
<section class="card" id="backupCard"><div class="section-title">پشتیبان‌گیری و بازیابی</div><div class="small">فایل پشتیبان شامل اطلاعات حساس کاربران است؛ آن را محرمانه نگه دار.</div><div class="tools" style="margin-top:12px"><button class="primary" onclick="location.href='/api/backup'">دریافت نسخه پشتیبان</button><input id="restoreFile" type="file" accept=".sqlite3,.db,application/vnd.sqlite3"><button class="danger" onclick="restoreBackup()">بازیابی از فایل</button></div></section><section class="card" id="resellerCard"><div class="section-title">زیرپنل‌ها و تقسیم حجم</div><div class="small">بخشی از حجم تخصیص‌یافته‌ات را به یک زیرپنل بده. مجموع حجم سرویس‌ها و زیرپنل‌ها از سهمیه‌ات بیشتر نمی‌شود.</div><div class="fields"><input id="resellerUsername" maxlength="48" placeholder="نام کاربری زیرپنل"><input id="resellerPassword" type="password" placeholder="رمز عبور حداقل ۱۴ نویسه"><input id="resellerQuota" type="number" min="0.1" step="0.1" placeholder="حجم اختصاصی (GB)"><button class="primary" onclick="addReseller()">ساخت زیرپنل</button></div><div id="resellerList" style="margin-top:12px"></div><div id="allocationStatus" class="small"></div></section><section class="card" id="settingsCard"><div class="section-title" data-i18n="settings">تنظیمات اتصال</div><div class="small" data-i18n="settingsHelp">پروفایل‌های قابل ارائه در اشتراک و Xray را فعال یا غیرفعال کن.</div><div id="profileSettings" class="profile-grid"></div></section><section class="card"><div id="status" class="small">در حال بررسی اتصال پنل…</div></section><section class="card"><div class="section-title" data-i18n="events">رویدادهای اخیر</div><div id="events"></div></section></main><dialog id="subDialog"><div class="modal-top"><div><h2 data-i18n="subTitle">مدیریت لینک اشتراک</h2><div id="subClientName" class="small"></div></div><button onclick="closeSub()" aria-label="بستن">✕</button></div><div class="sub-layout"><div><div class="sub-field"><label for="pageUrl" data-i18n="sharePage">صفحه اشتراک</label><input id="pageUrl" readonly></div><div class="sub-buttons"><button class="primary" onclick="copyField('pageUrl')" data-i18n="copyPage">کپی لینک صفحه</button><a class="button-link" id="openPage" target="_blank" rel="noopener" data-i18n="openPage">باز کردن صفحه</a></div><div class="sub-field"><label for="rawUrl" data-i18n="rawSubscription">لینک خام اشتراک برای کلاینت</label><input id="rawUrl" readonly></div><div class="sub-buttons"><button class="primary" onclick="copyField('rawUrl')" data-i18n="copyRaw">کپی لینک خام</button></div></div><div><img id="subQr" class="qr-preview" alt="QR code" width="170" height="170"><div class="small" style="text-align:center" data-i18n="qrHint">برای واردکردن سریع، QR را اسکن کن.</div></div></div></dialog><script src="/dashboard.js" defer></script></body></html>'''

DASH_JS=r'''let csrf='',allClients=[],lang=localStorage.getItem('abyss-lang')||'fa';
const words={
fa:{tagline:'پنل مدیریت خصوصی',changePassword:'تغییر رمز عبور',refresh:'به‌روزرسانی',logout:'خروج',total:'کل کاربران',active:'کاربران فعال',xray:'وضعیت Xray',clients:'مدیریت کاربران',clientHelp:'ساخت سرویس، کنترل دسترسی و مدیریت لینک اشتراک',search:'جست‌وجوی نام یا شناسه…',name:'نام کاربر',days:'مدت (روز، اختیاری)',quota:'حجم (GB، اختیاری)',note:'یادداشت (اختیاری)',optional:'خالی گذاشتن مدت و حجم یعنی نامحدود.',create:'+ ساخت کاربر',events:'رویدادهای اخیر',settings:'تنظیمات اتصال',settingsHelp:'پروفایل‌های قابل ارائه در اشتراک و Xray را فعال یا غیرفعال کن.',profileWs:'WebSocket',profileUpgrade:'HTTPUpgrade',profileXhttpAuto:'XHTTP · auto',profileXhttpPacket:'XHTTP · packet-up',online:'فعال',starting:'در حال راه‌اندازی',notInstalled:'نصب نیست',paused:'متوقف',used:'مصرف‌شده',unlimited:'نامحدود',expires:'انقضا',noExpiry:'بدون انقضا',subscription:'لینک اشتراک',copy:'کپی لینک',edit:'ویرایش',resetUsage:'ریست مصرف',subTitle:'مدیریت لینک اشتراک',sharePage:'صفحه اشتراک برای کاربر',rawSubscription:'لینک خام اشتراک برای کلاینت',copyPage:'کپی لینک صفحه',copiedPage:'لینک صفحه کپی شد.',copyRaw:'کپی لینک خام',openPage:'باز کردن صفحه',qrHint:'برای واردکردن سریع، QR را اسکن کن.',editName:'نام کاربر:',editNote:'یادداشت:',editDays:'مدت از امروز به روز (خالی = نامحدود):',editQuota:'حجم GB (خالی = نامحدود):',editSuccess:'مشخصات کاربر به‌روزرسانی شد.',resetConfirm:'مصرف ثبت‌شده این کاربر صفر شود؟',resetSuccess:'مصرف کاربر صفر شد.',pause:'توقف',enable:'فعال‌سازی',revoke:'حذف',noClients:'کاربری ثبت نشده است.',noResults:'موردی پیدا نشد.',connected:'اتصال پنل برقرار است.',apiError:'خطای API پنل: ',confirmRevoke:'این کاربر و دسترسی او حذف شود؟',copied:'لینک اشتراک کپی شد.',copyFail:'کپی خودکار ممکن نبود؛ لینک را کپی کن:',currentPassword:'رمز عبور فعلی:',newPassword:'رمز جدید (حداقل ۱۴ نویسه و شامل حرف و عدد):',passwordChanged:'رمز عبور تغییر کرد.',passwordRule:'رمز باید حداقل ۱۴ نویسه و شامل حروف و اعداد باشد.',createError:'ساخت کاربر ناموفق بود: ',changeError:'تغییر رمز ناموفق بود: ',xrayError:'آفلاین',subscriptionError:'دریافت لینک ناموفق بود: '},
en:{tagline:'PRIVATE CONTROL PANEL',changePassword:'Change password',refresh:'Refresh',logout:'Sign out',total:'Total clients',active:'Active clients',xray:'Xray status',clients:'Client management',clientHelp:'Create services, control access and manage subscription links',search:'Search by name or ID…',name:'Client name',days:'Duration (days, optional)',quota:'Quota (GB, optional)',note:'Note (optional)',optional:'Leave duration and quota empty for unlimited access.',create:'+ Create client',events:'Recent events',settings:'Connection settings',settingsHelp:'Enable or disable the profiles available in Xray and client subscriptions.',profileWs:'WebSocket',profileUpgrade:'HTTPUpgrade',profileXhttpAuto:'XHTTP · auto',profileXhttpPacket:'XHTTP · packet-up',online:'Online',starting:'Starting',notInstalled:'Not installed',paused:'Paused',used:'Used',unlimited:'Unlimited',expires:'Expires',noExpiry:'No expiry',subscription:'Subscription',copy:'Copy link',edit:'Edit',resetUsage:'Reset usage',subTitle:'Subscription links',sharePage:'Share page for the client',rawSubscription:'Raw subscription URL for clients',copyPage:'Copy page link',copiedPage:'Page link copied.',copyRaw:'Copy raw link',openPage:'Open page',qrHint:'Scan the QR code to import quickly.',editName:'Client name:',editNote:'Note:',editDays:'Duration from today in days (blank = unlimited):',editQuota:'Quota in GB (blank = unlimited):',editSuccess:'Client details updated.',resetConfirm:'Reset this client’s recorded usage to zero?',resetSuccess:'Client usage reset to zero.',pause:'Pause',enable:'Enable',revoke:'Revoke',noClients:'No clients yet.',noResults:'No matches found.',connected:'Dashboard connected successfully.',apiError:'Dashboard API error: ',confirmRevoke:'Revoke this client and remove access?',copied:'Subscription link copied.',copyFail:'Could not copy automatically. Copy this URL:',currentPassword:'Current password:',newPassword:'New password (14+ characters, letters and numbers):',passwordChanged:'Password changed.',passwordRule:'Password must be at least 14 characters and include letters and numbers.',createError:'Could not create client: ',changeError:'Could not change password: ',xrayError:'Offline',subscriptionError:'Could not get subscription: '}
};
function tr(k){return (words[lang]||words.fa)[k]||k}
function applyLanguage(){document.documentElement.lang=lang;document.documentElement.dir=lang==='fa'?'rtl':'ltr';document.querySelectorAll('[data-i18n]').forEach(el=>el.textContent=tr(el.dataset.i18n));document.querySelectorAll('[data-i18n-placeholder]').forEach(el=>el.placeholder=tr(el.dataset.i18nPlaceholder));document.getElementById('langBtn').textContent=lang==='fa'?'English':'فارسی';document.getElementById('status').textContent=tr('connected');renderClients()}
function toggleLanguage(){lang=lang==='fa'?'en':'fa';localStorage.setItem('abyss-lang',lang);applyLanguage()}
async function api(u,o={}){o.headers={...(o.headers||{}),'Content-Type':'application/json','X-CSRF-Token':csrf};let r=await fetch(u,o),d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.detail||'Request failed');return d}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function renderClients(){const term=(document.getElementById('search')?.value||'').trim().toLowerCase();const rows=allClients.filter(c=>(c.name+' '+c.id+' '+(c.note||'')).toLowerCase().includes(term));document.getElementById('clients').innerHTML=rows.map(c=>'<div class="client"><div class="client-info"><b class="client-name">'+esc(c.name)+'</b><div class="small">'+esc(c.id.slice(0,8))+' · '+(c.enabled?tr('online'):tr('paused'))+' · '+tr('used')+' '+(Number(c.used_bytes||0)/1073741824).toFixed(3)+' GB'+(c.quota_bytes===null?' / '+tr('unlimited'):(' / '+(c.quota_bytes/1073741824).toFixed(2)+' GB'))+' · '+(c.expires_at?tr('expires')+' '+esc(c.expires_at):tr('noExpiry'))+(c.note?' · '+esc(c.note):'')+'</div></div><div class="actions"><button onclick="sub(\''+c.id+'\')">'+tr('subscription')+'</button><button onclick="editClient(\''+c.id+'\')">'+tr('edit')+'</button><button onclick="resetUsage(\''+c.id+'\')">'+tr('resetUsage')+'</button><button onclick="toggle(\''+c.id+'\','+(!c.enabled)+')">'+(c.enabled?tr('pause'):tr('enable'))+'</button><button class="danger" onclick="revoke(\''+c.id+'\')">'+tr('revoke')+'</button></div></div>').join('')||(allClients.length?(term?'<p class="small">'+tr('noResults')+'</p>':''):'<p class="small">'+tr('noClients')+'</p>')}
function renderSettings(profiles){const labels={ws:'profileWs',httpupgrade:'profileUpgrade',xhttp_auto:'profileXhttpAuto',xhttp_packet_up:'profileXhttpPacket'};document.getElementById('profileSettings').innerHTML=(profiles||[]).map(p=>'<label class="profile-setting"><input type="checkbox" '+(p.enabled?'checked':'')+' onchange="setProfile(\''+p.key+'\',this.checked)"><span>'+tr(labels[p.key]||p.label)+'</span></label>').join('')}
async function setProfile(key,enabled){try{const d=await api('/api/settings/profiles',{method:'PATCH',body:JSON.stringify({profiles:{[key]:enabled}})});renderSettings(d.profiles);await load()}catch(e){alert(e.message);await load()}}
async function load(){try{let d=await api('/api/overview');csrf=d.csrf;allClients=d.clients||[];document.getElementById('backupCard').classList.toggle('hidden',d.role!=='root');document.getElementById('settingsCard').classList.toggle('hidden',d.role!=='root');document.getElementById('allocationStatus').textContent=d.role==='root'?'مدیریت سهمیه و زیرپنل‌ها':('حجم باقی‌مانده برای تخصیص: '+(Number(d.remaining_bytes||0)/1073741824).toFixed(2)+' GB');renderResellers(d.resellers||[]);document.getElementById('total').textContent=d.total;document.getElementById('active').textContent=d.active;document.getElementById('xray').textContent=d.xray.running?tr('online'):d.xray.installed?tr('starting'):tr('notInstalled');document.getElementById('events').innerHTML=d.events.map(e=>'<div class="small">'+esc(e.at)+' · '+esc(e.level)+' · '+esc(e.message)+'</div>').join('')||'—';renderClients();const settings=await api('/api/settings');renderSettings(settings.profiles);document.getElementById('status').textContent=tr('connected')}catch(e){document.getElementById('status').textContent=tr('apiError')+e.message}}
async function add(){const input=document.getElementById('name'),days=document.getElementById('days'),quota=document.getElementById('quota'),note=document.getElementById('note');try{await api('/api/clients',{method:'POST',body:JSON.stringify({name:input.value,duration_days:days.value?Number(days.value):null,quota_gb:quota.value?Number(quota.value):null,note:note.value})});input.value='';days.value='';quota.value='';note.value='';await load()}catch(e){alert(tr('createError')+e.message)}}
async function toggle(id,enabled){try{await api('/api/clients/'+id,{method:'PATCH',body:JSON.stringify({enabled})});await load()}catch(e){alert(e.message)}}
async function revoke(id){if(!confirm(tr('confirmRevoke')))return;try{await api('/api/clients/'+id,{method:'DELETE'});await load()}catch(e){alert(e.message)}}
async function sub(id){try{const d=await api('/api/clients/'+id+'/subscription');const c=allClients.find(x=>x.id===id);document.getElementById('subClientName').textContent=c?c.name:id;document.getElementById('pageUrl').value=d.page_url||d.url;document.getElementById('rawUrl').value=d.url;document.getElementById('openPage').href=d.page_url||d.url;document.getElementById('subQr').src=d.qr_url||'';document.getElementById('subDialog').showModal()}catch(e){alert(tr('subscriptionError')+e.message)}}
function closeSub(){document.getElementById('subDialog').close()}
async function copyField(id){const el=document.getElementById(id);try{await navigator.clipboard.writeText(el.value);alert(tr(id==='pageUrl'?'copiedPage':'copied'))}catch(e){el.focus();el.select();alert(tr('copyFail')+' '+el.value)}}
async function editClient(id){const c=allClients.find(x=>x.id===id);if(!c)return;const name=prompt(tr('editName'),c.name);if(name===null)return;const note=prompt(tr('editNote'),c.note||'');if(note===null)return;const daysNow=c.expires_at?Math.max(1,Math.ceil((Date.parse(c.expires_at)-Date.now())/86400000)):'';const days=prompt(tr('editDays'),String(daysNow));if(days===null)return;const quotaNow=c.quota_bytes===null?'':String((c.quota_bytes/1073741824).toFixed(2));const quota=prompt(tr('editQuota'),quotaNow);if(quota===null)return;const changes={};if(name!==c.name)changes.name=name;if(note!==(c.note||''))changes.note=note;if(days.trim()!==String(daysNow))changes.duration_days=days.trim()?Number(days):null;if(quota.trim()!==quotaNow)changes.quota_gb=quota.trim()?Number(quota):null;if(!Object.keys(changes).length)return;try{await api('/api/clients/'+id,{method:'PATCH',body:JSON.stringify(changes)});await load();alert(tr('editSuccess'))}catch(e){alert(tr('changeError')+e.message)}}
async function resetUsage(id){if(!confirm(tr('resetConfirm')))return;try{await api('/api/clients/'+id+'/reset-usage',{method:'POST'});await load();alert(tr('resetSuccess'))}catch(e){alert(e.message)}}
async function changePassword(){let current=prompt(tr('currentPassword'));if(current===null)return;let next=prompt(tr('newPassword'));if(next===null)return;if(next.length<14||!/[A-Za-z]/.test(next)||!/[0-9]/.test(next)){alert(tr('passwordRule'));return}try{await api('/api/password',{method:'POST',body:JSON.stringify({current_password:current,new_password:next})});alert(tr('passwordChanged'))}catch(e){alert(tr('changeError')+e.message)}}
function renderResellers(rows){const el=document.getElementById('resellerList');if(!rows.length){el.innerHTML='<div class="small">زیرپنلی ساخته نشده است.</div>';return}el.innerHTML=rows.map(x=>'<div class="client"><div class="client-info"><b>'+esc(x.username)+'</b><div class="small">'+(x.enabled?'فعال':'متوقف')+' · تخصیص '+(Number(x.quota_bytes)/1073741824).toFixed(2)+' GB · مصرف تخصیص‌یافته '+(Number(x.allocated_bytes||0)/1073741824).toFixed(2)+' GB · باقی‌مانده '+(Number(x.remaining_bytes||0)/1073741824).toFixed(2)+' GB</div></div><div class="actions"><button onclick="editReseller(\''+x.id+'\',\''+esc(x.username)+'\','+(Number(x.quota_bytes)/1073741824).toFixed(2)+')">ویرایش</button><button onclick="toggleReseller(\''+x.id+'\','+(!x.enabled)+')">'+(x.enabled?'توقف':'فعال‌سازی')+'</button><button class="danger" onclick="removeReseller(\''+x.id+'\')">حذف زیرپنل</button></div></div>').join('')}
async function addReseller(){const username=document.getElementById('resellerUsername').value.trim(),password=document.getElementById('resellerPassword').value,quota=Number(document.getElementById('resellerQuota').value);try{await api('/api/resellers',{method:'POST',body:JSON.stringify({username,password,quota_gb:quota})});document.getElementById('resellerUsername').value='';document.getElementById('resellerPassword').value='';document.getElementById('resellerQuota').value='';await load();alert('زیرپنل ساخته شد. نام کاربری و رمز را امن به صاحب آن بده.')}catch(e){alert('ساخت زیرپنل ناموفق بود: '+e.message)}}
async function editReseller(id,currentUsername,currentQuota){const username=prompt('نام کاربری جدید:',currentUsername);if(username===null)return;const quotaText=prompt('سهمیه کل زیرپنل (GB):',String(currentQuota));if(quotaText===null)return;const quota=Number(quotaText);if(!Number.isFinite(quota)||quota<0.1){alert('سهمیه نامعتبر است.');return}const password=prompt('رمز جدید (حداقل ۱۴ نویسه، خالی برای حفظ رمز):','');if(password===null)return;const body={username:username.trim(),quota_gb:quota};if(password)body.password=password;try{await api('/api/resellers/'+id,{method:'PATCH',body:JSON.stringify(body)});await load();alert('اطلاعات زیرپنل به‌روزرسانی شد.')}catch(e){alert('ویرایش ناموفق بود: '+e.message)}}
async function toggleReseller(id,enabled){try{await api('/api/resellers/'+id,{method:'PATCH',body:JSON.stringify({enabled})});await load()}catch(e){alert(e.message)}}
async function removeReseller(id){if(!confirm('زیرپنل حذف شود؟ ابتدا باید سهمیه‌های تخصیص‌یافته‌اش صفر باشد.'))return;try{await api('/api/resellers/'+id,{method:'DELETE'});await load()}catch(e){alert(e.message)}}
async function restoreBackup(){const f=document.getElementById('restoreFile').files[0];if(!f){alert('ابتدا فایل پشتیبان را انتخاب کن.');return}if(!confirm('بازیابی، پایگاه داده فعلی را جایگزین می‌کند. قبل از ادامه مطمئن شو فایل درست است.'))return;try{const r=await fetch('/api/restore',{method:'POST',headers:{'X-CSRF-Token':csrf,'Content-Type':'application/octet-stream'},body:await f.arrayBuffer()});const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.detail||'Restore failed');alert(d.message||'بازیابی انجام شد.');await load()}catch(e){alert('بازیابی ناموفق بود: '+e.message)}}
applyLanguage();load();'''

@app.get("/dashboard.js",response_class=PlainTextResponse)
async def dashboard_js():
    return PlainTextResponse(DASH_JS,media_type="application/javascript",headers={"Cache-Control":"no-store"})

@app.get("/",response_class=HTMLResponse)
async def home(r:Request): return HTMLResponse(DASH) if (r.session.get("admin") is True or r.session.get("reseller_id")) else RedirectResponse("/login",303)
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
    r.session.clear(); r.session["csrf"]=secrets.token_urlsafe(32)
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
    return {"profiles":[{"key":p["key"],"label":p["label"],"enabled":flags[p["key"]]} for p in PROFILES]}

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
    return {"profiles":[{"key":p["key"],"label":p["label"],"enabled":updated[p["key"]]} for p in PROFILES]}

@app.post("/api/clients")
async def create_client(r:Request):
    require_admin(r); require_csrf(r); b=await r.json(); name=valid_name(b.get("name")); note=b.get("note","")
    if not isinstance(note,str) or len(note)>300: raise HTTPException(422,"Note must be at most 300 characters")
    days=b.get("duration_days"); quota=b.get("quota_gb")
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
        c.execute("INSERT INTO clients(id,name,client_uuid,sub_token,enabled,created_at,note,expires_at,quota_bytes,used_bytes,owner_id) VALUES(?,?,?,?,1,?,?,?,?,0,?)",(cid,name,uid,token,utc_now(),note.strip(),expires,quota_bytes,owner))
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
    allowed={"enabled","name","note","duration_days","quota_gb"}
    if not isinstance(b,dict) or not b or set(b)-allowed: raise HTTPException(422,"Provide supported client fields only")
    if "enabled" in b and not isinstance(b["enabled"],bool): raise HTTPException(422,"enabled must be true or false")
    if "name" in b: b["name"]=valid_name(b["name"])
    if "note" in b and (not isinstance(b["note"],str) or len(b["note"])>300): raise HTTPException(422,"Note must be at most 300 characters")
    if "duration_days" in b and b["duration_days"] is not None and (not isinstance(b["duration_days"],(int,float)) or isinstance(b["duration_days"],bool) or not float(b["duration_days"]).is_integer() or not 1<=b["duration_days"]<=3650): raise HTTPException(422,"duration_days must be a whole number from 1 to 3650, or null")
    if "quota_gb" in b and b["quota_gb"] is not None and (not isinstance(b["quota_gb"],(int,float)) or isinstance(b["quota_gb"],bool) or not 1<=b["quota_gb"]<=100000): raise HTTPException(422,"quota_gb must be 1–100000, or null")
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
        if not updates: raise HTTPException(422,"No fields to update")
        if owner is not None and "quota_bytes" in updates:
            new_quota=updates["quota_bytes"]
            if new_quota is None: raise HTTPException(422,"Reseller clients must have a finite quota")
            allocated=int(c.execute("SELECT COALESCE(SUM(quota_bytes),0) n FROM clients WHERE owner_id=? AND id<>?",(owner,cid)).fetchone()["n"] or 0)
            children=int(c.execute("SELECT COALESCE(SUM(quota_bytes),0) n FROM resellers WHERE parent_id=?",(owner,)).fetchone()["n"] or 0)
            parent=c.execute("SELECT quota_bytes FROM resellers WHERE id=?",(owner,)).fetchone()
            if allocated+children+new_quota>int(parent["quota_bytes"]): raise HTTPException(422,"Updated quota exceeds your remaining allocation")
        c.execute("UPDATE clients SET "+", ".join(f"{key}=?" for key in updates)+" WHERE id=?",(*updates.values(),cid))
    if "enabled" in updates and updates["enabled"] != previous["enabled"]:
        try:
            await start_xray()
        except Exception as e:
            with db() as c: c.execute("UPDATE clients SET enabled=? WHERE id=?",(previous["enabled"],cid))
            try: await start_xray()
            except Exception as restore_error: event("ERROR",f"Xray recovery after failed client update also failed: {restore_error}")
            event("ERROR",f"Client update rolled back because Xray update failed: {e}")
            raise HTTPException(503,"Client status was not changed because Xray could not apply the configuration")
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
    base=get_base_url(r)
    host=urlsplit(base).hostname or PUBLIC_DOMAIN or "YOUR-RAILWAY-DOMAIN"
    links=[]
    flags=get_profile_flags()
    for profile in PROFILES:
        if not flags[profile["key"]]: continue
        network,path,mode=profile["network"],profile["path"],profile["mode"]
        proto=profile.get("protocol","vless")
        label=profile["key"].replace("_","-")
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
            userinfo=base64.urlsafe_b64encode(("2022-blake3-aes-128-gcm:"+ss_password).encode()).decode().rstrip("=")
            plugin=quote("v2ray-plugin;tls;host="+host+";path="+path,safe=";=")
            url=f"ss://{userinfo}@{host}:443?plugin={plugin}#{title}"
        else:
            continue
        links.append({"key":profile["key"],"label":profile["label"],"url":url})
    return links

def subscription_text(links):
    return base64.b64encode("\n".join(item["url"] for item in links).encode()).decode()

def render_subscription_page(client, links, sub_url, qr_url):
    quota=client["quota_bytes"]
    usage=(int(client["used_bytes"] or 0)/1024**3)
    quota_text="نامحدود" if quota is None else f"{quota/1024**3:.2f} GB"
    expiry=client["expires_at"] or "بدون انقضا"
    cards="".join(
        '<div class="profile-choice" data-profile-choice="'+html_escape(item["key"],quote=True)+'"><a class="profile" href="'+html_escape(item["url"],quote=True)+'"><span class="profile-icon">↗</span><span><b>'+html_escape(item["label"])+'</b><small>TLS · '+html_escape(item["label"])+'</small></span><span class="profile-open">باز کردن</span></a><div class="profile-marks"><button type="button" data-mark="ok" data-profile="'+html_escape(item["key"],quote=True)+'">✓ کار کرد</button><button type="button" data-mark="fail" data-profile="'+html_escape(item["key"],quote=True)+'">× کار نکرد</button><small data-result="'+html_escape(item["key"],quote=True)+'"></small></div></div>'
        for item in links
    )
    template="""<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="dark"><meta name="theme-color" content="#080b12"><title>Abyss Tunnel · اشتراک خصوصی</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 50% -15%,#163a43 0,transparent 48%),#080b12;color:#edf5f7;font:15px system-ui,-apple-system,sans-serif}.shell{width:min(820px,100%);margin:auto;padding:28px 16px 44px}.top,.row,.profile{display:flex;align-items:center;justify-content:space-between;gap:14px}.brand{font-size:12px;letter-spacing:.18em;color:#8de8d6;font-weight:800}.badge{font-size:11px;color:#8de8d6;border:1px solid #275c58;padding:7px 10px;border-radius:99px}.hero{margin:25px 0 16px;padding:25px;border:1px solid #25434b;border-radius:24px;background:linear-gradient(135deg,rgba(18,39,49,.96),rgba(13,20,32,.97));box-shadow:0 22px 70px #0005}.eyebrow{font-size:11px;color:#8de8d6;letter-spacing:.12em}.hero h1{font-size:clamp(25px,6vw,38px);line-height:1.2;margin:12px 0 8px;overflow-wrap:anywhere}.muted,small{color:#91a3b4;line-height:1.8}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:14px 0}.metric,.panel{background:#101722;border:1px solid #222f3f;border-radius:16px;padding:16px;min-width:0}.metric small{display:block;font-size:11px}.metric b{display:block;font-size:16px;margin-top:7px;overflow-wrap:anywhere}.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 12px}.section-head h2{font-size:16px;margin:0}.profiles{display:grid;gap:9px}.profile{padding:13px;text-decoration:none;color:#edf5f7;border:1px solid #263447;border-radius:13px;background:#0b111b;min-width:0}.profile:hover{border-color:#76e4d1;background:#101e27}.profile-icon{width:34px;height:34px;display:grid;place-items:center;border-radius:10px;background:#173b3c;color:#8de8d6;flex-shrink:0}.profile>span:nth-child(2){flex:1;min-width:0}.profile b,.profile small{display:block;overflow-wrap:anywhere}.profile-open{font-size:12px;color:#8de8d6;white-space:nowrap}.profile-marks{display:flex;flex-wrap:wrap;align-items:center;gap:6px;padding:6px 2px 2px}.profile-marks button{border:1px solid #2a3a4c;background:#101923;color:#b9c9d7;border-radius:8px;padding:6px 9px;font:inherit;font-size:11px;cursor:pointer}.profile-marks button[data-selected="true"][data-mark="ok"]{border-color:#4f9e87;color:#8de8d6;background:#102b26}.profile-marks button[data-selected="true"][data-mark="fail"]{border-color:#9c5a60;color:#ffb4b4;background:#2b151a}.profile-marks small{font-size:10px}.carrier-tools{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.6fr);gap:12px;align-items:center;margin-bottom:13px;padding:13px;border:1px solid #263748;border-radius:12px;background:#0b111b}.carrier-tools label{font-size:12px;color:#9aabbd}.carrier-tools select{width:100%;margin-top:6px;padding:10px;border:1px solid #2a3b4d;border-radius:9px;background:#080d15;color:#edf5f7}.share{display:grid;grid-template-columns:minmax(0,1fr) 160px;gap:16px;align-items:center}.linkbox{direction:ltr;text-align:left;width:100%;background:#080d15;color:#c6d6df;border:1px solid #2a3b4d;border-radius:10px;padding:12px;font:12px ui-monospace,monospace;overflow-wrap:anywhere}.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;margin-top:9px;padding:11px 14px;border-radius:10px;border:1px solid #2b4651;background:#152630;color:#eaf8f6;font:inherit;cursor:pointer;text-decoration:none}.btn.primary{background:#8de8d6;color:#061412;border-color:#8de8d6;font-weight:800}.qr{display:block;width:160px;max-width:100%;padding:9px;border-radius:13px;background:#fff;aspect-ratio:1}.footer{text-align:center;font-size:11px;color:#65778a;margin-top:24px;line-height:1.9}.warning{color:#d8c58a;font-size:12px;margin-top:12px;line-height:1.8}@media(max-width:560px){.shell{padding:18px 11px 30px}.hero{padding:19px;border-radius:19px}.grid{grid-template-columns:1fr 1fr}.share{grid-template-columns:1fr}.qr{width:145px;margin:8px auto 0}.profile{gap:9px;padding:11px}.profile-open{font-size:11px}.metric,.panel{padding:13px}}@media(max-width:360px){.grid{grid-template-columns:1fr}.profile-open{display:none}}
</style><style id="abyss-premium-upgrade">
:root{color-scheme:dark;--abyss-bg:#070a10;--abyss-panel:#101722;--abyss-line:#263748;--abyss-mint:#8de8d6;--abyss-text:#edf3fb;--abyss-muted:#9aabbd}
html{scroll-behavior:smooth}body{background-color:var(--abyss-bg)}body:before{content:"";position:fixed;inset:0;pointer-events:none;z-index:-1;background:radial-gradient(ellipse at 80% -10%,rgba(43,130,125,.16),transparent 42%),radial-gradient(ellipse at 0% 40%,rgba(37,66,107,.13),transparent 42%)}
.card,.panel,.box,.section,.stat,.metric,.client-card{border-color:var(--abyss-line)!important;box-shadow:0 12px 36px rgba(0,0,0,.14);transition:border-color .18s ease,transform .18s ease,box-shadow .18s ease}
button,.btn,a.button{transition:filter .15s ease,transform .15s ease,box-shadow .15s ease}button:hover,.btn:hover,a.button:hover{filter:brightness(1.08);transform:translateY(-1px)}
button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--abyss-mint);outline-offset:3px}
input,select,textarea{max-width:100%;min-width:0}table{display:block;max-width:100%;overflow-x:auto;border-collapse:collapse}main,.container,.wrap{min-width:0}
@media(max-width:600px){body{font-size:14px}main,.container,.wrap{padding-left:12px!important;padding-right:12px!important}.card,.panel,.box{border-radius:15px!important}.row{flex-wrap:wrap}.row>*{max-width:100%}button,.btn{min-height:42px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style></head><body data-sub-url="__SUB_URL__"><main class="shell"><header class="top"><div class="brand">◈ ABYSS TUNNEL</div><span class="badge">PRIVATE SUBSCRIPTION</span></header><section class="hero"><div class="eyebrow">YOUR CONNECTION · YOUR CONTROL</div><h1>اشتراک خصوصی شما</h1><p class="muted">پروفایل موردنظرت را انتخاب کن یا لینک اشتراک را در کلاینت VPN وارد کن.</p><div class="row"><div><small>نام سرویس</small><div style="font-size:19px;font-weight:800;overflow-wrap:anywhere">__CLIENT_NAME__</div></div><button class="btn primary" onclick="copySub()">کپی لینک اشتراک</button></div></section><section class="grid"><div class="metric"><small>مصرف‌شده</small><b>__USED__ GB</b></div><div class="metric"><small>حجم کل</small><b>__QUOTA__</b></div><div class="metric"><small>اعتبار تا</small><b>__EXPIRY__</b></div></section><section class="panel"><div class="section-head"><h2>پروفایل‌های اتصال</h2><span class="badge">__COUNT__ PROFILES</span></div><div class="carrier-tools"><div><label for="carrierSelect">شبکه‌ای که الان با آن تست می‌کنی</label><select id="carrierSelect"><option value="auto">انتخاب خودکار</option><option value="mci">همراه اول</option><option value="irancell">ایرانسل</option><option value="rightel">رایتل</option><option value="wifi">وای‌فای / سایر</option></select></div><div><small>نتیجهٔ هر پروفایل را روی همین دستگاه ثبت کن تا پروفایل‌های موفق برای همین شبکه بالاتر نمایش داده شوند.</small><br><small>نتیجه فقط روی همین دستگاه ذخیره می‌شود.</small></div></div><div class="profiles" id="profileChoices">__PROFILES__</div><p class="warning">اگر کلاینت شما از لینک اشتراک پشتیبانی می‌کند، لینک اصلی را وارد کنید تا همه پروفایل‌ها یکجا اضافه شوند.</p></section><section class="panel" style="margin-top:14px"><div class="section-head"><h2>لینک اشتراک</h2><span class="badge">BASE64</span></div><div class="share"><div><input class="linkbox" readonly value="__SUB_URL__" aria-label="Subscription URL"><button class="btn primary" onclick="copySub()">کپی لینک اشتراک</button><button class="btn" onclick="window.location.href=__SUB_JSON__">دریافت اشتراک</button></div><img class="qr" src="__QR_URL__" alt="QR code for subscription link" width="160" height="160"></div></section><footer class="footer">ABYSS TUNNEL · PRIVATE BY DESIGN<br>این صفحه را فقط با صاحب سرویس به اشتراک بگذار؛ لینک اشتراک مانند رمز دسترسی عمل می‌کند.</footer></main><script>async function copySub(){const u=document.body.dataset.subUrl;try{await navigator.clipboard.writeText(u);alert('لینک اشتراک کپی شد')}catch(e){const x=document.querySelector('.linkbox');x.focus();x.select();alert('لینک را به‌صورت دستی کپی کن')}}</script><script id="abyss-profile-results">(()=>{const select=document.getElementById('carrierSelect'),list=document.getElementById('profileChoices');if(!select||!list)return;const prefix='abyss-profile-results:';const storageKey=()=>prefix+select.value;const read=()=>{try{return JSON.parse(localStorage.getItem(storageKey())||'{}')}catch(e){return {}}};function paint(){const data=read();list.querySelectorAll('[data-profile-choice]').forEach(card=>{const key=card.dataset.profileChoice,value=data[key]||'';card.querySelectorAll('[data-mark]').forEach(b=>b.dataset.selected=String(b.dataset.mark===value));const out=card.querySelector('[data-result]');if(out)out.textContent=value==='ok'?'برای این شبکه موفق بود':value==='fail'?'برای این شبکه ناموفق بود':''});const cards=[...list.querySelectorAll('[data-profile-choice]')];cards.sort((a,b)=>{const rank=x=>({ok:0,'':1,fail:2})[data[x.dataset.profileChoice]||''];return rank(a)-rank(b)});cards.forEach(x=>list.appendChild(x))}select.value=localStorage.getItem(prefix+'carrier')||'auto';select.addEventListener('change',()=>{localStorage.setItem(prefix+'carrier',select.value);paint()});list.querySelectorAll('[data-mark]').forEach(b=>b.addEventListener('click',()=>{const d=read();d[b.dataset.profile]=b.dataset.mark;localStorage.setItem(storageKey(),JSON.stringify(d));paint()}));paint()})();</script></body></html>"""
    return (template.replace("__SUB_URL__",html_escape(sub_url,quote=True))
        .replace("__CLIENT_NAME__",html_escape(client["name"]))
        .replace("__USED__",f"{usage:.3f}")
        .replace("__QUOTA__",html_escape(quota_text))
        .replace("__EXPIRY__",html_escape(expiry))
        .replace("__PROFILES__",cards)
        .replace("__COUNT__",str(len(links)))
        .replace("__QR_URL__",html_escape(qr_url,quote=True))
        .replace("__SUB_JSON__",json.dumps(sub_url)))

@app.get("/api/clients/{cid}/subscription")
async def subscription_link(cid:str,r:Request):
    require_admin(r); require_client_access(r,cid)
    with db() as c: row=c.execute("SELECT sub_token FROM clients WHERE id=?",(cid,)).fetchone()
    if not row: raise HTTPException(404,"Client not found")
    base=get_base_url(r); token=row["sub_token"]
    return JSONResponse({"url":f"{base}/sub/{token}","page_url":f"{base}/s/{token}","qr_url":f"{base}/sub/{token}/qr"},headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"})

@app.get("/sub/{token}")
async def subscription(token:str,r:Request):
    """One shareable URL: browsers get the branded page; subscription clients get Base64."""
    client=active_subscription_client(token)
    links=make_subscription_links(client,r)
    accept=r.headers.get("accept","").lower()
    agent=r.headers.get("user-agent","").lower()
    browser_request=("text/html" in accept and any(x in agent for x in ("mozilla","chrome","safari","firefox","edg/","opr/")))
    headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow","Vary":"Accept, User-Agent"}
    if browser_request:
        base=get_base_url(r)
        page=render_subscription_page(client,links,f"{base}/sub/{token}",f"{base}/sub/{token}/qr")
        return HTMLResponse(page,headers=headers)
    return PlainTextResponse(subscription_text(links),headers=headers)

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
    return HTMLResponse(page,headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"})

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
                        raise HTTPException(422,"Incompatible AbyssPanel backup")
                    required_columns={
                        "admins":{"id","password_hash","password_changed_at"},
                        "clients":{"id","name","client_uuid","sub_token","enabled","created_at"},
                        "settings":{"key","value"},
                    }
                    for table,required in required_columns.items():
                        columns={row[1] for row in check.execute("PRAGMA table_info("+table+")")}
                        if not required.issubset(columns):
                            raise HTTPException(422,"Backup schema is incompatible with AbyssPanel")
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
            c.execute("UPDATE resellers SET "+", ".join(k+"=?" for k in updates)+" WHERE id=?",(*updates.values(),rid))
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
    return HTMLResponse("""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AbyssPanel API Docs</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css"></head><body style="margin:0;background:#080b12"><div id="swagger-ui"></div><script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:'/api-docs/openapi.json',dom_id:'#swagger-ui',deepLinking:true,persistAuthorization:false})</script></body></html>""",headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"})

@app.get("/api-docs/redoc",response_class=HTMLResponse)
async def protected_redoc_docs(r:Request):
    require_admin(r)
    return HTMLResponse("""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AbyssPanel API Reference</title></head><body style="margin:0;background:#080b12"><redoc spec-url="/api-docs/openapi.json"></redoc><script src="https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js"></script></body></html>""",headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"})

@app.get("/api-docs/openapi.json")
async def protected_openapi_schema(r:Request):
    require_admin(r)
    return app.openapi()

