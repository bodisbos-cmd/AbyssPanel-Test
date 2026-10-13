from __future__ import annotations
import asyncio, base64, hashlib, hmac, json, logging, os, secrets, sqlite3, subprocess, time, uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

APP_NAME="AbyssPanel-Test"
DATA_DIR=Path(os.getenv("DATA_DIR","/data")); DATA_DIR.mkdir(parents=True,exist_ok=True)
DB_PATH=DATA_DIR/"panel.sqlite3"; XRAY_CONFIG=DATA_DIR/"xray.json"
XRAY_BIN=os.getenv("XRAY_BIN","/usr/local/bin/xray"); PUBLIC_DOMAIN=os.getenv("RAILWAY_PUBLIC_DOMAIN","").strip()
BASE_URL=os.getenv("BASE_URL","").strip().rstrip("/")
LOG=logging.getLogger("abysspanel"); logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO").upper())
xray_proc=None; xray_lock=asyncio.Lock()

def utc_now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def db():
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(DB_PATH,timeout=15); c.row_factory=sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON"); c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA busy_timeout=15000")
    return c
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
        CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY,name TEXT NOT NULL,client_uuid TEXT NOT NULL UNIQUE,sub_token TEXT NOT NULL UNIQUE,enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,note TEXT NOT NULL DEFAULT '',expires_at TEXT,quota_bytes INTEGER,used_bytes INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,level TEXT NOT NULL,message TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_clients_created ON clients(created_at DESC);
        """)
        if not c.execute("SELECT id FROM admins WHERE id=1").fetchone():
            # Easy first login; change this default password immediately after deployment.
            pw="admin"; c.execute("INSERT INTO admins VALUES(1,?,?)",(password_hash(pw),utc_now()))
            p=DATA_DIR/"INITIAL_ADMIN_PASSWORD.txt"; p.write_text("Username: admin\nPassword: admin\n",encoding="utf-8")
            try: p.chmod(0o600)
            except OSError: pass
            if os.getenv("ABYSS_TEST_MODE")!="1": LOG.warning("DEFAULT ADMIN CREDENTIAL username=admin password=admin; change immediately in Settings")
        # Safe in-place migration for persistent databases created by older releases.
        cols={row["name"] for row in c.execute("PRAGMA table_info(clients)")}
        for name, declaration in (("expires_at","TEXT"),("quota_bytes","INTEGER"),("used_bytes","INTEGER NOT NULL DEFAULT 0")):
            if name not in cols: c.execute(f"ALTER TABLE clients ADD COLUMN {name} {declaration}")
        c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('created_at',?)",(utc_now(),))
def event(level,message):
    LOG.log(getattr(logging,level.upper(),logging.INFO),message)
    try:
        with db() as c:
            c.execute("INSERT INTO events(at,level,message) VALUES(?,?,?)",(utc_now(),level.upper(),message[:500]))
            c.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 250)")
    except Exception: LOG.exception("event storage failed")
def get_clients(include_client_uuid=False):
    cols="id,name,client_uuid,enabled,created_at,note,expires_at,quota_bytes,used_bytes" if include_client_uuid else "id,name,enabled,created_at,note,expires_at,quota_bytes,used_bytes"
    with db() as c: return [dict(r) for r in c.execute(f"SELECT {cols} FROM clients ORDER BY created_at DESC")]
def valid_name(name:Any):
    if not isinstance(name,str): raise HTTPException(422,"Client name must be text")
    name=" ".join(name.strip().split())
    if not name or len(name)>64 or any(ord(x)<32 for x in name): raise HTTPException(422,"Client name must be 1–64 printable characters")
    return name
def make_xray_config():
    clients=[{"id":x["client_uuid"],"email":f"client-{x['id'][:8]}"} for x in get_clients(True) if x["enabled"]]
    ins=[{"tag":"api","listen":"127.0.0.1","port":10085,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":10085,"network":"tcp"}}]
    for port,network,path in [(10001,"ws","/ws"),(10002,"httpupgrade","/httpupgrade"),(10003,"xhttp","/xhttp"),(10004,"xhttp","/xhttp-packet")]:
        stream={"network":network,"security":"none"}
        stream[{"ws":"wsSettings","httpupgrade":"httpupgradeSettings","xhttp":"xhttpSettings"}[network]]={"path":path,**({"mode":"packet-up" if path.endswith("packet") else "auto"} if network=="xhttp" else {})}
        ins.append({"tag":f"in-{network}-{port}","listen":"127.0.0.1","port":port,"protocol":"vless","settings":{"clients":clients,"decryption":"none"},"streamSettings":stream})
    return {"log":{"loglevel":"warning"},"api":{"tag":"api","services":["StatsService"]},"stats":{},"policy":{"levels":{"0":{"statsUserUplink":True,"statsUserDownlink":True}}},"inbounds":ins,"outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"},{"protocol":"freedom","tag":"api"}],"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]}}
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
            xray_proc.terminate()
            try: xray_proc.wait(timeout=4)
            except subprocess.TimeoutExpired: xray_proc.kill()
        err=open(DATA_DIR/"xray-stderr.log","ab")
        try: xray_proc=subprocess.Popen([XRAY_BIN,"run","-config",str(XRAY_CONFIG)],stdout=subprocess.DEVNULL,stderr=err)
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
        # user>>>client-<8 chars>>>traffic>>>uplink/downlink
        bits=name.split(">>>")
        if len(bits)>=4 and bits[0]=="user" and bits[1].startswith("client-") and bits[2]=="traffic":
            cid=bits[1].removeprefix("client-")
            stats.setdefault(cid,0); stats[cid]+=max(0,value)
    return stats

async def enforce_client_limits():
    if not Path(XRAY_BIN).exists() or not xray_proc or xray_proc.poll() is not None: return
    stats=read_xray_stats()
    with db() as c:
        rows=[dict(x) for x in c.execute("SELECT id,name,enabled,created_at,expires_at,quota_bytes,used_bytes FROM clients")]
        for row in rows:
            if not row["enabled"]: continue
            key=row["id"][:8]
            # Xray stats are cumulative per generated email; persist only positive deltas.
            total=stats.get(key)
            if total is not None:
                old=int(row["used_bytes"] or 0)
                # Stats are reset after each successful query, so each result is an interval delta.
                used=old+total
                c.execute("UPDATE clients SET used_bytes=? WHERE id=?",(used,row["id"]))
                row["used_bytes"]=used
            expired=bool(row["expires_at"] and row["expires_at"]<=utc_now())
            exhausted=bool(row["quota_bytes"] is not None and int(row["used_bytes"] or 0)>=int(row["quota_bytes"]))
            if expired or exhausted:
                c.execute("UPDATE clients SET enabled=0 WHERE id=?",(row["id"],))
                event("INFO",f"Client {row['name']!r} automatically disabled: {'expired' if expired else 'quota reached'}.")
    # Apply any auto-disabled clients to Xray once.
    with db() as c: disabled=c.execute("SELECT COUNT(*) n FROM clients WHERE enabled=0").fetchone()["n"]
    if any(row["enabled"] and ((row["expires_at"] and row["expires_at"]<=utc_now()) or (row["quota_bytes"] is not None and int(row["used_bytes"] or 0)>=int(row["quota_bytes"]))) for row in rows):
        await start_xray()

async def monitor():
    while True:
        await asyncio.sleep(30)
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
    if r.session.get("admin") is not True: raise HTTPException(401,"Authentication required")
def require_csrf(r):
    a=r.session.get("csrf",""); b=r.headers.get("x-csrf-token","")
    if not a or not b or not hmac.compare_digest(str(a),b): raise HTTPException(403,"Invalid CSRF token")
def rate_check(r,key,limit=8,window=300):
    now=int(time.time())
    with db() as c:
        k="rate:"+key; row=c.execute("SELECT value FROM settings WHERE key=?",(k,)).fetchone()
        if not row: c.execute("INSERT INTO settings VALUES(?,?)",(k,f"{now}:1")); return True
        try: start,count=map(int,row["value"].split(":",1))
        except Exception: start,count=now,limit
        if now-start>=window: c.execute("UPDATE settings SET value=? WHERE key=?",(f"{now}:1",k)); return True
        if count>=limit: return False
        c.execute("UPDATE settings SET value=? WHERE key=?",(f"{start}:{count+1}",k)); return True

LOGIN='''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AbyssPanel</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#080b12;color:#edf2ff;font:15px system-ui}.card{width:min(390px,calc(100% - 32px));padding:30px;border:1px solid #263449;border-radius:18px;background:#101622}h1{margin:10px 0}.mint{color:#76e4d1;letter-spacing:.15em;font-size:11px}label{display:block;margin:16px 0 6px}input{width:100%;box-sizing:border-box;padding:12px;border-radius:9px;border:1px solid #2a3548;background:#090e17;color:white}button{width:100%;padding:12px;margin-top:18px;background:#76e4d1;border:0;border-radius:9px;font-weight:bold}.err{color:#ff9f9f;font-size:12px}</style></head><body><main class="card"><div class="mint">ABYSSPANEL · PRIVATE CONTROL</div><h1>Welcome back.</h1><p>Sign in to manage proxy clients.</p><form method="post"><input type="hidden" name="csrf_token" value="{{CSRF}}"><label>Username</label><input name="username" value="admin" required><label>Password</label><input type="password" name="password" required><p class="err">{{ERROR}}</p><button>Sign in ↗</button></form></main></body></html>'''
DASH='''<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AbyssPanel</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#080b12;color:#edf2ff;font:14px system-ui,-apple-system,sans-serif}.wrap{max-width:1100px;margin:auto;padding:22px 14px}.card{background:#101622;border:1px solid #222d40;border-radius:14px;padding:17px;margin:14px 0}.top,.row,.client{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.mint{color:#76e4d1;font-size:11px;letter-spacing:.12em}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.num{font-size:26px;font-weight:750}.fields{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:14px}input,button{font:inherit;border-radius:8px;padding:10px}input{min-width:0;width:100%;background:#090e17;color:white;border:1px solid #2a3548}button{cursor:pointer;background:#14202b;color:white;border:1px solid #2d3b50}button.primary{background:#76e4d1;color:#07120f;font-weight:700}.tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.client{padding:14px 0;border-top:1px solid #222d40}.client-info{min-width:180px;flex:1}.actions{display:flex;gap:6px;flex-wrap:wrap}.small{font-size:11px;color:#8794ac;line-height:1.8}.section-title{font-weight:700}.hidden{display:none!important}#status{color:#76e4d1}.client-name{overflow-wrap:anywhere}@media(max-width:700px){.stats{grid-template-columns:1fr 1fr}.fields{grid-template-columns:1fr 1fr}.wrap{padding:14px 10px}.actions button{padding:8px;font-size:12px}}@media(max-width:420px){.stats,.fields{grid-template-columns:1fr}}
</style></head><body><main class="wrap">
<header class="top"><div><b>A / ABYSSPANEL</b><div class="mint" data-i18n="tagline">پنل مدیریت خصوصی</div></div><div class="tools"><button id="langBtn" onclick="toggleLanguage()">English</button><button onclick="changePassword()" data-i18n="changePassword">تغییر رمز عبور</button><button onclick="load()" data-i18n="refresh">به‌روزرسانی</button><button onclick="location.href='/logout'" data-i18n="logout">خروج</button></div></header>
<section class="stats"><div class="card"><span data-i18n="total">کل کاربران</span><div class="num" id="total">—</div></div><div class="card"><span data-i18n="active">کاربران فعال</span><div class="num" id="active">—</div></div><div class="card"><span data-i18n="xray">وضعیت Xray</span><div class="num" id="xray">—</div></div></section>
<section class="card"><div class="row"><div><div class="section-title" data-i18n="clients">مدیریت کاربران</div><div class="small" data-i18n="clientHelp">ساخت سرویس، کنترل دسترسی و مدیریت لینک اشتراک</div></div><div style="min-width:min(100%,260px)"><input id="search" placeholder="جست‌وجوی نام یا شناسه…" oninput="renderClients()" data-i18n-placeholder="search"></div></div>
<div class="fields"><input id="name" maxlength="64" placeholder="نام کاربر" data-i18n-placeholder="name"><input id="days" type="number" min="1" max="3650" placeholder="مدت (روز، اختیاری)" data-i18n-placeholder="days"><input id="quota" type="number" min="1" max="100000" placeholder="حجم (GB، اختیاری)" data-i18n-placeholder="quota"><input id="note" maxlength="300" placeholder="یادداشت (اختیاری)" data-i18n-placeholder="note"></div><div class="row" style="margin-top:9px"><span class="small" data-i18n="optional">خالی گذاشتن مدت و حجم یعنی نامحدود.</span><button class="primary" onclick="add()" data-i18n="create">+ ساخت کاربر</button></div><div id="clients" style="margin-top:12px"></div></section>
<section class="card"><div id="status" class="small">در حال بررسی اتصال پنل…</div></section><section class="card"><div class="section-title" data-i18n="events">رویدادهای اخیر</div><div id="events"></div></section></main><script src="/dashboard.js" defer></script></body></html>'''

DASH_JS=r'''let csrf='',allClients=[],lang=localStorage.getItem('abyss-lang')||'fa';
const words={
fa:{tagline:'پنل مدیریت خصوصی',changePassword:'تغییر رمز عبور',refresh:'به‌روزرسانی',logout:'خروج',total:'کل کاربران',active:'کاربران فعال',xray:'وضعیت Xray',clients:'مدیریت کاربران',clientHelp:'ساخت سرویس، کنترل دسترسی و مدیریت لینک اشتراک',search:'جست‌وجوی نام یا شناسه…',name:'نام کاربر',days:'مدت (روز، اختیاری)',quota:'حجم (GB، اختیاری)',note:'یادداشت (اختیاری)',optional:'خالی گذاشتن مدت و حجم یعنی نامحدود.',create:'+ ساخت کاربر',events:'رویدادهای اخیر',online:'فعال',starting:'در حال راه‌اندازی',notInstalled:'نصب نیست',paused:'متوقف',used:'مصرف‌شده',unlimited:'نامحدود',expires:'انقضا',noExpiry:'بدون انقضا',subscription:'لینک اشتراک',copy:'کپی لینک',pause:'توقف',enable:'فعال‌سازی',revoke:'حذف',noClients:'کاربری ثبت نشده است.',noResults:'موردی پیدا نشد.',connected:'اتصال پنل برقرار است.',apiError:'خطای API پنل: ',confirmRevoke:'این کاربر و دسترسی او حذف شود؟',copied:'لینک اشتراک کپی شد.',copyFail:'کپی خودکار ممکن نبود؛ لینک را کپی کن:',currentPassword:'رمز عبور فعلی:',newPassword:'رمز جدید (حداقل ۱۴ نویسه و شامل حرف و عدد):',passwordChanged:'رمز عبور تغییر کرد.',passwordRule:'رمز باید حداقل ۱۴ نویسه و شامل حروف و اعداد باشد.',createError:'ساخت کاربر ناموفق بود: ',changeError:'تغییر رمز ناموفق بود: ',xrayError:'آفلاین',subscriptionError:'دریافت لینک ناموفق بود: '},
en:{tagline:'PRIVATE CONTROL PANEL',changePassword:'Change password',refresh:'Refresh',logout:'Sign out',total:'Total clients',active:'Active clients',xray:'Xray status',clients:'Client management',clientHelp:'Create services, control access and manage subscription links',search:'Search by name or ID…',name:'Client name',days:'Duration (days, optional)',quota:'Quota (GB, optional)',note:'Note (optional)',optional:'Leave duration and quota empty for unlimited access.',create:'+ Create client',events:'Recent events',online:'Online',starting:'Starting',notInstalled:'Not installed',paused:'Paused',used:'Used',unlimited:'Unlimited',expires:'Expires',noExpiry:'No expiry',subscription:'Subscription',copy:'Copy link',pause:'Pause',enable:'Enable',revoke:'Revoke',noClients:'No clients yet.',noResults:'No matches found.',connected:'Dashboard connected successfully.',apiError:'Dashboard API error: ',confirmRevoke:'Revoke this client and remove access?',copied:'Subscription link copied.',copyFail:'Could not copy automatically. Copy this URL:',currentPassword:'Current password:',newPassword:'New password (14+ characters, letters and numbers):',passwordChanged:'Password changed.',passwordRule:'Password must be at least 14 characters and include letters and numbers.',createError:'Could not create client: ',changeError:'Could not change password: ',xrayError:'Offline',subscriptionError:'Could not get subscription: '}
};
function tr(k){return (words[lang]||words.fa)[k]||k}
function applyLanguage(){document.documentElement.lang=lang;document.documentElement.dir=lang==='fa'?'rtl':'ltr';document.querySelectorAll('[data-i18n]').forEach(el=>el.textContent=tr(el.dataset.i18n));document.querySelectorAll('[data-i18n-placeholder]').forEach(el=>el.placeholder=tr(el.dataset.i18nPlaceholder));document.getElementById('langBtn').textContent=lang==='fa'?'English':'فارسی';document.getElementById('status').textContent=tr('connected');renderClients()}
function toggleLanguage(){lang=lang==='fa'?'en':'fa';localStorage.setItem('abyss-lang',lang);applyLanguage()}
async function api(u,o={}){o.headers={...(o.headers||{}),'Content-Type':'application/json','X-CSRF-Token':csrf};let r=await fetch(u,o),d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.detail||'Request failed');return d}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function renderClients(){const term=(document.getElementById('search')?.value||'').trim().toLowerCase();const rows=allClients.filter(c=>(c.name+' '+c.id+' '+(c.note||'')).toLowerCase().includes(term));document.getElementById('clients').innerHTML=rows.map(c=>'<div class="client"><div class="client-info"><b class="client-name">'+esc(c.name)+'</b><div class="small">'+esc(c.id.slice(0,8))+' · '+(c.enabled?tr('online'):tr('paused'))+' · '+tr('used')+' '+(Number(c.used_bytes||0)/1073741824).toFixed(3)+' GB'+(c.quota_bytes===null?' / '+tr('unlimited'):(' / '+(c.quota_bytes/1073741824).toFixed(2)+' GB'))+' · '+(c.expires_at?tr('expires')+' '+esc(c.expires_at):tr('noExpiry'))+(c.note?' · '+esc(c.note):'')+'</div></div><div class="actions"><button onclick="sub(\''+c.id+'\')">'+tr('subscription')+'</button><button onclick="toggle(\''+c.id+'\','+(!c.enabled)+')">'+(c.enabled?tr('pause'):tr('enable'))+'</button><button onclick="revoke(\''+c.id+'\')">'+tr('revoke')+'</button></div></div>').join('')||(allClients.length?(term?'<p class="small">'+tr('noResults')+'</p>':''):'<p class="small">'+tr('noClients')+'</p>')}
async function load(){try{let d=await api('/api/overview');csrf=d.csrf;allClients=d.clients||[];document.getElementById('total').textContent=d.total;document.getElementById('active').textContent=d.active;document.getElementById('xray').textContent=d.xray.running?tr('online'):d.xray.installed?tr('starting'):tr('notInstalled');document.getElementById('events').innerHTML=d.events.map(e=>'<div class="small">'+esc(e.at)+' · '+esc(e.level)+' · '+esc(e.message)+'</div>').join('')||'—';renderClients();document.getElementById('status').textContent=tr('connected')}catch(e){document.getElementById('status').textContent=tr('apiError')+e.message}}
async function add(){const input=document.getElementById('name'),days=document.getElementById('days'),quota=document.getElementById('quota'),note=document.getElementById('note');try{await api('/api/clients',{method:'POST',body:JSON.stringify({name:input.value,duration_days:days.value?Number(days.value):null,quota_gb:quota.value?Number(quota.value):null,note:note.value})});input.value='';days.value='';quota.value='';note.value='';await load()}catch(e){alert(tr('createError')+e.message)}}
async function toggle(id,enabled){try{await api('/api/clients/'+id,{method:'PATCH',body:JSON.stringify({enabled})});await load()}catch(e){alert(e.message)}}
async function revoke(id){if(!confirm(tr('confirmRevoke')))return;try{await api('/api/clients/'+id,{method:'DELETE'});await load()}catch(e){alert(e.message)}}
async function sub(id){try{let d=await api('/api/clients/'+id+'/subscription');try{await navigator.clipboard.writeText(d.url);alert(tr('copied'))}catch(_){prompt(tr('copyFail'),d.url)}}catch(e){alert(tr('subscriptionError')+e.message)}}
async function changePassword(){let current=prompt(tr('currentPassword'));if(current===null)return;let next=prompt(tr('newPassword'));if(next===null)return;if(next.length<14||!/[A-Za-z]/.test(next)||!/[0-9]/.test(next)){alert(tr('passwordRule'));return}try{await api('/api/password',{method:'POST',body:JSON.stringify({current_password:current,new_password:next})});alert(tr('passwordChanged'))}catch(e){alert(tr('changeError')+e.message)}}
applyLanguage();load();'''

@app.get("/dashboard.js",response_class=PlainTextResponse)
async def dashboard_js():
    return PlainTextResponse(DASH_JS,media_type="application/javascript",headers={"Cache-Control":"no-store"})

@app.get("/",response_class=HTMLResponse)
async def home(r:Request): return HTMLResponse(DASH) if r.session.get("admin") is True else RedirectResponse("/login",303)
@app.get("/login",response_class=HTMLResponse)
async def login_page(r:Request):
    t=secrets.token_urlsafe(24); r.session["login_csrf"]=t
    return HTMLResponse(LOGIN.replace("{{ERROR}}","").replace("{{CSRF}}",t))
@app.post("/login")
async def login(r:Request,username:str=Form(...),password:str=Form(...)):
    f=await r.form(); a=str(f.get("csrf_token","")); b=str(r.session.get("login_csrf",""))
    if not a or not b or not hmac.compare_digest(a,b):
        token=secrets.token_urlsafe(24); r.session["login_csrf"]=token
        return HTMLResponse(LOGIN.replace("{{ERROR}}","Session expired. Please try again.").replace("{{CSRF}}",token),status_code=403)
    ip=r.client.host if r.client else "unknown"
    if not rate_check(r,"login:"+ip):
        token=secrets.token_urlsafe(24); r.session["login_csrf"]=token
        return HTMLResponse(LOGIN.replace("{{ERROR}}","Too many attempts. Wait five minutes.").replace("{{CSRF}}",token),status_code=429)
    with db() as c: row=c.execute("SELECT password_hash FROM admins WHERE id=1").fetchone()
    if not row or username!="admin" or not verify_password(password,row["password_hash"]):
        event("WARNING","Rejected administrator sign-in attempt.")
        token=secrets.token_urlsafe(24); r.session["login_csrf"]=token
        return HTMLResponse(LOGIN.replace("{{ERROR}}","Invalid username or password.").replace("{{CSRF}}",token),status_code=401)
    r.session.clear(); r.session["admin"]=True; r.session["csrf"]=secrets.token_urlsafe(32); event("INFO","Administrator signed in.")
    return RedirectResponse("/",303)
@app.get("/logout")
async def logout(r:Request): r.session.clear(); return RedirectResponse("/login",303)
@app.get("/api/overview")
async def overview(r:Request):
    require_admin(r)
    with db() as c:
        total=c.execute("SELECT COUNT(*) n FROM clients").fetchone()["n"]; active=c.execute("SELECT COUNT(*) n FROM clients WHERE enabled=1").fetchone()["n"]
        events=[dict(x) for x in c.execute("SELECT at,level,message FROM events ORDER BY id DESC LIMIT 8")]
    return {"csrf":r.session.get("csrf",""),"total":total,"active":active,"clients":get_clients(),"events":events,"xray":{"installed":Path(XRAY_BIN).exists(),"running":bool(xray_proc and xray_proc.poll() is None)}}
@app.post("/api/clients")
async def create_client(r:Request):
    require_admin(r); require_csrf(r); b=await r.json(); name=valid_name(b.get("name")); note=b.get("note","")
    if not isinstance(note,str) or len(note)>300: raise HTTPException(422,"Note must be at most 300 characters")
    days=b.get("duration_days"); quota=b.get("quota_gb")
    if days is not None and (not isinstance(days,(int,float)) or isinstance(days,bool) or days<1 or days>3650): raise HTTPException(422,"duration_days must be 1–3650")
    if quota is not None and (not isinstance(quota,(int,float)) or isinstance(quota,bool) or quota<1 or quota>100000): raise HTTPException(422,"quota_gb must be 1–100000")
    expires=(datetime.now(timezone.utc)+__import__("datetime").timedelta(days=int(days))).isoformat(timespec="seconds") if days is not None else None
    quota_bytes=int(float(quota)*1024**3) if quota is not None else None
    cid,uid,token=str(uuid.uuid4()),str(uuid.uuid4()),secrets.token_urlsafe(32)
    with db() as c: c.execute("INSERT INTO clients(id,name,client_uuid,sub_token,enabled,created_at,note,expires_at,quota_bytes,used_bytes) VALUES(?,?,?,?,1,?,?,?,?,0)",(cid,name,uid,token,utc_now(),note.strip(),expires,quota_bytes))
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
    require_admin(r); require_csrf(r); b=await r.json()
    if not isinstance(b.get("enabled"),bool): raise HTTPException(422,"enabled must be true or false")
    with db() as c:
        row=c.execute("SELECT enabled FROM clients WHERE id=?",(cid,)).fetchone()
        if not row: raise HTTPException(404,"Client not found")
        old_enabled=int(row["enabled"])
        c.execute("UPDATE clients SET enabled=? WHERE id=?",(int(b["enabled"]),cid))
    try:
        await start_xray()
    except Exception as e:
        with db() as c: c.execute("UPDATE clients SET enabled=? WHERE id=?",(old_enabled,cid))
        try: await start_xray()
        except Exception as restore_error: event("ERROR",f"Xray recovery after failed client update also failed: {restore_error}")
        event("ERROR",f"Client update rolled back because Xray update failed: {e}")
        raise HTTPException(503,"Client status was not changed because Xray could not apply the configuration")
    event("INFO",f"Updated client {cid[:8]}."); return {"ok":True}
@app.delete("/api/clients/{cid}")
async def delete_client(cid:str,r:Request):
    require_admin(r); require_csrf(r)
    with db() as c:
        row=c.execute("SELECT id,name,client_uuid,sub_token,enabled,created_at,note FROM clients WHERE id=?",(cid,)).fetchone()
        if not row: raise HTTPException(404,"Client not found")
        previous=dict(row)
        c.execute("DELETE FROM clients WHERE id=?",(cid,))
    try:
        await start_xray()
    except Exception as e:
        with db() as c:
            c.execute("INSERT OR REPLACE INTO clients(id,name,client_uuid,sub_token,enabled,created_at,note) VALUES(?,?,?,?,?,?,?)",
                      (previous["id"],previous["name"],previous["client_uuid"],previous["sub_token"],previous["enabled"],previous["created_at"],previous["note"]))
        try: await start_xray()
        except Exception as restore_error: event("ERROR",f"Xray recovery after failed client revocation also failed: {restore_error}")
        event("ERROR",f"Client revocation rolled back because Xray update failed: {e}")
        raise HTTPException(503,"Client was not revoked because Xray could not apply the configuration")
    event("INFO",f"Revoked client {cid[:8]}."); return {"ok":True}
def get_base_url(r=None):
    if BASE_URL:return BASE_URL
    if PUBLIC_DOMAIN:return "https://"+PUBLIC_DOMAIN
    if r:return f"{r.headers.get('x-forwarded-proto','https')}://{r.headers.get('x-forwarded-host') or r.headers.get('host','localhost')}"
    return "https://YOUR-RAILWAY-DOMAIN"
@app.get("/api/clients/{cid}/subscription")
async def subscription_link(cid:str,r:Request):
    require_admin(r)
    with db() as c: row=c.execute("SELECT sub_token FROM clients WHERE id=?",(cid,)).fetchone()
    if not row: raise HTTPException(404,"Client not found")
    return {"url":f"{get_base_url(r)}/sub/{row['sub_token']}"}
@app.get("/sub/{token}",response_class=PlainTextResponse)
async def subscription(token:str,r:Request):
    if len(token)>100: raise HTTPException(404,"Not found")
    with db() as c: client=c.execute("SELECT * FROM clients WHERE sub_token=? AND enabled=1",(token,)).fetchone()
    if not client: raise HTTPException(404,"Subscription not found or disabled")
    host=(r.headers.get("x-forwarded-host") or r.headers.get("host","YOUR-RAILWAY-DOMAIN")).split(",")[0].strip().split(":")[0]
    if host in ("localhost","127.0.0.1","YOUR-RAILWAY-DOMAIN"): host=PUBLIC_DOMAIN or "YOUR-RAILWAY-DOMAIN"
    links=[]
    for network,path,mode in [("ws","/ws",None),("httpupgrade","/httpupgrade",None),("xhttp","/xhttp","auto"),("xhttp","/xhttp-packet","packet-up")]:
        q=f"type={network}&security=tls&sni={host}&fp=chrome&host={host}&path={quote(path,safe='')}&encryption=none"
        if mode: q+=f"&mode={quote(mode)}"
        label={"ws":"ws","httpupgrade":"httpupgrade","/xhttp":"xhttp-auto","/xhttp-packet":"xhttp-packet-up"}[path if path in ("/xhttp","/xhttp-packet") else network]
        links.append(f"vless://{client['client_uuid']}@{host}:443?{q}#{quote(client['name'])}-{label}")
    return PlainTextResponse(base64.b64encode("\n".join(links).encode()).decode(),headers={"Cache-Control":"no-store"})
@app.get("/health")
async def health():
    with db() as c:c.execute("SELECT 1").fetchone()
    return {"ok":True}
@app.exception_handler(Exception)
async def unhandled(r:Request,e:Exception):
    LOG.exception("Unhandled error: %s",e)
    if r.url.path.startswith("/api/"): return JSONResponse({"detail":"Internal server error"},status_code=500)
    return HTMLResponse("<h1>Internal server error</h1>",status_code=500)


@app.post("/api/password")
async def change_password(r: Request):
    require_admin(r)
    require_csrf(r)
    body = await r.json()
    current = str(body.get("current_password", ""))
    new = str(body.get("new_password", ""))
    with db() as c:
        row = c.execute("SELECT password_hash FROM admins WHERE id=1").fetchone()
        if not row or not verify_password(current, row["password_hash"]):
            raise HTTPException(403, "Current password is incorrect")
        if len(new) < 14 or len(new) > 256 or not any(ch.isalpha() for ch in new) or not any(ch.isdigit() for ch in new):
            raise HTTPException(400, "New password must be 14–256 characters and include letters and numbers")
        c.execute("UPDATE admins SET password_hash=?, password_changed_at=? WHERE id=1", (password_hash(new), utc_now()))
    event("INFO", "Administrator password changed.")
    return {"ok": True}
