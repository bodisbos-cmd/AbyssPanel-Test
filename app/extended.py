from __future__ import annotations
import asyncio
import hashlib, hmac, io, json, os, shutil, sqlite3, tempfile, time, zipfile, secrets, uuid, http.client
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, Response

MAX_UPLOAD = 20 * 1024 * 1024
_HISTORY = []
_LAST_TRAFFIC = None

def _utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _global(panel, name):
    namespace=getattr(panel,"_globals",None)
    if isinstance(namespace,dict) and name in namespace: return namespace[name]
    return getattr(panel,name,None)

def _db_path(panel):
    return Path(_global(panel, "DB_PATH"))

def _init(panel):
    with panel.db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS api_keys(
            id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
            token_prefix TEXT NOT NULL, scopes TEXT NOT NULL, created_at TEXT NOT NULL,
            last_used_at TEXT, enabled INTEGER NOT NULL DEFAULT 1, expires_at TEXT)""")
        cols={row["name"] for row in c.execute("PRAGMA table_info(api_keys)")}
        if "expires_at" not in cols: c.execute("ALTER TABLE api_keys ADD COLUMN expires_at TEXT")
        c.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_enabled ON api_keys(enabled)")

def _admin(r, p): p.require_admin(r)
def _role(r, p, *roles): p.require_role(r, *roles)
def _csrf(r, p): p.require_csrf(r)
def _hash(token): return hashlib.sha256(token.encode()).hexdigest()
def _scopes(raw):
    try:
        v=json.loads(raw)
        return set(v) if isinstance(v,list) else set()
    except (ValueError,TypeError): return set()

def _api_auth(r,p,scope):
    _init(p)
    scheme,_,token=r.headers.get("authorization","").partition(" ")
    if scheme.lower()!="bearer" or not token or len(token)>256:
        raise HTTPException(401,"A valid Bearer API token is required",headers={"WWW-Authenticate":"Bearer"})
    digest=_hash(token)
    expired=False
    with p.db() as c:
        row=c.execute("SELECT id,name,token_hash,scopes,enabled,expires_at FROM api_keys WHERE token_hash=?",(digest,)).fetchone()
        if not row or not row["enabled"] or not hmac.compare_digest(row["token_hash"],digest):
            raise HTTPException(401,"Invalid or revoked API token",headers={"WWW-Authenticate":"Bearer"})
        if row["expires_at"] and row["expires_at"]<=_utc():
            c.execute("UPDATE api_keys SET enabled=0 WHERE id=?",(row["id"],))
            expired=True
        else:
            scopes=_scopes(row["scopes"])
            if scope not in scopes: raise HTTPException(403,"API token does not have the required permission")
            c.execute("UPDATE api_keys SET last_used_at=? WHERE id=?",(_utc(),row["id"]))
    if expired: raise HTTPException(401,"API token expired",headers={"WWW-Authenticate":"Bearer"})
    if not p.rate_check(r,"api:"+row["id"],limit=180,window=60):
        raise HTTPException(429,"API request limit reached")
    return row

def _metrics(p):
    cpu=None
    try:
        v=[int(x) for x in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
        idle=v[3]+(v[4] if len(v)>4 else 0); total=sum(v); prev=getattr(_metrics,"cpu",None); _metrics.cpu=(idle,total)
        if prev and total>prev[1]: cpu=round(100*(1-(idle-prev[0])/(total-prev[1])),1)
    except (OSError,ValueError,IndexError): pass
    mt=ma=None
    try:
        m={}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k,v=line.split(":",1); m[k]=int(v.strip().split()[0])*1024
        mt=m.get("MemTotal"); ma=m.get("MemAvailable",m.get("MemFree"))
    except (OSError,ValueError,IndexError): pass
    try:
        disk=shutil.disk_usage(_global(p,"DATA_DIR")); dt,du,df=disk.total,disk.used,disk.free
    except OSError: dt=du=df=None
    try: load=[round(float(x),2) for x in Path("/proc/loadavg").read_text().split()[:3]]
    except (OSError,ValueError): load=[]
    with p.db() as c:
        rows=c.execute("SELECT used_bytes,enabled FROM clients").fetchall()
    total_bytes=sum(max(0,int(x["used_bytes"] or 0)) for x in rows)
    now=time.monotonic(); speed=0
    global _LAST_TRAFFIC
    if _LAST_TRAFFIC:
        old_t,old_b=_LAST_TRAFFIC
        if now>old_t: speed=max(0,int((total_bytes-old_b)/(now-old_t)))
    _LAST_TRAFFIC=(now,total_bytes)
    snap={"at":_utc(),"cpu_percent":cpu,"memory_total_bytes":mt,"memory_available_bytes":ma,
      "memory_used_percent":round(100*(mt-ma)/mt,1) if mt and ma is not None else None,
      "disk_total_bytes":dt,"disk_used_bytes":du,"disk_free_bytes":df,
      "disk_used_percent":round(100*du/dt,1) if dt else None,"load_average":load,
      "traffic_bytes_per_second":speed,"recorded_traffic_bytes":total_bytes,
      "clients_total":len(rows),"clients_active":sum(bool(x["enabled"]) for x in rows),
      "xray_installed":Path(_global(p,"XRAY_BIN")).exists(),"xray_running":bool(_global(p,"xray_proc") and _global(p,"xray_proc").poll() is None),
      "metrics_scope":"container"}
    _HISTORY.append({k:snap[k] for k in ("at","cpu_percent","memory_used_percent","traffic_bytes_per_second")})
    del _HISTORY[:-60]
    return snap

def _probe_profile(profile):
    started=time.monotonic()
    result={"key":profile["key"],"label":profile["label"],"path":profile["path"],"latency_ms":None,"http_status":None,"route_ok":False,"error":None}
    connection=None
    try:
        connection=http.client.HTTPConnection("127.0.0.1",8080,timeout=0.8)
        connection.request("GET",profile["path"],headers={"Host":"localhost","Connection":"close"})
        response=connection.getresponse()
        result["http_status"]=response.status
        response.read(1)
        result["route_ok"]=result["http_status"] not in {502,503,504}
    except (http.client.HTTPException,TimeoutError,OSError) as exc:
        result["error"]="Gateway/route did not respond: "+str(exc)[:120]
    finally:
        if connection: connection.close()
    result["latency_ms"]=round((time.monotonic()-started)*1000,1)
    return result

def _download_items():
    return [
      ("Hiddify · Google Play (Android)","https://play.google.com/store/apps/details?id=app.hiddify.com"),
      ("Hiddify · App Store (iPhone/iPad)","https://apps.apple.com/app/hiddify-proxy-vpn/id6596777532"),
      ("v2rayNG · GitHub (Android)","https://github.com/2dust/v2rayNG/releases"),
      ("Hiddify · GitHub (Android/Desktop)","https://github.com/hiddify/hiddify-app/releases"),
      ("NekoBox · GitHub (Android)","https://github.com/MatsuriDayo/NekoBoxForAndroid/releases"),
      ("v2rayN · GitHub (Windows)","https://github.com/2dust/v2rayN/releases")]

def install_extended(app, namespace):
    p=type("PanelNamespace",(),namespace)
    p._globals=namespace
    _init(p)

    @app.get("/api/admin/users")
    async def list_admin_users(request:Request):
        _role(request,p,"owner")
        with p.db() as c:
            rows=[dict(x) for x in c.execute("SELECT id,username,role,enabled,created_at,password_changed_at FROM panel_admins ORDER BY created_at")]
        for row in rows: row["enabled"]=bool(row["enabled"])
        return {"users":rows}

    @app.post("/api/admin/users")
    async def create_admin_user(request:Request):
        _role(request,p,"owner"); _csrf(request,p); body=await request.json()
        if not isinstance(body,dict): raise HTTPException(422,"JSON object required")
        username=str(body.get("username","")).strip()
        password=str(body.get("password",""))
        role=body.get("role","admin")
        if not 3<=len(username)<=32 or any(not (ch.isalnum() or ch in "._-") for ch in username):
            raise HTTPException(422,"Username must be 3–32 letters, numbers, dots, dashes or underscores")
        if role not in {"admin","viewer"}: raise HTTPException(422,"Role must be admin or viewer")
        if len(password)<14 or len(password)>256 or not any(ch.isalpha() for ch in password) or not any(ch.isdigit() for ch in password):
            raise HTTPException(422,"Password must be 14–256 characters and include letters and numbers")
        now=_utc(); uid=uuid.uuid4().hex
        try:
            with p.db() as c:
                c.execute("INSERT INTO panel_admins(id,username,password_hash,role,enabled,created_at,password_changed_at) VALUES(?,?,?,?,1,?,?)",
                    (uid,username,p.password_hash(password),role,now,now))
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409,"Username already exists") from exc
        p.event("INFO",f"Created panel account {username!r} with role {role}.")
        return {"id":uid,"username":username,"role":role,"enabled":True,"created_at":now}

    @app.patch("/api/admin/users/{user_id}")
    async def update_admin_user(user_id:str,request:Request):
        _role(request,p,"owner"); _csrf(request,p); body=await request.json()
        if not isinstance(body,dict) or not body or set(body)-{"role","enabled"}:
            raise HTTPException(422,"Supported fields: role, enabled")
        if "role" in body and body["role"] not in {"admin","viewer"}:
            raise HTTPException(422,"Role must be admin or viewer")
        if "enabled" in body and not isinstance(body["enabled"],bool):
            raise HTTPException(422,"enabled must be true or false")
        if user_id==request.session.get("admin_id","owner-admin") and body.get("enabled") is False:
            raise HTTPException(400,"You cannot disable your own account")
        with p.db() as c:
            row=c.execute("SELECT id,username,role,enabled FROM panel_admins WHERE id=?",(user_id,)).fetchone()
            if not row: raise HTTPException(404,"Panel account not found")
            if row["role"]=="owner" and (body.get("enabled") is False or "role" in body):
                raise HTTPException(400,"The owner account cannot be disabled or demoted here")
            new_role=body.get("role",row["role"])
            new_enabled=int(body.get("enabled",bool(row["enabled"])))
            c.execute("UPDATE panel_admins SET role=?,enabled=? WHERE id=?",(new_role,new_enabled,user_id))
        p.event("WARNING",f"Updated panel account {row['username']!r}.")
        return {"ok":True,"id":user_id}

    @app.post("/api/admin/users/{user_id}/reset-password")
    async def reset_admin_password(user_id:str,request:Request):
        _role(request,p,"owner"); _csrf(request,p); body=await request.json()
        if not isinstance(body,dict): raise HTTPException(422,"JSON object required")
        password=str(body.get("password",""))
        if len(password)<14 or len(password)>256 or not any(ch.isalpha() for ch in password) or not any(ch.isdigit() for ch in password):
            raise HTTPException(422,"Password must be 14–256 characters and include letters and numbers")
        with p.db() as c:
            row=c.execute("SELECT username,role FROM panel_admins WHERE id=?",(user_id,)).fetchone()
            if not row: raise HTTPException(404,"Panel account not found")
            if row["role"]=="owner": raise HTTPException(400,"The owner password must be changed by signing in as the owner")
            c.execute("UPDATE panel_admins SET password_hash=?,password_changed_at=? WHERE id=?",(p.password_hash(password),_utc(),user_id))
        p.event("WARNING",f"Owner reset password for panel account {row['username']!r}.")
        return {"ok":True}

    @app.get("/api/system/metrics")
    async def system_metrics(request:Request):
        _admin(request,p)
        return {"current":_metrics(p),"history":list(_HISTORY)}

    @app.get("/api/system/profiles/check")
    async def check_profile_routes(request:Request):
        _admin(request,p)
        results=[]
        for profile in p.PROFILES:
            started=time.monotonic()
            result={"key":profile["key"],"label":profile["label"],"path":profile["path"],"latency_ms":None,"http_status":None,"route_ok":False,"error":None}
            connection=None
            try:
                connection=http.client.HTTPConnection("127.0.0.1",8080,timeout=1.5)
                connection.request("GET",profile["path"],headers={"Host":"localhost","Connection":"close"})
                resp=connection.getresponse()
                result["http_status"]=resp.status
                resp.read(1)
                result["latency_ms"]=round((time.monotonic()-started)*1000,1)
                result["route_ok"]=result["http_status"] not in {502,503,504}
            except (http.client.HTTPException,TimeoutError,OSError) as exc:
                result["latency_ms"]=round((time.monotonic()-started)*1000,1)
                result["error"]="Nginx/route did not respond: "+str(exc)[:140]
            finally:
                if connection: connection.close()
            results.append(result)
        return {"checks":results,"note":"این تست فقط مسیر HTTP داخل کانتینر تا Nginx/Xray را می‌سنجد؛ پینگ واقعی تونل یا سرعت اینترنت مشتری نیست."}

    @app.get("/api/admin/api-keys")
    async def list_api_keys(request:Request):
        _role(request,p,"owner"); _init(p)
        with p.db() as c:
            rows=[dict(x) for x in c.execute("SELECT id,name,token_prefix,scopes,created_at,last_used_at,enabled,expires_at FROM api_keys ORDER BY created_at DESC")]
        for x in rows: x["scopes"]=sorted(_scopes(x["scopes"])); x["enabled"]=bool(x["enabled"])
        return {"keys":rows}

    @app.post("/api/admin/api-keys")
    async def create_api_key(request:Request):
        _role(request,p,"owner"); _csrf(request,p); _init(p); body=await request.json()
        if not isinstance(body,dict): raise HTTPException(422,"JSON object required")
        name=p.valid_name(body.get("name"))
        if len(name)>48: raise HTTPException(422,"API key name must be at most 48 characters")
        allowed={"clients:read","clients:write","subscriptions:read","metrics:read"}
        scopes=body.get("scopes",sorted(allowed))
        if not isinstance(scopes,list) or not scopes or any(x not in allowed for x in scopes):
            raise HTTPException(422,"Choose supported API permissions")
        days=body.get("expires_in_days")
        if days is not None and (not isinstance(days,int) or isinstance(days,bool) or not 1<=days<=3650):
            raise HTTPException(422,"expires_in_days must be an integer from 1 to 3650, or null")
        expires=(datetime.now(timezone.utc)+timedelta(days=days)).isoformat(timespec="seconds") if days is not None else None
        scopes=sorted(set(scopes)); token="aby_"+secrets.token_urlsafe(36); kid=uuid.uuid4().hex
        with p.db() as c:
            c.execute("INSERT INTO api_keys(id,name,token_hash,token_prefix,scopes,created_at,enabled,expires_at) VALUES(?,?,?,?,?,?,1,?)",
              (kid,name,_hash(token),token[:12],json.dumps(scopes),_utc(),expires))
        p.event("INFO",f"Created bot API key {name!r} ({kid[:8]}).")
        return {"id":kid,"name":name,"token":token,"prefix":token[:12],"scopes":scopes,"expires_at":expires}

    @app.delete("/api/admin/api-keys/{key_id}")
    async def revoke_api_key(key_id:str,request:Request):
        _role(request,p,"owner"); _csrf(request,p); _init(p)
        with p.db() as c:
            cur=c.execute("UPDATE api_keys SET enabled=0 WHERE id=? AND enabled=1",(key_id,))
            if not cur.rowcount: raise HTTPException(404,"API key not found or already revoked")
        p.event("WARNING",f"Revoked bot API key ({key_id[:8]}).")
        return {"ok":True}

    @app.get("/api/v1/health")
    async def bot_api_health(request:Request):
        _api_auth(request,p,"clients:read")
        return {"ok":True,"service":"AbyssPanel","time":_utc()}

    @app.get("/api/v1/system/metrics")
    async def bot_api_metrics(request:Request):
        _api_auth(request,p,"metrics:read")
        return {"current":_metrics(p),"history":list(_HISTORY)}

    @app.get("/api/v1/clients")
    async def bot_api_list_clients(request:Request):
        _api_auth(request,p,"clients:read")
        return {"clients":p.get_clients()}

    @app.post("/api/v1/clients")
    async def bot_api_create_client(request:Request):
        _api_auth(request,p,"clients:write"); b=await request.json()
        if not isinstance(b,dict): raise HTTPException(422,"JSON object required")
        name=p.valid_name(b.get("name")); note=b.get("note",""); days=b.get("duration_days"); quota=b.get("quota_gb")
        if not isinstance(note,str) or len(note)>300: raise HTTPException(422,"Note must be at most 300 characters")
        if days is not None and (not isinstance(days,(int,float)) or isinstance(days,bool) or not float(days).is_integer() or days<1 or days>3650):
            raise HTTPException(422,"duration_days must be a whole number from 1 to 3650")
        if quota is not None and (not isinstance(quota,(int,float)) or isinstance(quota,bool) or not 1<=quota<=100000):
            raise HTTPException(422,"quota_gb must be 1–100000")
        expires=(datetime.now(timezone.utc)+timedelta(days=int(days))).isoformat(timespec="seconds") if days is not None else None
        quota_bytes=int(float(quota)*1024**3) if quota is not None else None
        cid,uid,token=str(uuid.uuid4()),str(uuid.uuid4()),secrets.token_urlsafe(32)
        with p.db() as c:
            c.execute("INSERT INTO clients(id,name,client_uuid,sub_token,enabled,created_at,note,expires_at,quota_bytes,used_bytes) VALUES(?,?,?,?,1,?,?,?,?,0)",
              (cid,name,uid,token,_utc(),note.strip(),expires,quota_bytes))
        try: await p.start_xray()
        except Exception as exc:
            with p.db() as c: c.execute("DELETE FROM clients WHERE id=?",(cid,))
            try: await p.start_xray()
            except Exception as recovery: p.event("ERROR",f"Bot API create rollback failed: {recovery}")
            p.event("ERROR",f"Bot API client creation rolled back: {exc}")
            raise HTTPException(503,"Xray could not apply the new client")
        p.event("INFO",f"Bot API created client {name!r} ({cid[:8]}).")
        base=p.get_base_url(request)
        return {"id":cid,"name":name,"enabled":True,"subscription_url":f"{base}/sub/{token}",
          "subscription_page_url":f"{base}/sub/{token}","expires_at":expires,"quota_bytes":quota_bytes}

    @app.patch("/api/v1/clients/{client_id}")
    async def bot_api_update_client(client_id:str,request:Request):
        _api_auth(request,p,"clients:write"); b=await request.json()
        allowed={"enabled","name","note","duration_days","quota_gb"}
        if not isinstance(b,dict) or not b or set(b)-allowed:
            raise HTTPException(422,"Supported fields: enabled, name, note, duration_days, quota_gb")
        if "enabled" in b and not isinstance(b["enabled"],bool): raise HTTPException(422,"enabled must be boolean")
        if "name" in b: b["name"]=p.valid_name(b["name"])
        if "note" in b and (not isinstance(b["note"],str) or len(b["note"])>300): raise HTTPException(422,"Note too long")
        days=b.get("duration_days"); quota=b.get("quota_gb")
        if "duration_days" in b and days is not None and (not isinstance(days,(int,float)) or isinstance(days,bool) or not float(days).is_integer() or not 1<=days<=3650):
            raise HTTPException(422,"duration_days must be a whole number from 1 to 3650, or null")
        if "quota_gb" in b and quota is not None and (not isinstance(quota,(int,float)) or isinstance(quota,bool) or not 1<=quota<=100000):
            raise HTTPException(422,"quota_gb must be 1–100000, or null")
        with p.db() as c:
            old=c.execute("SELECT * FROM clients WHERE id=?",(client_id,)).fetchone()
            if not old: raise HTTPException(404,"Client not found")
            old=dict(old)
            expires=old["expires_at"]
            if "duration_days" in b:
                expires=(datetime.now(timezone.utc)+timedelta(days=int(days))).isoformat(timespec="seconds") if days is not None else None
            quota_bytes=old["quota_bytes"]
            if "quota_gb" in b: quota_bytes=int(float(quota)*1024**3) if quota is not None else None
            c.execute("UPDATE clients SET name=?,note=?,enabled=?,expires_at=?,quota_bytes=? WHERE id=?",
                (b.get("name",old["name"]),b.get("note",old["note"]),int(b.get("enabled",bool(old["enabled"]))),expires,quota_bytes,client_id))
        try: await p.start_xray()
        except Exception as exc:
            with p.db() as c:
                c.execute("UPDATE clients SET name=?,note=?,enabled=?,expires_at=?,quota_bytes=?,used_bytes=? WHERE id=?",
                  (old["name"],old["note"],old["enabled"],old["expires_at"],old["quota_bytes"],old["used_bytes"],client_id))
            try: await p.start_xray()
            except Exception as recovery: p.event("ERROR",f"Bot API update rollback failed: {recovery}")
            raise HTTPException(503,"Xray could not apply the update") from exc
        return {"ok":True,"id":client_id}

    @app.delete("/api/v1/clients/{client_id}")
    async def bot_api_delete_client(client_id:str,request:Request):
        _api_auth(request,p,"clients:write")
        with p.db() as c:
            old=c.execute("SELECT * FROM clients WHERE id=?",(client_id,)).fetchone()
            if not old: raise HTTPException(404,"Client not found")
            old=dict(old); c.execute("DELETE FROM clients WHERE id=?",(client_id,))
        try: await p.start_xray()
        except Exception as exc:
            with p.db() as c:
                c.execute("INSERT INTO clients(id,name,client_uuid,sub_token,enabled,created_at,note,expires_at,quota_bytes,used_bytes) VALUES(?,?,?,?,?,?,?,?,?,?)",
                  tuple(old[k] for k in ("id","name","client_uuid","sub_token","enabled","created_at","note","expires_at","quota_bytes","used_bytes")))
            try: await p.start_xray()
            except Exception as recovery: p.event("ERROR",f"Bot API delete rollback failed: {recovery}")
            raise HTTPException(503,"Xray could not apply the deletion") from exc
        p.event("INFO",f"Bot API revoked client {client_id[:8]}.")
        return {"ok":True}

    @app.post("/api/v1/clients/{client_id}/reset-usage")
    async def bot_api_reset_usage(client_id:str,request:Request):
        _api_auth(request,p,"clients:write")
        with p.db() as c:
            if not c.execute("SELECT id FROM clients WHERE id=?",(client_id,)).fetchone():
                raise HTTPException(404,"Client not found")
        try:
            pending=p.read_xray_stats()
            p.apply_xray_stats(pending)
        except Exception as exc:
            p.event("WARNING",f"Usage reset for {client_id[:8]} proceeded with uncollected Xray stats: {exc}")
        with p.db() as c: c.execute("UPDATE clients SET used_bytes=0 WHERE id=?",(client_id,))
        p.event("INFO",f"Bot API reset usage for client {client_id[:8]}.")
        return {"ok":True,"id":client_id,"used_bytes":0}

    @app.get("/api/v1/clients/{client_id}/subscription")
    async def bot_api_subscription(client_id:str,request:Request):
        _api_auth(request,p,"subscriptions:read")
        with p.db() as c: row=c.execute("SELECT sub_token,enabled FROM clients WHERE id=?",(client_id,)).fetchone()
        if not row: raise HTTPException(404,"Client not found")
        base=p.get_base_url(request); token=row["sub_token"]
        return {"enabled":bool(row["enabled"]),"subscription_url":f"{base}/sub/{token}",
          "subscription_page_url":f"{base}/sub/{token}","qr_url":f"{base}/sub/{token}/qr"}

    @app.get("/api/backup")
    async def download_backup(request:Request):
        _role(request,p,"owner"); _init(p); path=_db_path(p)
        if not path.exists(): raise HTTPException(503,"Database is not initialized yet")
        with tempfile.TemporaryDirectory(prefix="abyss-backup-") as temp:
            target_path=Path(temp)/"panel.sqlite3"
            target=sqlite3.connect(str(target_path),timeout=15)
            try:
                with p.db() as source:
                    source.execute("PRAGMA wal_checkpoint(FULL)")
                    source.backup(target)
                target.commit()
            finally: target.close()
            meta={"format":"abysspanel-backup-v1","created_at":_utc(),"database":"panel.sqlite3",
              "contains":["clients","admin credential hashes","settings","events","API-key hashes"],
              "excludes":["session secret","initial password file","Xray runtime logs"]}
            buffer=io.BytesIO()
            with zipfile.ZipFile(buffer,"w",zipfile.ZIP_DEFLATED) as z:
                z.write(target_path,"panel.sqlite3"); z.writestr("metadata.json",json.dumps(meta,ensure_ascii=False,indent=2))
            p.event("INFO","Administrator downloaded a database backup.")
            return Response(buffer.getvalue(),media_type="application/zip",headers={
              "Content-Disposition":'attachment; filename="abysspanel-backup.zip"',"Cache-Control":"no-store","X-Content-Type-Options":"nosniff"})

    @app.post("/api/backup/restore")
    async def restore_backup(request:Request,backup:UploadFile=File(...)):
        _role(request,p,"owner"); _csrf(request,p); raw=await backup.read(MAX_UPLOAD+1)
        if len(raw)>MAX_UPLOAD: raise HTTPException(413,"Backup file is larger than 20 MB")
        if not raw: raise HTTPException(400,"Choose a backup ZIP file")
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                info=next((x for x in z.infolist() if x.filename=="panel.sqlite3"),None)
                if not info or info.file_size>100*1024*1024 or info.file_size<1024: raise ValueError("Database file missing or invalid size")
                if info.compress_size and info.file_size/info.compress_size>250: raise ValueError("Unsafe compression ratio")
                db_bytes=z.read(info)
        except (zipfile.BadZipFile,KeyError,ValueError,OSError) as exc:
            raise HTTPException(400,f"Invalid backup archive: {exc}") from exc
        with tempfile.TemporaryDirectory(prefix="abyss-restore-") as temp:
            root=Path(temp); restored=root/"restored.sqlite3"; previous=root/"previous.sqlite3"; restored.write_bytes(db_bytes)
            check=sqlite3.connect(f"file:{restored}?mode=ro",uri=True)
            try:
                integrity=check.execute("PRAGMA integrity_check").fetchone()[0]
                tables={x[0] for x in check.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if integrity!="ok" or not {"admins","clients","settings","events"}.issubset(tables):
                    raise HTTPException(400,"Backup database failed integrity/schema validation: integrity="+str(integrity)+", tables="+",".join(sorted(tables)))
            finally: check.close()
            path=_db_path(p); path.parent.mkdir(parents=True,exist_ok=True)
            if path.exists():
                src=sqlite3.connect(str(path),timeout=15); dst=sqlite3.connect(str(previous),timeout=15)
                try: src.execute("PRAGMA wal_checkpoint(FULL)"); src.backup(dst)
                finally: dst.close(); src.close()
            def replace(source_path):
                replacement=path.with_name(".restore-"+uuid.uuid4().hex+".sqlite3")
                shutil.copyfile(source_path,replacement)
                for suffix in ("-wal","-shm"):
                    try: Path(str(path)+suffix).unlink(missing_ok=True)
                    except OSError: pass
                os.replace(replacement,path)
            replace(restored)
            p.init_db()
            _init(p)
            try: await p.start_xray()
            except Exception as exc:
                if previous.exists():
                    replace(previous)
                    try: await p.start_xray()
                    except Exception as recovery: p.event("ERROR",f"Restore rollback restart failed: {recovery}")
                raise HTTPException(503,"Restore rolled back because Xray rejected the restored configuration") from exc
        p.event("WARNING","Administrator restored a panel database backup.")
        return {"ok":True,"message":"Backup restored successfully"}

    @app.get("/s/{token}/diagnostics")
    async def subscription_diagnostics(token:str,request:Request):
        if not p.rate_check(request,"subdiag:"+token[:16],limit=8,window=60):
            raise HTTPException(429,"Too many diagnostic checks; wait a minute and retry")
        client=p.active_subscription_client(token); flags=p.get_profile_flags(); links=p.make_subscription_links(client,request)
        expires=client.get("expires_at"); expired=bool(expires and expires<=_utc())
        quota=client.get("quota_bytes"); used=int(client.get("used_bytes") or 0)
        remaining=None if quota is None else max(0,int(quota)-used)
        selected=[x for x in p.PROFILES if flags[x["key"]]]
        route_checks=await asyncio.gather(*(asyncio.to_thread(_probe_profile,profile) for profile in selected))
        return {"ok":not expired and (remaining is None or remaining>0) and bool(links),
          "service_enabled":bool(client["enabled"]),"expiry_ok":not expired,"quota_ok":remaining is None or remaining>0,
          "xray_installed":Path(p.XRAY_BIN).exists(),"xray_running":bool(p.xray_proc and p.xray_proc.poll() is None),
          "subscription_fetchable":True,"enabled_profiles":[x["key"] for x in selected],
          "profile_count":len(links),"used_bytes":used,"remaining_bytes":remaining,"expires_at":expires,
          "route_checks":route_checks,
          "note":"Route checks test the HTTP gateway from inside the server only; they cannot prove a working VPN tunnel or measure real client latency."}

    @app.get("/s/{token}/help",response_class=HTMLResponse)
    async def subscription_help(token:str):
        client=p.active_subscription_client(token)
        base=os.getenv("BASE_URL","").strip().rstrip("/") or ("https://"+os.getenv("RAILWAY_PUBLIC_DOMAIN","").strip() if os.getenv("RAILWAY_PUBLIC_DOMAIN") else "")
        sub=(base+"/sub/"+token) if base else ("/sub/"+token)
        cards="".join('<a class="app" href="'+p.html_escape(url,quote=True)+'" target="_blank" rel="noopener noreferrer"><b>'+p.html_escape(name)+'</b><span>صفحه رسمی دانلود ↗</span></a>' for name,url in _download_items())
        html="""<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="dark"><meta name="robots" content="noindex,nofollow"><title>Abyss Tunnel · راهنمای اتصال</title><style>*{box-sizing:border-box}body{margin:0;background:#080b12;color:#edf2ff;font:15px system-ui,-apple-system,sans-serif}main{width:min(760px,100%);margin:auto;padding:22px 14px 42px}.box{padding:18px;margin:12px 0;border:1px solid #273749;border-radius:16px;background:#101622}h1{font-size:clamp(24px,6vw,34px)}h2{font-size:17px}.muted,li{color:#9aabc0;line-height:1.9}a{color:#8de8d6}.apps{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:9px}.app{display:flex;flex-direction:column;gap:7px;padding:13px;text-decoration:none;border:1px solid #2a3b4e;border-radius:12px;color:#edf2ff;background:#0b111b}.app span{font-size:12px;color:#8de8d6}.url{direction:ltr;overflow-wrap:anywhere;padding:12px;background:#080d15;border:1px solid #2a3b4e;border-radius:9px;font-size:12px}button{border:0;border-radius:9px;background:#8de8d6;color:#07120f;padding:11px;font:inherit;font-weight:700;margin-top:8px}@media(max-width:420px){main{padding:15px 10px}.box{padding:14px}}</style></head><body><main><div class="muted">◈ ABYSS TUNNEL · راهنمای ساده</div><h1>اتصال به سرویس</h1><p class="muted">اول یکی از برنامه‌های رسمی را نصب کن؛ تنظیمات فنی را لازم نیست دستی وارد کنی.</p><section class="box"><h2>۱. انتخاب برنامه</h2><div class="apps">"""+cards+"""</div><p class="muted">برای اندروید معمولاً v2rayNG یا Hiddify گزینه‌های ساده‌ای هستند. اگر نسخه‌ای در فروشگاه رسمی در دسترس نبود، از صفحه رسمی GitHub استفاده کن و فایل متناسب با معماری دستگاه را انتخاب کن.</p></section><section class="box"><h2>۲. اتصال مستقیم</h2><ol><li>لینک اشتراک را از صفحه قبلی کپی کن.</li><li>در برنامه گزینه افزودن یا واردکردن Subscription را بزن.</li><li>لینک را وارد کن و Update/Refresh را بزن.</li><li>یک پروفایل انتخاب کن و Connect را بزن؛ مجوز VPN را فقط در پنجره خود سیستم تأیید کن.</li></ol><div class="url">"""+p.html_escape(sub,quote=True)+"""</div><button onclick="navigator.clipboard.writeText(document.querySelector('.url').textContent).then(()=>alert('کپی شد')).catch(()=>alert('لینک را دستی کپی کن'))">کپی لینک اشتراک</button></section><section class="box"><h2>۳. اگر وصل نشد</h2><ol><li>در صفحه اشتراک «بررسی اتصال» را اجرا کن.</li><li>اینترنت و دسترسی به دامنه را بررسی کن.</li><li>یک پروفایل دیگر را امتحان کن؛ پینگ به اپراتور، مسیر شبکه و شلوغی بستگی دارد.</li><li>برنامه را از منبع رسمی به‌روزرسانی و اشتراک را دوباره Refresh کن.</li><li>اگر مشکل ماند، اسکرین‌شات خطا و نام اپراتور را برای پشتیبانی بفرست؛ لینک اشتراک را عمومی منتشر نکن.</li></ol></section><p class="muted">لینک اشتراک مانند رمز دسترسی است؛ عمومی منتشرش نکن.</p></main></body></html>"""
        return HTMLResponse(html,headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"})

    @app.middleware("http")
    async def abyss_extras(request:Request,call_next):
        response=await call_next(request); path=request.url.path
        if (path.startswith("/s/") or path.startswith("/sub/")) and path.count("/") == 2 and response.status_code == 404:
            message = "این اشتراک در دسترس نیست؛ ممکن است غیرفعال یا منقضی شده باشد."
            channel = os.getenv("ABYSS_CHANNEL_URL", "").strip()
            parsed = urlsplit(channel) if channel else None
            support = ""
            if parsed and parsed.scheme == "https" and parsed.hostname in {"t.me", "www.t.me", "telegram.me"}:
                support = '<a href="' + p.html_escape(channel, quote=True) + '" rel="noopener noreferrer">ارتباط با پشتیبانی ↗</a>'
            return HTMLResponse(
                '<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Abyss Tunnel · اشتراک در دسترس نیست</title><body style="margin:0;min-height:100vh;display:grid;place-items:center;background:#080b12;color:#edf2ff;font:15px system-ui;padding:20px"><main style="width:min(480px,100%);padding:25px;border:1px solid #273749;border-radius:18px;background:#101622"><div style="color:#8de8d6">◈ ABYSS TUNNEL</div><h1>اشتراک در دسترس نیست</h1><p style="line-height:1.9;color:#9aabc0">' + message + '</p>' + support + '</main></body></html>',
                status_code=404, headers={"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"})
        if "text/html" not in response.headers.get("content-type","") or response.status_code!=200: return response
        if not (path=="/" or ((path.startswith("/s/") or path.startswith("/sub/")) and path.count("/")==2)): return response
        try: body=b"".join([part async for part in response.body_iterator]).decode("utf-8")
        except Exception: return response
        if path=="/" and request.session.get("admin") is True:
            css="""<style id="abyss-extra-css">#abyssMenuButton{position:fixed;z-index:1200;top:14px;left:14px;width:44px;height:44px;border:1px solid #2a4651;border-radius:13px;background:#101923;color:#8de8d6;font-size:23px;box-shadow:0 8px 28px #0006}#abyssDrawer{position:fixed;z-index:1199;inset:0 auto 0 0;width:min(290px,86vw);padding:76px 15px 20px;background:#0d131e;border-right:1px solid #2b3a4d;box-shadow:25px 0 90px #0008;transform:translateX(-105%);transition:transform .22s ease;overflow:auto}#abyssDrawer.open{transform:translateX(0)}#abyssDrawer h3{color:#8de8d6;letter-spacing:.12em;font-size:12px;padding:0 10px}#abyssDrawer button{display:block;width:100%;text-align:right;margin:5px 0;padding:12px;border-radius:10px;background:#111c28;border:1px solid #263749;color:#e6eef8}#abyssShade{display:none;position:fixed;inset:0;z-index:1198;background:#02050bc7;backdrop-filter:blur(3px)}#abyssShade.open{display:block}.extra-grid{display:contents}.extra-box{background:#101622;border:1px solid #273749;border-radius:14px;padding:15px;min-width:0}.extra-box h3{font-size:15px;margin:0 0 10px}.extra-box p{color:#94a6ba;font-size:12px;line-height:1.8}.extra-box input,.extra-box select{width:100%;margin:5px 0;background:#090e17;color:#eef4ff;border:1px solid #2a3548;border-radius:8px;padding:10px}.extra-box button{margin:5px 3px 0 0}.metric-row{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}.metric-pill{padding:10px;border:1px solid #273749;border-radius:10px;background:#0b111b}.metric-pill small{display:block;color:#91a3b4}.metric-pill b{font-size:18px}.gauge-row{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;justify-items:center;margin:18px 0}.gauge-item{display:grid;justify-items:center;gap:8px;min-width:0;text-align:center}.gauge-item small{color:#9aabc0;font-size:11px}.gauge{--value:0;width:78px;height:78px;border-radius:50%;display:grid;place-items:center;background:conic-gradient(#76e4d1 calc(var(--value)*1%),#263748 0);position:relative;transition:background .45s ease}.gauge:before{content:'';position:absolute;inset:7px;border-radius:50%;background:#101622;border:1px solid #263749}.gauge span{position:relative;z-index:1;font-size:12px;font-weight:800;color:#e8f6f4}@media(max-width:600px){.gauge-row{grid-template-columns:repeat(2,minmax(0,1fr))}}#apiKeyList{overflow-wrap:anywhere}.api-key-row{border-top:1px solid #273749;padding:9px 0;display:flex;justify-content:space-between;gap:8px;align-items:center}@media(max-width:600px){#abyssMenuButton{top:10px;left:10px}.wrap{padding-top:62px}.metric-row{grid-template-columns:1fr 1fr}}@media(prefers-reduced-motion:reduce){#abyssDrawer{transition:none}}#abyssMenuButton,#abyssDrawer,#abyssShade{display:none!important}</style>"""
            nav="""<button id="abyssMenuButton" aria-label="باز کردن منو" aria-expanded="false">☰</button><div id="abyssShade"></div><nav id="abyssDrawer" aria-label="منوی اصلی"><h3>◈ ABYSS TUNNEL</h3><button data-jump="0">نمای کلی</button><button data-jump="1">مدیریت کاربران</button><button data-jump="2">پروفایل‌های اتصال</button><button data-jump="metricsPanel">پایش منابع و سرعت</button><button data-jump="apiPanel" data-owner-only>API و اتصال بات</button><button data-jump="backupPanel" data-owner-only>پشتیبان‌گیری و بازیابی</button><button data-jump="adminPanel" data-owner-only>مدیریت مدیران</button><button data-jump="eventsPanel">رویدادها</button><button onclick="changePassword()">امنیت و رمز عبور</button><button onclick="location.href='/logout'">خروج از پنل</button></nav>"""
            js="""<script id="abyss-extra-js">(()=>{const drawer=document.getElementById('abyssDrawer'),shade=document.getElementById('abyssShade'),btn=document.getElementById('abyssMenuButton');function close(){drawer.classList.remove('open');shade.classList.remove('open');btn.setAttribute('aria-expanded','false')}btn.onclick=()=>{drawer.classList.toggle('open');shade.classList.toggle('open');btn.setAttribute('aria-expanded',drawer.classList.contains('open')?'true':'false')};shade.onclick=close;drawer.querySelectorAll('[data-jump]').forEach(b=>b.onclick=()=>{const v=b.dataset.jump;let t=/^\\d+$/.test(v)?document.querySelectorAll('main.wrap > section')[Number(v)]:document.getElementById(v);if(t)t.scrollIntoView({behavior:'smooth',block:'start'});close()});const main=document.querySelector('.workspace');if(!main)return;['metricsCard','apiKeysCard','backupCard','adminUsersCard'].forEach(id=>{const el=document.getElementById(id);if(el){el.dataset.sectionPage='legacy-hidden';el.classList.add('nav-hidden')}});const eventsSection=main.querySelector('[data-section-page="events"]');if(eventsSection)eventsSection.id='eventsPanel';const metrics=document.createElement('section');metrics.className='extra-box';metrics.id='metricsPanel';metrics.dataset.sectionPage='metrics';metrics.innerHTML='<h3>پایش زنده سرویس</h3><p>شاخص‌های حلقه‌ای وضعیت کانتینر را نشان می‌دهند. سرعت بر اساس مصرف ثبت‌شده است؛ پینگ واقعی کاربر یا سرعت‌سنج اینترنت نیست.</p><div class=\"gauge-row\"><div class=\"gauge-item\"><div class=\"gauge\" id=\"gCpu\" style=\"--value:0\"><span id=\"gCpuValue\">—</span></div><small>CPU</small></div><div class=\"gauge-item\"><div class=\"gauge\" id=\"gRam\" style=\"--value:0\"><span id=\"gRamValue\">—</span></div><small>RAM</small></div><div class=\"gauge-item\"><div class=\"gauge\" id=\"gDisk\" style=\"--value:0\"><span id=\"gDiskValue\">—</span></div><small>دیسک</small></div><div class=\"gauge-item\"><div class=\"gauge\" id=\"gSpeed\" style=\"--value:0\"><span id=\"gSpeedValue\">—</span></div><small>سرعت · مقیاس ۰–۱۰ MB/s</small></div></div><div class=\"metric-row\"><div class=\"metric-pill\"><small>کاربران فعال</small><b id=\"mActive\">—</b></div><div class=\"metric-pill\"><small>Load</small><b id=\"mLoad\">—</b></div><div class=\"metric-pill\"><small>سرعت ثبت‌شده</small><b id=\"mSpeed\">—</b></div></div><p id=\"mAt\">در حال دریافت…</p>';const api=document.createElement('section');api.className='extra-box';api.id='apiPanel';api.dataset.sectionPage='apikeys';api.innerHTML='<h3>API و اتصال ربات</h3><p>کلید کامل فقط یک بار نشان داده می‌شود. آن را در متغیر امن ربات نگه دار و داخل GitHub نگذار.</p><a class=\"button-link\" href=\"/api-docs\" target=\"_blank\" rel=\"noopener\">مستندات تعاملی API ↗</a><input id=\"apiName\" maxlength=\"48\" placeholder=\"نام اتصال ربات\"><select id=\"apiExpiry\"><option value=\"\">بدون انقضا</option><option value=\"30\">انقضا پس از ۳۰ روز</option><option value=\"90\">انقضا پس از ۹۰ روز</option><option value=\"365\">انقضا پس از یک سال</option></select><label><input id=\"scopeRead\" type=\"checkbox\" checked> مشاهده کاربران</label><label><input id=\"scopeWrite\" type=\"checkbox\" checked> مدیریت کاربران</label><label><input id=\"scopeSub\" type=\"checkbox\" checked> لینک اشتراک</label><label><input id=\"scopeMetrics\" type=\"checkbox\"> پایش و آمار</label><button class=\"primary\" id=\"createApiKey\">ساخت کلید API</button><div id=\"newApiToken\"></div><div id=\"apiKeyList\">در حال بارگذاری…</div><p>API: GET/POST /api/v1/clients، PATCH/DELETE /api/v1/clients/{id}، POST /api/v1/clients/{id}/reset-usage، GET /api/v1/clients/{id}/subscription و با مجوز جدا GET /api/v1/system/metrics. احراز هویت با Bearer token.</p>';const backup=document.createElement('section');backup.className='extra-box';backup.id='backupPanel';backup.dataset.sectionPage='backup';backup.innerHTML='<h3>پشتیبان‌گیری و بازیابی</h3><p>بکاپ شامل دیتابیس کاربران، تنظیمات و هش رمزهاست؛ خصوصی نگهش دار. بازیابی جایگزین اطلاعات فعلی می‌شود.</p><button class=\"primary\" id=\"downloadBackup\">دریافت بکاپ</button><div style=\"margin-top:12px\"><input type=\"file\" id=\"restoreFileAdvanced\" accept=\".zip,application/zip\"><button class=\"danger\" id=\"restoreBackup\">بازیابی از فایل</button></div><p id=\"backupStatus\"></p>';const admins=document.createElement('section');admins.className='extra-box';admins.id='adminPanel';admins.dataset.sectionPage='admins';admins.innerHTML='<h3>مدیریت مدیران پنل</h3><p>برای همکاران حساب جدا بساز. نقش مشاهده‌گر فقط برای دیدن اطلاعات است؛ مدیر می‌تواند کاربران و پروفایل‌ها را تغییر دهد. فقط مالک می‌تواند مدیران، کلیدهای API و بکاپ را مدیریت کند.</p><div class="metric-row"><input id="adminUsernameAdvanced" maxlength="32" placeholder="نام کاربری جدید"><input id="adminPasswordAdvanced" type="password" maxlength="256" placeholder="رمز قوی، حداقل ۱۴ نویسه"><select id="adminRoleAdvanced"><option value="admin">مدیر</option><option value="viewer">فقط مشاهده</option></select><button class="primary" id="createAdmin">ساخت حساب</button></div><div id="adminUserList">در حال بارگذاری حساب‌ها…</div>';const extras=document.createElement('div');extras.className='extra-grid';extras.append(metrics,api,backup,admins);const status=main.querySelector('#status')?.closest('section');if(status)status.before(extras);else main.append(extras);const call=async(u,o={})=>{let r=await fetch(u,{...o,headers:{...(o.headers||{}),'Content-Type':'application/json','X-CSRF-Token':csrf}}),d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.detail||'Request failed');return d};const fmt=n=>n==null?'—':n<1024?n+' B/s':n<1048576?(n/1024).toFixed(1)+' KB/s':(n/1048576).toFixed(2)+' MB/s';async function mt(){try{const d=await call('/api/system/metrics'),m=d.current;const setGauge=(id,value,label)=>{const n=value==null?0:Math.max(0,Math.min(100,value));document.getElementById(id).style.setProperty('--value',n);document.getElementById(id+'Value').textContent=label};setGauge('gCpu',m.cpu_percent,m.cpu_percent==null?'—':m.cpu_percent+'%');setGauge('gRam',m.memory_used_percent,m.memory_used_percent==null?'—':m.memory_used_percent+'%');setGauge('gDisk',m.disk_used_percent,m.disk_used_percent==null?'—':m.disk_used_percent+'%');const speed=Math.max(0,Number(m.traffic_bytes_per_second)||0);setGauge('gSpeed',speed/(10*1024*1024)*100,speed<1048576?(speed/1024).toFixed(1)+'K':(speed/1048576).toFixed(1)+'M');document.getElementById('mSpeed').textContent=fmt(speed);document.getElementById('mActive').textContent=m.clients_active+'/'+m.clients_total;document.getElementById('mLoad').textContent=(m.load_average||[]).join(' / ')||'—';document.getElementById('mAt').textContent='آخرین به‌روزرسانی: '+m.at+' · Xray: '+(m.xray_running?'فعال':'غیرفعال')}catch(e){document.getElementById('mAt').textContent='خطا: '+e.message}}async function kt(){try{const d=await call('/api/admin/api-keys');document.getElementById('apiKeyList').innerHTML=d.keys.length?d.keys.map(k=>'<div class=\"api-key-row\"><span><b>'+esc(k.name)+'</b><br><small>'+esc(k.token_prefix)+' · '+(k.enabled?'فعال':'لغوشده')+' · '+esc(k.scopes.join(', '))+' · '+(k.expires_at?'انقضا: '+esc(k.expires_at):'بدون انقضا')+'</small></span>'+(k.enabled?'<button class=\"danger\" data-revoke=\"'+esc(k.id)+'\">لغو</button>':'')+'</div>').join(''):'<p>هنوز کلیدی ساخته نشده.</p>';document.querySelectorAll('[data-revoke]').forEach(b=>b.onclick=async()=>{if(confirm('این کلید فوراً باطل شود؟'))try{await call('/api/admin/api-keys/'+b.dataset.revoke,{method:'DELETE'});await kt()}catch(e){alert(e.message)}})}catch(e){document.getElementById('apiKeyList').textContent='خطا: '+e.message}}document.getElementById('createApiKey').onclick=async()=>{const scopes=[];if(document.getElementById('scopeRead').checked)scopes.push('clients:read');if(document.getElementById('scopeWrite').checked)scopes.push('clients:write');if(document.getElementById('scopeSub').checked)scopes.push('subscriptions:read');if(document.getElementById('scopeMetrics').checked)scopes.push('metrics:read');try{const d=await call('/api/admin/api-keys',{method:'POST',body:JSON.stringify({name:document.getElementById('apiName').value.trim(),scopes,expires_in_days:document.getElementById('apiExpiry').value?Number(document.getElementById('apiExpiry').value):null})});document.getElementById('newApiToken').innerHTML='<p>کلید فقط همین بار نمایش داده می‌شود.</p><input id=\"rawNewApiToken\" readonly><button id=\"copyNewApiToken\">کپی کلید</button>';document.getElementById('rawNewApiToken').value=d.token;document.getElementById('copyNewApiToken').onclick=()=>navigator.clipboard.writeText(d.token).then(()=>alert('کپی شد')).catch(()=>alert(d.token));document.getElementById('apiName').value='';await kt()}catch(e){alert(e.message)}};async function usersTick(){try{const d=await call('/api/admin/users');document.getElementById('adminUserList').innerHTML=d.users.map(u=>'<div class="api-key-row"><span><b>'+esc(u.username)+'</b><br><small>'+esc(u.role)+' · '+(u.enabled?'فعال':'غیرفعال')+'</small></span><span><select data-user-role="'+u.id+'"><option value="admin" '+(u.role==='admin'?'selected':'')+'>مدیر</option><option value="viewer" '+(u.role==='viewer'?'selected':'')+'>فقط مشاهده</option></select><button data-user-save="'+u.id+'">ذخیره</button><button data-user-reset="'+u.id+'">تغییر رمز</button><button data-user-toggle="'+u.id+'" data-enabled="'+(!u.enabled)+'">'+(u.enabled?'غیرفعال‌کردن':'فعال‌کردن')+'</button></span></div>').join('');document.querySelectorAll('[data-user-save]').forEach(b=>b.onclick=async()=>{try{await call('/api/admin/users/'+b.dataset.userSave,{method:'PATCH',body:JSON.stringify({role:document.querySelector('[data-user-role="'+b.dataset.userSave+'"]').value})});await usersTick()}catch(e){alert(e.message)}});document.querySelectorAll('[data-user-reset]').forEach(b=>b.onclick=async()=>{const password=prompt('رمز جدید، حداقل ۱۴ نویسه با حروف و عدد:');if(!password)return;try{await call('/api/admin/users/'+b.dataset.userReset+'/reset-password',{method:'POST',body:JSON.stringify({password})});alert('رمز جدید ذخیره شد؛ نشست‌های قبلی آن حساب باطل می‌شوند.')}catch(e){alert(e.message)}});document.querySelectorAll('[data-user-toggle]').forEach(b=>b.onclick=async()=>{try{await call('/api/admin/users/'+b.dataset.userToggle,{method:'PATCH',body:JSON.stringify({enabled:b.dataset.enabled==='true'})});await usersTick()}catch(e){alert(e.message)}})}catch(e){document.getElementById('adminUserList').textContent='خطا: '+e.message}}document.getElementById('createAdmin').onclick=async()=>{try{await call('/api/admin/users',{method:'POST',body:JSON.stringify({username:document.getElementById('adminUsernameAdvanced').value.trim(),password:document.getElementById('adminPasswordAdvanced').value,role:document.getElementById('adminRoleAdvanced').value})});document.getElementById('adminUsernameAdvanced').value='';document.getElementById('adminPasswordAdvanced').value='';await usersTick();alert('حساب ساخته شد. رمز را به‌صورت امن به صاحب حساب بده.')}catch(e){alert(e.message)}};document.getElementById('downloadBackup').onclick=async()=>{try{const r=await fetch('/api/backup');if(!r.ok)throw Error('دانلود بکاپ ناموفق بود');const u=URL.createObjectURL(await r.blob()),a=document.createElement('a');a.href=u;a.download='abysspanel-backup.zip';a.click();URL.revokeObjectURL(u);document.getElementById('backupStatus').textContent='بکاپ آماده شد.'}catch(e){document.getElementById('backupStatus').textContent=e.message}};document.getElementById('restoreBackup').onclick=async()=>{const f=document.getElementById('restoreFileAdvanced').files[0];if(!f){alert('اول فایل را انتخاب کن.');return}if(!confirm('اطلاعات فعلی با بکاپ جایگزین می‌شود. ادامه می‌دهی؟'))return;const fd=new FormData();fd.append('backup',f);try{const r=await fetch('/api/backup/restore',{method:'POST',headers:{'X-CSRF-Token':csrf},body:fd}),d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.detail||'بازیابی ناموفق');document.getElementById('backupStatus').textContent='بازیابی شد؛ صفحه دوباره بارگذاری می‌شود.';setTimeout(()=>location.reload(),800)}catch(e){document.getElementById('backupStatus').textContent=e.message}};document.getElementById('checkProfiles').onclick=async()=>{const b=document.getElementById('checkProfiles'),out=document.getElementById('profileCheckResult');b.disabled=true;b.textContent='در حال بررسی…';try{const d=await call('/api/system/profiles/check');out.innerHTML=d.checks.map(x=>'<div style="padding:6px 0;border-bottom:1px solid #273749"><b>'+esc(x.label)+'</b> · '+(x.route_ok?'دروازه پاسخ داد':'خطای دروازه')+' · HTTP '+esc(String(x.http_status??'—'))+' · '+esc(String(x.latency_ms??'—'))+' ms'+(x.error?' · '+esc(x.error):'')+'</div>').join('')+'<p>'+esc(d.note)+'</p>'}catch(e){out.textContent='خطا: '+e.message}finally{b.disabled=false;b.textContent='تست مسیرهای پروفایل'}};function applyRoleVisibility(){const owner=window.abyssRole==='root';document.querySelectorAll('[data-owner-only]').forEach(el=>el.classList.toggle('hidden',!owner));['apiPanel','backupPanel','adminPanel'].forEach(id=>document.getElementById(id)?.classList.toggle('hidden',!owner));if(owner){kt();usersTick()}}window.addEventListener('load',()=>{const boot=()=>{if(!csrf){setTimeout(boot,200);return}mt();applyRoleVisibility();setInterval(mt,5000)};boot()})})();</script>"""
            body=body.replace("</head>",css+"</head>",1).replace("<body>","<body>"+nav,1).replace("</body>",js+"</body>",1)
        else:
            token=path.split("/")[2]
            diagnostic="""<section class="panel" id="abyssTroubleshoot" style="margin-top:14px"><div class="section-head"><h2>بررسی اتصال و عیب‌یابی</h2><span class="badge">SELF CHECK</span></div><p class="muted">این بررسی لینک و وضعیت سرویس را می‌سنجد؛ به‌تنهایی عبور واقعی VPN یا پینگ شبکه شما را تضمین نمی‌کند.</p><div class="row"><button class="btn primary" id="runAbyssDiagnostics">بررسی اتصال</button><a class="btn" href="/s/"""+token+"""/help">راهنمای اتصال گوشی و کامپیوتر</a></div><div id="abyssDiagnosticResult" class="muted" style="margin-top:12px" aria-live="polite">برای شروع دکمه را بزن.</div></section><section class="panel" style="margin-top:14px"><div class="section-head"><h2>دانلود برنامه‌های رسمی</h2><span class="badge">OFFICIAL SOURCES</span></div><div class="profiles"><a class="profile" href="https://play.google.com/store/apps/details?id=app.hiddify.com" target="_blank" rel="noopener noreferrer"><span class="profile-icon">↗</span><span><b>Hiddify · Google Play</b><small>فروشگاه رسمی اندروید</small></span><span class="profile-open">نصب</span></a><a class="profile" href="https://github.com/2dust/v2rayNG/releases" target="_blank" rel="noopener noreferrer"><span class="profile-icon">↗</span><span><b>v2rayNG · Android</b><small>GitHub رسمی پروژه</small></span><span class="profile-open">دانلود</span></a><a class="profile" href="https://github.com/hiddify/hiddify-app/releases" target="_blank" rel="noopener noreferrer"><span class="profile-icon">↗</span><span><b>Hiddify · Android / Desktop</b><small>انتشارهای رسمی چند سیستم‌عامل</small></span><span class="profile-open">دانلود</span></a><a class="profile" href="https://github.com/MatsuriDayo/NekoBoxForAndroid/releases" target="_blank" rel="noopener noreferrer"><span class="profile-icon">↗</span><span><b>NekoBox · Android</b><small>GitHub رسمی</small></span><span class="profile-open">دانلود</span></a><a class="profile" href="https://github.com/2dust/v2rayN/releases" target="_blank" rel="noopener noreferrer"><span class="profile-icon">↗</span><span><b>v2rayN · Windows / macOS / Linux</b><small>GitHub رسمی پروژه</small></span><span class="profile-open">دانلود</span></a></div></section><script>(()=>{const b=document.getElementById('runAbyssDiagnostics'),out=document.getElementById('abyssDiagnosticResult');b.onclick=async()=>{b.disabled=true;b.textContent='در حال بررسی…';try{const t0=performance.now();const r=await fetch('/s/"""+token+"""/diagnostics',{cache:'no-store'});const httpMs=Math.round(performance.now()-t0);const d=await r.json();if(!r.ok)throw Error(d.detail||'اشتراک در دسترس نیست');const a=[['زمان پاسخ صفحه (پینگ تونل نیست)',true,httpMs+' ms'],['دسترسی به صفحه',true],['سرویس فعال',d.service_enabled],['اعتبار زمانی',d.expiry_ok],['حجم باقی‌مانده',d.quota_ok],['هسته Xray',d.xray_running],['پروفایل فعال',d.profile_count>0]];const routes=(d.route_checks||[]).map(x=>'<div style="padding:7px 0;border-bottom:1px solid #243345">'+(x.route_ok?'✓':'⚠')+' '+x.label+' — '+(x.route_ok?'دروازه پاسخ داد':'خطای دروازه')+' · HTTP '+(x.http_status??'—')+' · '+(x.latency_ms??'—')+' ms</div>').join('');out.innerHTML=a.map(x=>'<div style="padding:7px 0;border-bottom:1px solid #243345">'+(x[1]?'✓':'⚠')+' '+x[0]+' — '+(x[2]|| (x[1]?'مناسب':'نیاز به بررسی'))+'</div>').join('')+'<h3 style="margin-top:14px">بررسی مسیرهای وب از داخل سرور</h3>'+routes+'<p class="muted">'+d.note+'</p>'}catch(e){out.textContent='بررسی ناموفق: '+e.message}finally{b.disabled=false;b.textContent='بررسی اتصال'}}})();</script>"""
            body=body.replace("</main>",diagnostic+"</main>",1)
            channel=os.getenv("ABYSS_CHANNEL_URL","").strip(); label=os.getenv("ABYSS_CHANNEL_TEXT","کانال رسمی Abyss Tunnel").strip()[:80]
            parsed=urlsplit(channel) if channel else None
            if parsed and parsed.scheme=="https" and parsed.hostname in {"t.me","www.t.me","telegram.me"}:
                ad='<section class="panel" style="margin-top:14px"><div class="section-head"><h2>'+p.html_escape(label)+'</h2><span class="badge">OFFICIAL</span></div><a class="btn" href="'+p.html_escape(channel,quote=True)+'" target="_blank" rel="noopener noreferrer">ورود به کانال ↗</a></section>'
                body=body.replace("</main>",ad+"</main>",1)
        headers=dict(response.headers); headers.pop("content-length",None); headers.pop("content-encoding",None)
        return Response(content=body,status_code=response.status_code,headers=headers,media_type="text/html",background=response.background)
