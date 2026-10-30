from __future__ import annotations
import hashlib, hmac, html, json, os, re, secrets, sqlite3, time, uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.getenv("NORTHCAUSE_DATA", ROOT / "var"))
DATA.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.getenv("NORTHCAUSE_DB", DATA / "northcause.sqlite3"))
EVIDENCE_DIR = Path(os.getenv("NORTHCAUSE_EVIDENCE", DATA / "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD = 2 * 1024 * 1024
ALLOWED = {".log", ".txt", ".json", ".ndjson", ".csv", ".yaml", ".yml"}
SESSION_TTL = 8 * 3600
app = FastAPI(title="Northcause", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=ROOT / "app" / "static"), name="static")
templates = Jinja2Templates(directory=ROOT / "app" / "templates")
templates.env.filters["from_json"] = json.loads


def now() -> str: return datetime.now(timezone.utc).isoformat()
def uid(prefix: str) -> str: return prefix + "_" + uuid.uuid4().hex[:18]

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
        conn.commit()
    finally: conn.close()

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'admin',csrf TEXT NOT NULL,created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires INTEGER NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,title TEXT NOT NULL,service TEXT NOT NULL,environment TEXT NOT NULL DEFAULT 'production',severity TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',created TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL,label TEXT NOT NULL,body TEXT NOT NULL,sha256 TEXT NOT NULL,created TEXT NOT NULL,FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS investigations(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL,result TEXT NOT NULL,created TEXT NOT NULL,FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS drafts(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL,body TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',review_reason TEXT,created TEXT NOT NULL,FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT,action TEXT NOT NULL,target TEXT,details TEXT,created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS contacts(id TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT NOT NULL,company TEXT,message TEXT NOT NULL,created TEXT NOT NULL);
        """)
        # Keep existing local pilot databases usable after adding environment context.
        incident_columns = {row["name"] for row in c.execute("PRAGMA table_info(incidents)")}
        if "environment" not in incident_columns:
            c.execute("ALTER TABLE incidents ADD COLUMN environment TEXT NOT NULL DEFAULT 'production'")
init_db()

def hash_pw(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return salt.hex() + "$" + dk.hex()
def check_pw(password: str, stored: str) -> bool:
    try:
        salt_hex, digest = stored.split("$")
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 310_000).hex(), digest)
    except Exception: return False

def audit(actor: str | None, action: str, target: str | None = None, details: dict | None = None):
    with db() as c: c.execute("INSERT INTO audit(actor,action,target,details,created) VALUES(?,?,?,?,?)",(actor,action,target,json.dumps(details or {}),now()))
def csrf(request: Request) -> str:
    return request.state.user["csrf"] if getattr(request.state,"user",None) else ""

@app.middleware("http")
async def security(request: Request, call_next):
    token=request.cookies.get("nc_session","")
    request.state.user=None
    if token:
        digest=hashlib.sha256(token.encode()).hexdigest()
        with db() as c:
            row=c.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>?",(digest,int(time.time()))).fetchone()
        request.state.user=row
    if request.method=="POST":
        origin=request.headers.get("origin")
        host=request.headers.get("host","")
        if origin:
            from urllib.parse import urlparse
            if urlparse(origin).netloc != host: return PlainTextResponse("Origin rejected",403)
    response=await call_next(request)
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Referrer-Policy"]="strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"]="default-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    return response

def page(request: Request, name: str, **ctx):
    token = csrf(request)
    active = {"/product": "product", "/security": "security", "/docs": "docs", "/pricing": "pricing"}.get(request.url.path, "")
    return templates.TemplateResponse(request=request,name=name,context={"user":request.state.user,"csrf":token,"csrf_token":token,"active":active,**ctx})
def require_user(request: Request):
    user=request.state.user
    if not user: raise HTTPException(401,"Sign-in required")
    return user
def check_csrf(request: Request, token: str):
    user=require_user(request)
    if not token or not hmac.compare_digest(token,user["csrf"]): raise HTTPException(403,"Invalid CSRF token")
    return user

def get_incident(incident_id: str, user):
    with db() as c: row=c.execute("SELECT * FROM incidents WHERE id=? AND user_id=?",(incident_id,user["id"])).fetchone()
    if not row: raise HTTPException(404,"Incident not found")
    return row

@app.get("/",response_class=HTMLResponse)
def home(request: Request): return page(request,"home.html",title="Find it. Fix it. Prove it.")
@app.get("/product",response_class=HTMLResponse)
def product(request: Request): return page(request,"product.html",title="Product")
@app.get("/security",response_class=HTMLResponse)
def security_page(request: Request): return page(request,"security.html",title="Security")
@app.get("/docs",response_class=HTMLResponse)
def docs(request: Request): return page(request,"docs.html",title="Docs")
@app.get("/pricing",response_class=HTMLResponse)
def pricing(request: Request): return page(request,"pricing.html",title="Pricing")
@app.get("/demo",response_class=HTMLResponse)
def demo(request: Request): return page(request,"demo.html",title="Sample workspace")
@app.get("/contact",response_class=HTMLResponse)
def contact(request: Request, sent: int=0):
    token=secrets.token_urlsafe(24)
    response=page(request,"contact.html",title="Contact",sent=bool(sent),success="Thanks. Your message was saved for the Northcause team." if sent else None,csrf_token=token)
    response.set_cookie("nc_contact_csrf",token,httponly=True,samesite="strict",secure=os.getenv("NORTHCAUSE_COOKIE_SECURE","0")=="1",max_age=3600,path="/")
    return response
@app.post("/contact")
def contact_post(request: Request,name:Annotated[str,Form()],email:Annotated[str,Form()],message:Annotated[str,Form()]="",company:Annotated[str,Form()]="",csrf_token:Annotated[str,Form()]=""):
    cookie=request.cookies.get("nc_contact_csrf","")
    if not cookie or not csrf_token or not hmac.compare_digest(cookie,csrf_token): raise HTTPException(403,"Invalid CSRF token")
    if len(name)>100 or len(email)>254 or len(message)>4000 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",email): raise HTTPException(400,"Invalid form")
    with db() as c:c.execute("INSERT INTO contacts VALUES(?,?,?,?,?,?)",(uid("msg"),name,email,company[:120],message,now()))
    return RedirectResponse("/contact?sent=1",303)
@app.get("/healthz")
def health(): return {"ok":True,"mode":"local-pilot"}
@app.get("/login",response_class=HTMLResponse)
def login(request: Request):
    token=secrets.token_urlsafe(24)
    response=page(request,"login.html",title="Sign in",error="Sign-in failed" if request.query_params.get("error") else None,csrf_token=token)
    response.set_cookie("nc_login_csrf",token,httponly=True,samesite="strict",secure=os.getenv("NORTHCAUSE_COOKIE_SECURE","0")=="1",max_age=3600,path="/")
    return response
@app.post("/login")
def login_post(request: Request,email:Annotated[str,Form()],password:Annotated[str,Form()],csrf_token:Annotated[str,Form()]=""):
    cookie=request.cookies.get("nc_login_csrf","")
    if not cookie or not csrf_token or not hmac.compare_digest(cookie,csrf_token): raise HTTPException(403,"Invalid CSRF token")
    with db() as c: u=c.execute("SELECT * FROM users WHERE email=?",(email.lower().strip(),)).fetchone()
    if not u or not check_pw(password,u["password_hash"]): return RedirectResponse("/login?error=1",303)
    token=secrets.token_urlsafe(32); csrf_token=secrets.token_urlsafe(32)
    with db() as c:
        c.execute("UPDATE users SET csrf=? WHERE id=?",(csrf_token,u["id"]))
        c.execute("INSERT INTO sessions VALUES(?,?,?)",(hashlib.sha256(token.encode()).hexdigest(),u["id"],int(time.time())+SESSION_TTL))
    audit(u["id"],"auth.login",u["id"])
    response=RedirectResponse("/app",303);response.set_cookie("nc_session",token,httponly=True,secure=os.getenv("NORTHCAUSE_COOKIE_SECURE","0")=="1",samesite="strict",max_age=SESSION_TTL,path="/");response.delete_cookie("nc_login_csrf",path="/")
    return response
@app.post("/logout")
def logout(request: Request,token:Annotated[str,Form()]=""):
    user=require_user(request);check_csrf(request,token)
    raw=request.cookies.get("nc_session","")
    with db() as c:c.execute("DELETE FROM sessions WHERE token_hash=?",(hashlib.sha256(raw.encode()).hexdigest(),))
    audit(user["id"],"auth.logout",user["id"])
    r=RedirectResponse("/",303);r.delete_cookie("nc_session",path="/");return r
@app.get("/app",response_class=HTMLResponse)
def dashboard(request: Request):
    u=require_user(request)
    with db() as c: incidents=c.execute("SELECT i.*,COUNT(e.id) evidence_count FROM incidents i LEFT JOIN evidence e ON e.incident_id=i.id WHERE i.user_id=? GROUP BY i.id ORDER BY i.created DESC",(u["id"],)).fetchall()
    return page(request,"dashboard.html",title="Workspace",incidents=incidents)
@app.get("/app/incidents/new",response_class=HTMLResponse)
def incident_new(request: Request): require_user(request);return page(request,"incident_new.html",title="New incident")
@app.post("/app/incidents")
def incident_create(request: Request,title:Annotated[str,Form()],service:Annotated[str,Form()]="unknown",environment:Annotated[str,Form()]="production",severity:Annotated[str,Form()]="medium",token:Annotated[str,Form()]=""):
    u=check_csrf(request,token)
    if not title.strip() or len(title)>200 or len(service)>120 or environment not in {"development","staging","production"} or severity not in {"low","medium","high","critical"}: raise HTTPException(400,"Invalid incident fields")
    iid=uid("inc")
    with db() as c:c.execute("INSERT INTO incidents(id,user_id,title,service,environment,severity,created) VALUES(?,?,?,?,?,?,?)",(iid,u["id"],title.strip(),service.strip(),environment,severity,now()))
    audit(u["id"],"incident.create",iid);return RedirectResponse(f"/app/incidents/{iid}",303)
@app.get("/app/incidents/{incident_id}",response_class=HTMLResponse)
def incident_detail(request: Request,incident_id: str):
    u=require_user(request);incident=get_incident(incident_id,u)
    with db() as c:
        evidence=c.execute("SELECT id,label,sha256,created,length(body) bytes FROM evidence WHERE incident_id=? ORDER BY created",(incident_id,)).fetchall()
        investigations=c.execute("SELECT * FROM investigations WHERE incident_id=? ORDER BY created DESC",(incident_id,)).fetchall()
        drafts=c.execute("SELECT * FROM drafts WHERE incident_id=? ORDER BY created DESC",(incident_id,)).fetchall()
    return page(request,"incident.html",title=incident["title"],incident=incident,evidence=evidence,investigations=investigations,drafts=drafts)
@app.post("/app/incidents/{incident_id}/evidence")
async def upload(request: Request,incident_id: str,label:Annotated[str,Form()]="evidence",file:UploadFile=File(...),token:Annotated[str,Form()]=""):
    u=check_csrf(request,token);get_incident(incident_id,u)
    suffix=Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED: raise HTTPException(415,"Only text evidence files are accepted")
    if len(file.filename or "")>180: raise HTTPException(400,"Filename too long")
    with db() as c:
        count=c.execute("SELECT COUNT(*) FROM evidence WHERE incident_id=?",(incident_id,)).fetchone()[0]
    if count >= 25: raise HTTPException(413,"An incident can contain at most 25 evidence files")
    raw=await file.read(MAX_UPLOAD+1)
    if len(raw)>MAX_UPLOAD: raise HTTPException(413,"Evidence file exceeds 2 MiB")
    try: text=raw.decode("utf-8")
    except UnicodeDecodeError: raise HTTPException(400,"Evidence must be UTF-8 text")
    # Minimal secret masking before persistence. Original digest retained for integrity checks.
    digest=hashlib.sha256(raw).hexdigest()
    redacted=re.sub(r"(?i)(api[_-]?key|token|password|secret)(\s*[:=]\s*)[^\s,;]+",r"\1\2[REDACTED]",text)
    eid=uid("ev")
    with db() as c:c.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?)",(eid,incident_id,label[:120] or file.filename or "evidence",redacted,digest,now()))
    audit(u["id"],"evidence.upload",eid,{"sha256":digest,"size":len(raw)})
    return RedirectResponse(f"/app/incidents/{incident_id}",303)
@app.get("/app/evidence/{evidence_id}",response_class=HTMLResponse)
def evidence_view(request: Request,evidence_id: str):
    u=require_user(request)
    with db() as c: row=c.execute("SELECT e.*,i.user_id FROM evidence e JOIN incidents i ON i.id=e.incident_id WHERE e.id=?",(evidence_id,)).fetchone()
    if not row or row["user_id"]!=u["id"]:raise HTTPException(404,"Evidence not found")
    return page(request,"evidence.html",title=row["label"],evidence=row,lines=row["body"].splitlines())
@app.post("/app/incidents/{incident_id}/investigate")
def investigate(request: Request,incident_id: str,token:Annotated[str,Form()]=""):
    u=check_csrf(request,token);inc=get_incident(incident_id,u)
    with db() as c: evidence=c.execute("SELECT * FROM evidence WHERE incident_id=? ORDER BY created",(incident_id,)).fetchall()
    findings=[]
    signatures=[("GPU OOM",re.compile(r"out of memory|cuda.*oom|gpu.*oom",re.I)),("Kubernetes restart",re.compile(r"CrashLoopBackOff|OOMKilled",re.I)),("HTTP 5xx",re.compile(r"\b5\d\d\b|internal server error",re.I)),("Timeout",re.compile(r"timed? ?out|deadline exceeded",re.I)),("Rate limit",re.compile(r"\b429\b|rate.?limit|quota exceeded",re.I)),("Disk pressure",re.compile(r"no space left|disk pressure",re.I)),("TLS failure",re.compile(r"certificate verify failed|tls handshake",re.I)),("RAG retrieval issue",re.compile(r"retrieval.*(empty|failed|timeout)|no relevant chunks",re.I)),("Prompt injection indicator",re.compile(r"ignore (all )?(previous|prior) instructions|reveal.*system prompt",re.I))]
    for ev in evidence:
        for no,line in enumerate(ev["body"].splitlines(),1):
            for label,pat in signatures:
                if pat.search(line):findings.append({"label":label,"evidence_id":ev["id"],"line":no,"excerpt":line[:400]})
    result={"provider":"local-rules","note":"Rule-based analysis, not an AI model. Findings are hypotheses and must be reviewed.","insufficient_evidence":not findings,"claims":findings[:50]}
    with db() as c:c.execute("INSERT INTO investigations VALUES(?,?,?,?)",(uid("inv"),incident_id,json.dumps(result),now()))
    audit(u["id"],"incident.investigate",incident_id,{"provider":"local-rules","claims":len(findings)})
    return RedirectResponse(f"/app/incidents/{incident_id}",303)
@app.post("/app/incidents/{incident_id}/draft")
def draft(request: Request,incident_id: str,body:Annotated[str,Form()],token:Annotated[str,Form()]=""):
    u=check_csrf(request,token);get_incident(incident_id,u)
    if len(body)>3000:raise HTTPException(413,"Draft too large")
    did=uid("draft")
    with db() as c:c.execute("INSERT INTO drafts VALUES(?,?,?,'pending',NULL,?)",(did,incident_id,body,now()))
    audit(u["id"],"remediation.draft",did);return RedirectResponse(f"/app/incidents/{incident_id}",303)
@app.post("/app/drafts/{draft_id}/decision")
def decide(request: Request,draft_id: str,decision:Annotated[str,Form()],reason:Annotated[str,Form()],token:Annotated[str,Form()]=""):
    u=check_csrf(request,token)
    if u["role"]!="admin":raise HTTPException(403,"Admin only")
    if decision not in {"approved","rejected"} or not reason.strip() or len(reason)>500:raise HTTPException(400,"Choose a decision and provide a reason")
    with db() as c:
        d=c.execute("SELECT d.*,i.user_id FROM drafts d JOIN incidents i ON i.id=d.incident_id WHERE d.id=?",(draft_id,)).fetchone()
        if not d or d["user_id"]!=u["id"]:raise HTTPException(404,"Draft not found")
        c.execute("UPDATE drafts SET status=?,review_reason=? WHERE id=? AND status='pending'",(decision,reason.strip(),draft_id))
    audit(u["id"],"remediation."+decision,draft_id);return RedirectResponse(f"/app/incidents/{d['incident_id']}",303)
@app.get("/app/audit",response_class=HTMLResponse)
def audit_page(request: Request):
    u=require_user(request)
    with db() as c:events=c.execute("SELECT * FROM audit WHERE actor=? ORDER BY id DESC LIMIT 200",(u["id"],)).fetchall()
    return page(request,"audit.html",title="Audit trail",events=events)
@app.get("/admin/contacts",response_class=HTMLResponse)
def contact_admin(request: Request):
    u=require_user(request)
    if u["role"]!="admin":raise HTTPException(403,"Admin only")
    with db() as c: rows=c.execute("SELECT * FROM contacts ORDER BY created DESC LIMIT 100").fetchall()
    return page(request,"contacts.html",title="Contact inbox",contacts=rows)
@app.post("/admin/contacts/{message_id}/delete")
def contact_delete(request: Request,message_id: str,token:Annotated[str,Form()]=""):
    u=check_csrf(request,token)
    if u["role"]!="admin":raise HTTPException(403,"Admin only")
    with db() as c:c.execute("DELETE FROM contacts WHERE id=?",(message_id,))
    audit(u["id"],"contact.delete",message_id);return RedirectResponse("/admin/contacts",303)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app",host="127.0.0.1",port=8000,reload=True)
