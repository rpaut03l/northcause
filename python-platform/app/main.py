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
from .replay import evaluate_jsonl, evaluate_candidates, dataset_version, ReplayInputError
from .proofs import sign_record, verify_record, ensure_signing_key
from .semantic import score_cases, SemanticJudgeError
from .analysis import compute_regressions, build_timeline, rank_hypotheses, serialize_hypothesis

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.getenv("NORTHCAUSE_DATA", ROOT / "var"))
DATA.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.getenv("NORTHCAUSE_DB", DATA / "northcause.sqlite3"))
EVIDENCE_DIR = Path(os.getenv("NORTHCAUSE_EVIDENCE", DATA / "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD = 2 * 1024 * 1024
ALLOWED = {".log", ".txt", ".json", ".ndjson", ".jsonl", ".csv", ".yaml", ".yml"}
SESSION_TTL = 8 * 3600
app = FastAPI(title="NorthCause", docs_url=None, redoc_url=None)
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
        CREATE TABLE IF NOT EXISTS replay_runs(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL,user_id TEXT NOT NULL,summary TEXT NOT NULL,created TEXT NOT NULL,FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS otel_spans(span_id TEXT NOT NULL,trace_id TEXT NOT NULL,name TEXT NOT NULL,service TEXT NOT NULL,environment TEXT NOT NULL,start_ns TEXT NOT NULL,duration_ms REAL NOT NULL,status TEXT NOT NULL,attributes TEXT NOT NULL,created TEXT NOT NULL,PRIMARY KEY(trace_id,span_id));
        CREATE INDEX IF NOT EXISTS idx_otel_spans_trace ON otel_spans(trace_id);
        CREATE TABLE IF NOT EXISTS github_deliveries(delivery_id TEXT PRIMARY KEY,event TEXT NOT NULL,repository TEXT NOT NULL,ref TEXT,before_sha TEXT,after_sha TEXT,environment TEXT,status TEXT,created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS semantic_runs(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,summary TEXT NOT NULL,created TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS eval_cases(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL,label TEXT NOT NULL,expected TEXT NOT NULL,baseline TEXT NOT NULL,source_evidence_id TEXT,source_line INTEGER,reviewer TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'active',created TEXT NOT NULL,FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE);
        CREATE INDEX IF NOT EXISTS idx_eval_cases_incident ON eval_cases(incident_id);
        CREATE TABLE IF NOT EXISTS hypotheses(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL,statement TEXT NOT NULL,confidence REAL NOT NULL,evidence TEXT NOT NULL,counterevidence TEXT NOT NULL,status TEXT NOT NULL,generator TEXT NOT NULL,created TEXT NOT NULL,FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE);
        CREATE INDEX IF NOT EXISTS idx_hypotheses_incident ON hypotheses(incident_id);
        CREATE TABLE IF NOT EXISTS proof_records(id TEXT PRIMARY KEY,replay_id TEXT NOT NULL UNIQUE,incident_id TEXT NOT NULL,user_id TEXT NOT NULL,payload TEXT NOT NULL,payload_sha256 TEXT NOT NULL,previous_hash TEXT NOT NULL,record_hash TEXT NOT NULL,signature TEXT NOT NULL,public_key TEXT NOT NULL,key_fingerprint TEXT NOT NULL,created TEXT NOT NULL,FOREIGN KEY(replay_id) REFERENCES replay_runs(id) ON DELETE CASCADE,FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
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
    active = {"/product": "product", "/evidence-loop": "evidence_loop", "/security": "security", "/docs": "docs", "/pricing": "pricing", "/cloud-shell": "cloud_shell"}.get(request.url.path, "")
    from urllib.parse import quote
    public_url = os.getenv("NORTHCAUSE_PUBLIC_URL", "https://northcause.com").rstrip("/")
    share_url = public_url + "/"
    share_message = "NorthCause.com — Find it. Fix it. Prove it. Investigate AI production incidents with connected evidence. " + share_url
    whatsapp_share_url = "https://wa.me/?text=" + quote(share_message, safe="")
    return templates.TemplateResponse(request=request,name=name,context={"user":request.state.user,"csrf":token,"csrf_token":token,"active":active,"public_url":public_url,"share_url":share_url,"whatsapp_share_url":whatsapp_share_url,**ctx})
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

def constant_token_ok(request: Request, env_name: str) -> bool:
    expected = os.getenv(env_name, "")
    supplied = request.headers.get("authorization", "")
    return bool(expected and supplied.startswith("Bearer ") and hmac.compare_digest(supplied[7:], expected))

async def read_bounded(request: Request, limit: int) -> bytes:
    chunks=[]; size=0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit: raise HTTPException(413, "Request body exceeds the configured limit")
        chunks.append(chunk)
    return b"".join(chunks)

def otel_attribute_map(items) -> dict:
    # Keep only low-risk routing metadata. Prompt, completion, query, body, and user data never persist.
    allowed = {"service.name", "service.version", "deployment.environment", "deployment.environment.name", "gen_ai.system", "gen_ai.operation.name", "gen_ai.request.model", "gen_ai.response.model", "http.request.method", "http.response.status_code"}
    result = {}
    for item in items if isinstance(items, list) else []:
        key = item.get("key") if isinstance(item, dict) else None
        value = item.get("value", {}) if isinstance(item, dict) else {}
        if key in allowed and isinstance(value, dict):
            scalar = next((value[k] for k in ("stringValue", "intValue", "boolValue", "doubleValue") if k in value), None)
            if scalar is not None and len(str(scalar)) <= 160:
                result[key] = str(scalar)
    return result

def _proof_for_replay(replay_id: str, incident_id: str, user_id: str, summary: dict):
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        previous = c.execute("SELECT record_hash FROM proof_records ORDER BY created DESC,id DESC LIMIT 1").fetchone()
        previous_hash = previous["record_hash"] if previous else "0" * 64
        incident = c.execute("SELECT title,service,environment,severity FROM incidents WHERE id=?", (incident_id,)).fetchone()
        payload = {"schema": "northcause.replay-proof.v1", "replay_id": replay_id, "incident_id": incident_id,
                   "service": incident["service"], "environment": incident["environment"], "severity": incident["severity"],
                   "incident_title_sha256": hashlib.sha256(incident["title"].encode()).hexdigest(),
                   "result": summary, "created_at": now()}
        signed = sign_record(payload, previous_hash, DATA)
        proof_id = uid("proof")
        c.execute("INSERT INTO proof_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                  (proof_id,replay_id,incident_id,user_id,signed["payload"],signed["payload_sha256"],signed["previous_hash"],signed["record_hash"],signed["signature"],signed["public_key"],signed["key_fingerprint"],now()))
    return proof_id

def matched_signals(incident) -> dict:
    owner_email=os.getenv("NORTHCAUSE_INTEGRATION_OWNER_EMAIL","").strip().lower()
    with db() as c: owner=c.execute("SELECT id FROM users WHERE lower(email)=?",(owner_email,)).fetchone() if owner_email else None
    if not owner or owner["id"] != incident["user_id"]:
        return {"window_start":None,"traces":[],"git_events":[]}
    try: cutoff=datetime.fromtimestamp(datetime.fromisoformat(incident["created"]).timestamp()-24*3600,timezone.utc).isoformat()
    except (TypeError,ValueError): cutoff=datetime.fromtimestamp(time.time()-24*3600,timezone.utc).isoformat()
    with db() as c:
        traces=c.execute("SELECT trace_id,span_id,name,service,environment,start_ns,duration_ms,status,attributes,created FROM otel_spans WHERE service=? AND environment=? AND created>=? ORDER BY created DESC LIMIT 100",(incident["service"],incident["environment"],cutoff)).fetchall()
        repo=os.getenv("NORTHCAUSE_GITHUB_REPOSITORY","").strip().lower()
        changes=c.execute("SELECT event,repository,ref,before_sha,after_sha,environment,status,created FROM github_deliveries WHERE lower(repository)=? AND created>=? ORDER BY created DESC LIMIT 50",(repo,cutoff)).fetchall() if repo else []
    return {"window_start":cutoff,"traces":[{**dict(row),"attributes":json.loads(row["attributes"])} for row in traces],"git_events":[dict(row) for row in changes]}

@app.get("/",response_class=HTMLResponse)
def home(request: Request): return page(request,"home.html",title="Find it. Fix it. Prove it.")
@app.get("/product",response_class=HTMLResponse)
def product(request: Request): return page(request,"product.html",title="Product")
@app.get("/evidence-loop",response_class=HTMLResponse)
def evidence_loop(request: Request): return page(request,"evidence_loop.html",title="Evidence Loop")
@app.get("/security",response_class=HTMLResponse)
def security_page(request: Request): return page(request,"security.html",title="Security")
@app.get("/docs",response_class=HTMLResponse)
def docs(request: Request): return page(request,"docs.html",title="Docs")
@app.get("/cli",response_class=HTMLResponse)
def cli_page(request: Request): return page(request,"cli.html",title="CLI tools",active="cli")
@app.get("/cloud-shell",response_class=HTMLResponse)
def cloud_shell_page(request: Request): return page(request,"cloud_shell.html",title="NorthCause Cloud Shell",active="cloud_shell")
@app.get("/pricing",response_class=HTMLResponse)
def pricing(request: Request): return page(request,"pricing.html",title="Pricing")
@app.get("/demo",response_class=HTMLResponse)
def demo(request: Request): return page(request,"demo.html",title="Sample workspace")
@app.get("/contact",response_class=HTMLResponse)
def contact(request: Request, sent: int=0):
    token=secrets.token_urlsafe(24)
    response=page(request,"contact.html",title="Contact",sent=bool(sent),success="Thanks. Your message was saved for the NorthCause team." if sent else None,csrf_token=token)
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

@app.post("/api/otel/v1/traces")
async def ingest_otlp_traces(request: Request):
    if not constant_token_ok(request, "NORTHCAUSE_OTEL_INGEST_TOKEN"):
        raise HTTPException(401, "Valid OTLP bearer token required")
    raw = await read_bounded(request, 2 * 1024 * 1024)
    try: payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError): raise HTTPException(400, "Expected OTLP JSON")
    groups = payload.get("resourceSpans") if isinstance(payload, dict) else None
    if not isinstance(groups, list) or len(groups) > 200:
        raise HTTPException(400, "Expected a bounded OTLP resourceSpans list")
    seen = accepted = duplicates = 0
    with db() as c:
        for resource_group in groups:
            if not isinstance(resource_group, dict): continue
            resource_attrs = otel_attribute_map((resource_group.get("resource") or {}).get("attributes", []))
            service = resource_attrs.get("service.name", "unknown")[:120]
            environment = resource_attrs.get("deployment.environment.name", resource_attrs.get("deployment.environment", "production"))[:80]
            scope_groups = resource_group.get("scopeSpans", [])
            for scope in scope_groups if isinstance(scope_groups, list) else []:
                spans = scope.get("spans", []) if isinstance(scope, dict) else []
                for span in spans if isinstance(spans, list) else []:
                    if not isinstance(span, dict) or not re.fullmatch(r"[0-9a-fA-F]{32}", str(span.get("traceId", ""))) or not re.fullmatch(r"[0-9a-fA-F]{16}", str(span.get("spanId", ""))):
                        continue
                    seen += 1
                    if seen > 1000: raise HTTPException(413, "OTLP batch exceeds 1,000 spans")
                    attrs = otel_attribute_map(span.get("attributes", []))
                    name = str(span.get("name", "span"))[:160]
                    if re.search(r"prompt|completion|response|request body|user input", name, re.I): name = "redacted-span"
                    try:
                        start = str(int(span.get("startTimeUnixNano", "0")))
                        end = int(span.get("endTimeUnixNano", start))
                        duration_ms = max(0, min(86_400_000, (end - int(start)) / 1_000_000))
                    except (TypeError, ValueError): start, duration_ms = "0", 0
                    status = (span.get("status") or {}).get("code", 0)
                    status = "error" if str(status).lower() in {"2", "error"} else "ok"
                    cursor=c.execute("INSERT OR IGNORE INTO otel_spans VALUES(?,?,?,?,?,?,?,?,?,?)",
                              (span["spanId"].lower(),span["traceId"].lower(),name,service,environment,start,duration_ms,status,json.dumps(attrs,sort_keys=True),now()))
                    if cursor.rowcount: accepted += 1
                    else: duplicates += 1
    return {"accepted_spans": accepted, "duplicate_spans": duplicates}

@app.post("/api/integrations/github/webhook")
async def github_webhook(request: Request):
    secret = os.getenv("NORTHCAUSE_GITHUB_WEBHOOK_SECRET", "")
    signature = request.headers.get("x-hub-signature-256", "")
    if not secret or not re.fullmatch(r"sha256=[0-9a-f]{64}", signature): raise HTTPException(401, "GitHub webhook signature required")
    raw = await read_bounded(request, 1024 * 1024)
    expected = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature): raise HTTPException(401, "Invalid GitHub webhook signature")
    try: payload = json.loads(raw)
    except json.JSONDecodeError: raise HTTPException(400, "Invalid GitHub webhook JSON")
    if not isinstance(payload, dict): raise HTTPException(400, "GitHub webhook payload must be an object")
    event = request.headers.get("x-github-event", "")
    if event not in {"push", "deployment_status"}: return {"accepted": False, "reason": "event_not_supported"}
    delivery = request.headers.get("x-github-delivery", "")
    if not re.fullmatch(r"[A-Za-z0-9-]{8,100}", delivery): raise HTTPException(400, "Missing GitHub delivery ID")
    repo_obj = payload.get("repository") or {}
    if not isinstance(repo_obj, dict): raise HTTPException(400, "Invalid repository identity")
    repository = repo_obj.get("full_name", "")
    if not isinstance(repository, str) or len(repository) > 200: raise HTTPException(400, "Invalid repository identity")
    deployment = payload.get("deployment") or {} if event == "deployment_status" else {}
    status_obj = payload.get("deployment_status") or {} if event == "deployment_status" else {}
    if not isinstance(deployment,dict) or not isinstance(status_obj,dict): raise HTTPException(400, "Invalid deployment status payload")
    with db() as c:
        duplicate = c.execute("SELECT 1 FROM github_deliveries WHERE delivery_id=?",(delivery,)).fetchone() is not None
        c.execute("INSERT OR IGNORE INTO github_deliveries VALUES(?,?,?,?,?,?,?,?,?)",
                  (delivery,event,repository[:200],str(payload.get("ref", ""))[:200] or None,
                   str(payload.get("before", ""))[:64] or None,str(payload.get("after", ""))[:64] or None,
                   str(deployment.get("environment", ""))[:80] or None,str(status_obj.get("state", ""))[:40] or None,now()))
    return {"accepted": True, "duplicate": duplicate, "delivery_id": delivery}

@app.post("/api/evaluations/semantic")
async def semantic_evaluation(request: Request):
    user = require_user(request)
    raw = await read_bounded(request, 256 * 1024)
    try: payload = json.loads(raw)
    except json.JSONDecodeError: raise HTTPException(400, "Expected JSON")
    cases = payload.get("cases") if isinstance(payload, dict) else None
    if not isinstance(cases, list) or not 1 <= len(cases) <= 20:
        raise HTTPException(400, "Provide between 1 and 20 evaluation cases")
    for case in cases:
        if not isinstance(case, dict) or any(not isinstance(case.get(k), str) or not case[k].strip() for k in ("criteria", "expected", "candidate")):
            raise HTTPException(400, "Each case needs criteria, expected, and candidate text")
        if any(len(case[k]) > 8000 for k in ("criteria", "expected", "candidate")):
            raise HTTPException(413, "Evaluation case field exceeds 8,000 characters")
    cutoff=datetime.fromtimestamp(time.time()-3600,timezone.utc).isoformat()
    with db() as c: recent=c.execute("SELECT COUNT(*) FROM semantic_runs WHERE user_id=? AND created>=?",(user["id"],cutoff)).fetchone()[0]
    if recent >= 10: raise HTTPException(429, "Semantic evaluation limit reached for this user. Try again in one hour.")
    try: result = score_cases(cases)
    except SemanticJudgeError as exc: raise HTTPException(503, str(exc))
    summary = {key: value for key, value in result.items() if key != "results"}
    with db() as c: c.execute("INSERT INTO semantic_runs VALUES(?,?,?,?)", (uid("sem"),user["id"],json.dumps(summary),now()))
    audit(user["id"],"semantic.evaluate",None,summary)
    return result

@app.post("/api/sos")
async def sos_intake(request: Request):
    user = require_user(request)
    raw = await read_bounded(request, 12_000)
    try: data = json.loads(raw)
    except json.JSONDecodeError: raise HTTPException(400, "Expected JSON")
    title = data.get("title", "") if isinstance(data, dict) else ""
    service = data.get("service", "unknown") if isinstance(data, dict) else "unknown"
    env = data.get("environment", "production") if isinstance(data, dict) else "production"
    summary = data.get("summary", "") if isinstance(data, dict) else ""
    severity = data.get("severity", "critical") if isinstance(data, dict) else "critical"
    if not isinstance(title,str) or not title.strip() or len(title)>180 or not isinstance(service,str) or len(service)>120 or env not in {"development","staging","production"} or severity not in {"high","critical"} or not isinstance(summary,str) or not summary.strip() or len(summary)>8000:
        raise HTTPException(400, "SOS needs a title, service, environment, high/critical severity, and summary")
    cutoff=datetime.fromtimestamp(time.time()-3600,timezone.utc).isoformat()
    with db() as c: recent=c.execute("SELECT COUNT(*) FROM audit WHERE actor=? AND action='sos.intake' AND created>=?",(user["id"],cutoff)).fetchone()[0]
    if recent >= 5: raise HTTPException(429,"SOS intake limit reached for this user. Use your existing on-call process for additional urgent incidents.")
    incident_id=uid("inc")
    with db() as c:
        c.execute("INSERT INTO incidents(id,user_id,title,service,environment,severity,created) VALUES(?,?,?,?,?,?,?)",(incident_id,user["id"],title.strip(),service.strip(),env,severity,now()))
        safe = re.sub(r"(?i)(api[\s_-]?key|token|password|secret)(\s*[:=]\s*)[^\s,;]+",r"\1\2[REDACTED]",summary)
        c.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?)",(uid("ev"),incident_id,"SOS intake",safe,hashlib.sha256(summary.encode()).hexdigest(),now()))
    audit(user["id"],"sos.intake",incident_id,{"severity":severity})
    return {"incident_id":incident_id,"status":"received","response_service":"not_staffed","message":"The incident is saved in your workspace. This pilot does not provide a staffed response SLA or automatic containment."}

@app.get("/api/proofs/{proof_id}/verify")
def proof_verify(proof_id: str):
    with db() as c: row=c.execute("SELECT * FROM proof_records WHERE id=?",(proof_id,)).fetchone()
    if not row: raise HTTPException(404,"Proof record not found")
    record=dict(row)
    return {"proof_id":proof_id,"valid":verify_record(record),"record_hash":record["record_hash"],"previous_hash":record["previous_hash"],"key_fingerprint":record["key_fingerprint"],"created_at":record["created"]}

@app.get("/api/proofs/{proof_id}")
def proof_download(request: Request,proof_id: str):
    user=require_user(request)
    with db() as c: row=c.execute("SELECT id,payload,payload_sha256,previous_hash,record_hash,signature,public_key,key_fingerprint,created FROM proof_records WHERE id=? AND user_id=?",(proof_id,user["id"])).fetchone()
    if not row: raise HTTPException(404,"Proof record not found")
    result=dict(row); result["payload"]=json.loads(result["payload"]); result["algorithm"]="Ed25519";result["verification_url"]=f"/api/proofs/{proof_id}/verify"
    return result

@app.get("/api/incidents/{incident_id}/signals")
def incident_signals(request: Request,incident_id: str):
    user=require_user(request); incident=get_incident(incident_id,user)
    signals=matched_signals(incident)
    return {"incident_id":incident_id,**signals,"regressions":compute_regressions(signals["traces"],incident["created"]),"note":"Signals are time- and service-matched context, not a verified causal finding."}

def _latest_claims(incident_id: str) -> list[dict]:
    with db() as c:
        latest=c.execute("SELECT result FROM investigations WHERE incident_id=? ORDER BY created DESC LIMIT 1",(incident_id,)).fetchone()
    if not latest: return []
    try: return json.loads(latest["result"]).get("claims",[]) or []
    except (TypeError,ValueError,json.JSONDecodeError): return []

@app.post("/app/incidents/{incident_id}/hypotheses")
def hypotheses_generate(request: Request,incident_id: str,token:Annotated[str,Form()]=""):
    u=check_csrf(request,token);incident=get_incident(incident_id,u)
    signals=matched_signals(incident)
    regressions=compute_regressions(signals["traces"],incident["created"])
    ranked=rank_hypotheses(incident,regressions,signals["git_events"],_latest_claims(incident_id))
    with db() as c:
        c.execute("DELETE FROM hypotheses WHERE incident_id=?",(incident_id,))
        for h in ranked:
            ev,counter=serialize_hypothesis(h)
            c.execute("INSERT INTO hypotheses VALUES(?,?,?,?,?,?,?,?,?)",(uid("hyp"),incident_id,h["statement"],h["confidence"],ev,counter,h["status"],h["generator"],now()))
    audit(u["id"],"incident.hypotheses",incident_id,{"count":len(ranked),"top_generator":ranked[0]["generator"]})
    return RedirectResponse(f"/app/incidents/{incident_id}#hypotheses",303)

def _active_cases(incident_id: str) -> list[dict]:
    with db() as c:
        rows=c.execute("SELECT * FROM eval_cases WHERE incident_id=? AND status='active' ORDER BY created",(incident_id,)).fetchall()
    return [dict(r) for r in rows]

@app.post("/app/incidents/{incident_id}/eval-cases")
def eval_case_create(request: Request,incident_id: str,label:Annotated[str,Form()],expected:Annotated[str,Form()],baseline:Annotated[str,Form()],source_evidence_id:Annotated[str,Form()]="",source_line:Annotated[str,Form()]="",token:Annotated[str,Form()]=""):
    u=check_csrf(request,token);get_incident(incident_id,u)
    label,expected,baseline=label.strip(),expected.strip(),baseline.strip()
    if not label or not expected or not baseline or len(label)>120 or len(expected)>8000 or len(baseline)>8000:
        raise HTTPException(400,"Eval case needs a label and non-empty expected/baseline up to 8,000 characters")
    evidence_ref=None
    if source_evidence_id.strip():
        with db() as c: row=c.execute("SELECT id FROM evidence WHERE id=? AND incident_id=?",(source_evidence_id.strip(),incident_id)).fetchone()
        if not row: raise HTTPException(400,"source_evidence_id does not belong to this incident")
        evidence_ref=row["id"]
    line=None
    if source_line.strip():
        try: line=max(1,int(source_line))
        except ValueError: raise HTTPException(400,"source_line must be an integer")
    case_id=uid("case")
    with db() as c:
        if c.execute("SELECT COUNT(*) n FROM eval_cases WHERE incident_id=? AND status='active'",(incident_id,)).fetchone()["n"]>=500:
            raise HTTPException(413,"An incident dataset is limited to 500 active cases")
        c.execute("INSERT INTO eval_cases VALUES(?,?,?,?,?,?,?,?,?,?)",(case_id,incident_id,label,expected,baseline,evidence_ref,line,u["id"],"active",now()))
    audit(u["id"],"eval_case.create",case_id,{"incident_id":incident_id,"evidence_ref":evidence_ref})
    return RedirectResponse(f"/app/incidents/{incident_id}#evalcases",303)

@app.post("/app/eval-cases/{case_id}/retire")
def eval_case_retire(request: Request,case_id: str,token:Annotated[str,Form()]=""):
    u=check_csrf(request,token)
    with db() as c:
        row=c.execute("SELECT e.id,e.incident_id FROM eval_cases e JOIN incidents i ON i.id=e.incident_id WHERE e.id=? AND i.user_id=?",(case_id,u["id"])).fetchone()
        if not row: raise HTTPException(404,"Eval case not found")
        c.execute("UPDATE eval_cases SET status='retired' WHERE id=?",(case_id,))
    audit(u["id"],"eval_case.retire",case_id)
    return RedirectResponse(f"/app/incidents/{row['incident_id']}#evalcases",303)

@app.get("/api/incidents/{incident_id}/eval-cases")
def eval_cases_api(request: Request,incident_id: str):
    user=require_user(request);get_incident(incident_id,user)
    cases=_active_cases(incident_id)
    return {"incident_id":incident_id,"dataset_version":dataset_version(cases) if cases else None,
            "cases":[{k:case[k] for k in ("id","label","expected","baseline","source_evidence_id","source_line","created")} for case in cases],
            "candidate_template":[{"case_id":case["id"],"candidate":""} for case in cases],
            "note":"Reviewed cases define the dataset. Any change to the active set changes dataset_version."}

@app.get("/api/incidents/{incident_id}/hypotheses")
def hypotheses_api(request: Request,incident_id: str):
    user=require_user(request);get_incident(incident_id,user)
    with db() as c: rows=c.execute("SELECT * FROM hypotheses WHERE incident_id=? ORDER BY confidence DESC,created DESC",(incident_id,)).fetchall()
    return {"incident_id":incident_id,"hypotheses":[{**dict(r),"evidence":json.loads(r["evidence"]),"counterevidence":json.loads(r["counterevidence"])} for r in rows],"note":"Deterministic, rule-ranked hypotheses for human review. An inconclusive outcome is a valid result."}
@app.get("/login",response_class=HTMLResponse)
def login(request: Request):
    token=secrets.token_urlsafe(24)
    response=page(request,"login.html",title="Sign in",error="Sign-in failed" if request.query_params.get("error") else None,csrf_token=token)
    response.set_cookie("nc_login_csrf",token,httponly=True,samesite="strict",secure=os.getenv("NORTHCAUSE_COOKIE_SECURE","0")=="1",max_age=3600,path="/")
    return response
@app.get("/signup",response_class=HTMLResponse)
def signup(request: Request):
    token=secrets.token_urlsafe(24)
    response=page(request,"signup.html",title="Request workspace access",csrf_token=token,sent=request.query_params.get("sent")=="1")
    response.set_cookie("nc_signup_csrf",token,httponly=True,samesite="strict",secure=os.getenv("NORTHCAUSE_COOKIE_SECURE","0")=="1",max_age=3600,path="/")
    return response
@app.post("/signup")
def signup_post(request: Request,name:Annotated[str,Form()],email:Annotated[str,Form()],company:Annotated[str,Form()]= "",message:Annotated[str,Form()]= "",website:Annotated[str,Form()]= "",csrf_token:Annotated[str,Form()]= ""):
    cookie=request.cookies.get("nc_signup_csrf","")
    if not cookie or not csrf_token or not hmac.compare_digest(cookie,csrf_token): raise HTTPException(403,"Invalid CSRF token")
    if website.strip(): return RedirectResponse("/signup?sent=1",303)
    name=name.strip(); email=email.strip().lower(); company=company.strip(); message=message.strip()
    if not name or len(name)>100 or len(email)>254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",email) or len(company)>120 or len(message)>1200:
        raise HTTPException(400,"Please check the form fields and try again")
    request_message="Workspace access request. "+(message if message else "Please contact me about NorthCause workspace access.")
    cutoff=datetime.fromtimestamp(time.time()-900,timezone.utc).isoformat()
    with db() as c:
        recent=c.execute("SELECT 1 FROM contacts WHERE lower(email)=? AND message LIKE 'Workspace access request.%' AND created>=? LIMIT 1",(email,cutoff)).fetchone()
        if not recent:
            c.execute("INSERT INTO contacts VALUES(?,?,?,?,?,?)",(uid("msg"),name,email,company,request_message,now()))
    return RedirectResponse("/signup?sent=1",303)
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
    with db() as c:
        incidents=c.execute("SELECT i.*,COUNT(e.id) evidence_count FROM incidents i LEFT JOIN evidence e ON e.incident_id=i.id WHERE i.user_id=? GROUP BY i.id ORDER BY i.created DESC",(u["id"],)).fetchall()
        totals=c.execute("""
            SELECT
              (SELECT COUNT(*) FROM incidents WHERE user_id=? AND status NOT IN ('resolved','closed')) AS active_incidents,
              (SELECT COUNT(*) FROM evidence e JOIN incidents i ON i.id=e.incident_id WHERE i.user_id=?) AS evidence_items,
              (SELECT COUNT(*) FROM replay_runs WHERE user_id=?) AS replay_runs,
              (SELECT COUNT(*) FROM proof_records WHERE user_id=?) AS proof_records
        """,(u["id"],u["id"],u["id"],u["id"])).fetchone()
        recent_evidence=c.execute("SELECT e.id,e.label,e.sha256,e.created,i.title AS incident_title FROM evidence e JOIN incidents i ON i.id=e.incident_id WHERE i.user_id=? ORDER BY e.created DESC LIMIT 4",(u["id"],)).fetchall()
    return page(request,"dashboard.html",title="Workspace",incidents=incidents,totals=totals,recent_evidence=recent_evidence)
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
        replay_runs=c.execute("SELECT id,summary,created FROM replay_runs WHERE incident_id=? AND user_id=? ORDER BY created DESC LIMIT 10",(incident_id,u["id"])).fetchall()
    signals=matched_signals(incident)
    regressions=compute_regressions(signals["traces"],incident["created"])
    timeline=build_timeline(incident,evidence,signals["git_events"],regressions)
    with db() as c:
        hypotheses=[{**dict(r),"evidence":json.loads(r["evidence"]),"counterevidence":json.loads(r["counterevidence"])} for r in c.execute("SELECT * FROM hypotheses WHERE incident_id=? ORDER BY confidence DESC,created DESC",(incident_id,)).fetchall()]
    eval_cases=_active_cases(incident_id)
    return page(request,"incident.html",title=incident["title"],incident=incident,evidence=evidence,investigations=investigations,drafts=drafts,replay_runs=replay_runs,signals=signals,regressions=regressions,timeline=timeline,hypotheses=hypotheses,eval_cases=eval_cases,dataset_version=dataset_version(eval_cases) if eval_cases else None)

@app.get("/app/incidents/{incident_id}/replay",response_class=HTMLResponse)
def replay_page(request: Request,incident_id: str):
    u=require_user(request); incident=get_incident(incident_id,u)
    with db() as c:
        rows=c.execute("SELECT summary,created FROM replay_runs WHERE incident_id=? AND user_id=? ORDER BY created DESC LIMIT 10",(incident_id,u["id"])).fetchall()
    runs=[{"summary":json.loads(row["summary"]),"created":row["created"]} for row in rows]
    with db() as c: proof=c.execute("SELECT id FROM proof_records WHERE incident_id=? AND user_id=? ORDER BY created DESC LIMIT 1",(incident_id,u["id"])).fetchone()
    cases=_active_cases(incident_id)
    return page(request,"replay.html",title="Reliability Replay",incident=incident,runs=runs,error=None,result=runs[0]["summary"] if runs else None,proof=proof,eval_cases=cases,dataset_version=dataset_version(cases) if cases else None)

@app.post("/app/incidents/{incident_id}/replay",response_class=HTMLResponse)
async def replay_run(request: Request,incident_id: str,file: UploadFile=File(...),threshold: Annotated[float,Form()]=80,mode: Annotated[str,Form()]="paired",token:Annotated[str,Form()]=""):
    u=check_csrf(request,token); incident=get_incident(incident_id,u)
    if Path(file.filename or "").suffix.lower() not in {".jsonl", ".ndjson"}:
        raise HTTPException(415,"Upload a JSONL or NDJSON replay set")
    if not 0 <= threshold <= 100:
        raise HTTPException(400,"Threshold must be between 0 and 100 percent")
    raw=await file.read(MAX_UPLOAD+1)
    if len(raw)>MAX_UPLOAD:
        raise HTTPException(413,"Replay file exceeds 2 MiB")
    digest=hashlib.sha256(raw).hexdigest()
    cases=_active_cases(incident_id) if mode=="stored" else []
    try:
        if mode=="stored": evaluated=evaluate_candidates(raw,cases,threshold,digest)
        elif mode=="paired": evaluated=evaluate_jsonl(raw,threshold,digest)
        else: raise ReplayInputError("Unknown replay mode")
    except ReplayInputError as exc:
        with db() as c:
            rows=c.execute("SELECT summary,created FROM replay_runs WHERE incident_id=? AND user_id=? ORDER BY created DESC LIMIT 10",(incident_id,u["id"])).fetchall()
        runs=[{"summary":json.loads(row["summary"]),"created":row["created"]} for row in rows]
        return page(request,"replay.html",title="Reliability Replay",incident=incident,runs=runs,error=str(exc),result=runs[0]["summary"] if runs else None,eval_cases=_active_cases(incident_id),dataset_version=None)
    summary={"cases":evaluated.cases,"baseline_passes":evaluated.baseline_passes,"candidate_passes":evaluated.candidate_passes,"baseline_rate":evaluated.baseline_rate,"candidate_rate":evaluated.candidate_rate,"threshold":evaluated.threshold,"gate":evaluated.gate,"source_sha256":evaluated.source_sha256,"mode":mode,"dataset_version":dataset_version(cases) if mode=="stored" else None}
    try: ensure_signing_key(DATA)
    except (RuntimeError,ValueError) as exc: raise HTTPException(503, str(exc))
    replay_id=uid("replay")
    with db() as c:
        c.execute("INSERT INTO replay_runs VALUES(?,?,?,?,?)",(replay_id,incident_id,u["id"],json.dumps(summary),now()))
    proof_id=_proof_for_replay(replay_id,incident_id,u["id"],summary)
    audit(u["id"],"replay.run",incident_id,{"cases":evaluated.cases,"gate":evaluated.gate,"source_sha256":digest,"metric":"exact_match","proof_id":proof_id})
    return RedirectResponse(f"/app/incidents/{incident_id}/replay",303)
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
    redacted=re.sub(r"(?i)(api[\s_-]?key|token|password|secret)(\s*[:=]\s*)[^\s,;]+",r"\1\2[REDACTED]",text)
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

@app.post("/app/incidents/{incident_id}/recommend")
def recommend_remediation(request: Request,incident_id: str,token:Annotated[str,Form()]=""):
    u=check_csrf(request,token);get_incident(incident_id,u)
    playbooks={
        "GPU OOM":"Compare GPU memory usage and batch size with the last known-good run. In staging, lower concurrency or batch size and replay the same workload before proposing a rollout.",
        "Kubernetes restart":"Review pod events, recent image/config changes, resource limits, and probe thresholds. Validate a narrowly scoped manifest change in a non-production environment.",
        "HTTP 5xx":"Compare the deployment diff and error logs around the first failure. Reproduce against the prior version, then test a minimal rollback or dependency fix with the same checks.",
        "Timeout":"Compare latency by dependency and request size. Test bounded timeouts, cancellation, or concurrency adjustments against the incident cases before proposing a rollout.",
        "Rate limit":"Confirm provider quotas and retry behavior. Test exponential backoff with jitter or a reviewed fallback route, then replay for latency, quality, and cost regressions.",
        "RAG retrieval issue":"Compare the active index, embedding model, filters, and top-k settings with the last known-good run. Replay the affected queries against both configurations before changing traffic.",
        "Prompt injection indicator":"Preserve the affected trace and review tool permissions and guardrail changes. Add the sanitized case to the red-team regression set and require a passing check before release.",
        "Disk pressure":"Identify the affected volume and growth source. Validate retention or capacity changes against workload needs before applying any infrastructure change.",
        "TLS failure":"Check certificate chain, expiry, hostname, and trust-store changes. Verify the proposed certificate or trust configuration in staging before rollout.",
    }
    with db() as c: row=c.execute("SELECT result FROM investigations WHERE incident_id=? ORDER BY created DESC LIMIT 1",(incident_id,)).fetchone()
    if not row: raise HTTPException(409,"Run an evidence investigation before generating a remediation draft")
    result=json.loads(row["result"]); claim=next((item for item in result.get("claims",[]) if item.get("label") in playbooks),None)
    if not claim: raise HTTPException(409,"No supported remediation playbook matched the latest evidence")
    body=(f"Suggested playbook for {claim['label']}: {playbooks[claim['label']]} "
          f"Evidence reference: {claim['evidence_id']}, line {claim['line']}. This is guidance, not an executed change. "
          "A reviewer must validate the proposal and record an approval decision.")
    did=uid("draft")
    with db() as c:c.execute("INSERT INTO drafts VALUES(?,?,?,'pending',NULL,?)",(did,incident_id,body,now()))
    audit(u["id"],"remediation.recommend",did,{"finding":claim["label"],"evidence_id":claim["evidence_id"],"line":claim["line"]})
    return RedirectResponse(f"/app/incidents/{incident_id}#remediation",303)
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
