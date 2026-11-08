"""AliGuard portal: signup/login (email or Google) + 3 services + entitlements. Payment is in TEST MODE (no real payment)."""
import base64, contextlib, hashlib, hmac, json, os, re, secrets, smtplib, sqlite3, threading, time, urllib.parse, urllib.request
from email.message import EmailMessage
from collections import defaultdict
from pathlib import Path
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
DB = os.getenv("DB_PATH", str(ROOT / "aliguard.db"))
SECURE = os.getenv("APP_ENV") == "production"
ph = PasswordHasher()
DUMMY = ph.hash(secrets.token_urlsafe(16))
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000").rstrip("/")
EMAIL = r"^[^@\s]{1,64}@[^@\s]{1,200}\.[^@\s]{2,}$"
USERNAME = r"^[A-Za-z0-9_]{3,20}$"
GOOGLE_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
# SSO handoff into aliguard-full (the product app). Same secret must be set as SSO_SHARED_SECRET
# there. Empty = handoff disabled, buy()/sso_url() just skip the sso_url field.
SSO_SECRET = os.getenv("SSO_SHARED_SECRET", "")
FULL_APP_URL = os.getenv("FULL_APP_URL", "http://127.0.0.1:8001").rstrip("/")
SSO_TOKEN_TTL = 120  # seconds the one-time handoff link stays valid for
# Security switches
PAYMENTS_TEST_MODE = os.getenv("PAYMENTS_TEST_MODE", "1" if not SECURE else "0") == "1"  # production: free activation is OFF unless explicitly enabled
SMTP_HOST, SMTP_PORT = os.getenv("SMTP_HOST", ""), int(os.getenv("SMTP_PORT", "587"))
SMTP_USER, SMTP_PASS = os.getenv("SMTP_USER", ""), os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)
SERVICES = [  # price is decided on the server (placeholder PKR/month)
    {"id": "gmail", "name": "Gmail Guard", "price": 1500, "tone": "g",
     "tagline": "Catch phishing emails before they reach your inbox.",
     "points": ["Auto label and quarantine", "Multi-language scam detection", "Telegram alert"]},
    {"id": "whatsapp", "name": "WhatsApp Guard", "price": 1200, "tone": "g",
     "tagline": "Forward a suspicious message and get a verdict in seconds.",
     "points": ["Scam link check", "Fake courier and prize scams", "Plain-language reason for every verdict"]},
    {"id": "website", "name": "Website Shield", "price": 2500, "tone": "r",
     "tagline": "Watch your website for attacks around the clock.",
     "points": ["Security headers and SSL check", "Outdated software scan", "Change and uptime alerts"]},
]
app = FastAPI(docs_url=None, redoc_url=None)
hits: dict = defaultdict(list)


@contextlib.contextmanager
def db():
    """Commit on success, rollback on error, and ALWAYS close (plain sqlite3 `with` leaks the connection)."""
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    try:
        with c:
            yield c
    finally:
        c.close()


with db() as c:
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, pw TEXT NOT NULL, created INT);
    CREATE TABLE IF NOT EXISTS sessions(h TEXT PRIMARY KEY, user_id INT NOT NULL, exp INT NOT NULL);
    CREATE TABLE IF NOT EXISTS entitlements(user_id INT, service TEXT, exp INT, PRIMARY KEY(user_id, service));
    CREATE TABLE IF NOT EXISTS resets(h TEXT PRIMARY KEY, user_id INT NOT NULL, exp INT NOT NULL, used INT DEFAULT 0);
    CREATE TABLE IF NOT EXISTS verifs(h TEXT PRIMARY KEY, user_id INT NOT NULL, exp INT NOT NULL, used INT DEFAULT 0);""")
    if "verified" not in [r[1] for r in c.execute("PRAGMA table_info(users)")]:  # email ownership proof: only verified emails may be handed to the full app
        c.execute("ALTER TABLE users ADD COLUMN verified INT DEFAULT 0")
    c.execute("DELETE FROM sessions WHERE exp<?", (int(time.time()),))  # purge expired sessions
    c.execute("DELETE FROM resets WHERE exp<?", (int(time.time()),))
    c.execute("DELETE FROM verifs WHERE exp<?", (int(time.time()),))
    if "username" not in [r[1] for r in c.execute("PRAGMA table_info(users)")]:  # migrate databases created before usernames existed
        c.execute("ALTER TABLE users ADD COLUMN username TEXT")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_username ON users(lower(username))")


def limit(key: str, n: int, win: int = 60):
    now = time.time()
    hits[key] = [t for t in hits[key] if now - t < win]
    if len(hits[key]) >= n:
        raise HTTPException(429, "Too many attempts. Wait a minute and try again.")
    hits[key].append(now)


class Signup(BaseModel):
    username: str = Field(pattern=USERNAME)
    email: str = Field(pattern=EMAIL, max_length=254)
    password: str = Field(min_length=12, max_length=128)
    confirm: str = Field(min_length=1, max_length=128)


class Login(BaseModel):
    email: str = Field(max_length=254)  # accepts an email address or a username
    password: str = Field(min_length=1, max_length=128)


def csrf(request: Request):  # cross-site forms and fetches cannot set this custom header
    if request.headers.get("x-requested-with") != "aliguard":
        raise HTTPException(403, "Blocked: missing security header.")


def user_of(request: Request):
    tok = request.cookies.get("ag_session")
    if not tok:
        return None
    with db() as c:
        return c.execute("SELECT u.id,u.email,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.h=? AND s.exp>?",
                         (hashlib.sha256(tok.encode()).hexdigest(), int(time.time()))).fetchone()


def start_session(resp: Response, uid: int):
    tok = secrets.token_urlsafe(32)
    with db() as c:
        c.execute("INSERT INTO sessions VALUES(?,?,?)", (hashlib.sha256(tok.encode()).hexdigest(), uid, int(time.time()) + 86400))
    resp.set_cookie("ag_session", tok, max_age=86400, httponly=True, samesite="lax", secure=SECURE, path="/")


def send_mail(to: str, subject: str, body: str):
    """SMTP in a background thread. Without SMTP_HOST: dev prints to console, production just skips (never leaks tokens to logs)."""
    if not SMTP_HOST:
        if not SECURE:
            print(f"[DEV] mail to {to}: {subject}\n{body}", flush=True)
        return
    def run():
        try:
            m = EmailMessage(); m["To"], m["From"], m["Subject"] = to, SMTP_FROM, subject; m.set_content(body)
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as sm:
                sm.starttls(); 
                if SMTP_USER: sm.login(SMTP_USER, SMTP_PASS)
                sm.send_message(m)
        except Exception:
            print("[WARN] mail send failed", flush=True)
    threading.Thread(target=run, daemon=True).start()


def send_verification(uid: int, email: str):
    tok = secrets.token_urlsafe(32)
    with db() as c:
        c.execute("INSERT INTO verifs(h,user_id,exp) VALUES(?,?,?)", (hashlib.sha256(tok.encode()).hexdigest(), uid, int(time.time()) + 86400))
    send_mail(email, "Verify your AliGuard email", f"Confirm this is your email address:\n{BASE_URL}/api/verify?token={tok}\n\nIf you did not sign up, ignore this message.")


def is_verified(uid: int) -> bool:
    with db() as c:
        r = c.execute("SELECT verified FROM users WHERE id=?", (uid,)).fetchone()
    return bool(r and r["verified"])


def make_sso_token(email: str, service: str = "") -> str:
    """One-time signed handoff link into aliguard-full's /api/auth/sso. We already verified this
    email (our own signup/login or Google OAuth), so the full app trusts a valid signature instead
    of asking the user to log in a second time. Short-lived + single-use (nonce) on the other end."""
    payload = json.dumps(
        {"email": email, "service": service, "verified": True, "nonce": secrets.token_urlsafe(16), "exp": int(time.time()) + SSO_TOKEN_TTL},
        separators=(",", ":"),
    ).encode()
    body_b64 = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    sig = hmac.new(SSO_SECRET.encode(), body_b64.encode(), hashlib.sha256).hexdigest()
    return f"{body_b64}.{sig}"


def sso_redirect_url(email: str, service: str = "") -> str | None:
    if not SSO_SECRET or len(SSO_SECRET) < 32:
        return None
    return f"{FULL_APP_URL}/api/auth/sso?token={make_sso_token(email, service)}"


@app.middleware("http")
async def headers(request: Request, call_next):
    r = await call_next(request)
    r.headers.update({
        "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Cross-Origin-Opener-Policy": "same-origin",
        "Cache-Control": "no-store" if request.url.path.startswith(("/api", "/world")) else "no-cache"})
    if SECURE:
        r.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return r


@app.get("/api/services")
def services(request: Request):
    if not user_of(request):  # plans only after sign-up/sign-in: enforced on the server, not just hidden in the UI
        raise HTTPException(401, "Create an account to see plans.")
    return SERVICES


@app.get("/api/me")
def me(request: Request):
    u = user_of(request)
    if not u:
        return {"user": None}
    with db() as c:
        rows = c.execute("SELECT service,exp FROM entitlements WHERE user_id=? AND exp>?", (u["id"], int(time.time()))).fetchall()
    return {"user": {"email": u["email"], "username": u["username"] or u["email"].split("@")[0], "verified": is_verified(u["id"])}, "active": {r["service"]: r["exp"] for r in rows}, "test_mode": PAYMENTS_TEST_MODE}


@app.post("/api/signup")
def signup(body: Signup, request: Request, response: Response):
    csrf(request)
    limit("su:" + request.client.host, 10, 3600)
    if body.password != body.confirm:
        raise HTTPException(400, "The two passwords do not match.")
    try:
        with db() as c:
            cur = c.execute("INSERT INTO users(email,username,pw,created) VALUES(?,?,?,?)",
                            (body.email.lower(), body.username, ph.hash(body.password), int(time.time())))
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(400, "That username or email is already in use.")
    start_session(response, uid)
    send_verification(uid, body.email.lower())
    return {"ok": True}


@app.get("/api/verify")
def verify_email(request: Request, token: str = ""):
    limit("vf:" + request.client.host, 20, 3600)
    h = hashlib.sha256(token.encode()).hexdigest()
    with db() as c:
        cur = c.execute("UPDATE verifs SET used=1 WHERE h=? AND used=0 AND exp>?", (h, int(time.time())))  # single-use
        if cur.rowcount != 1:
            return RedirectResponse("/#auth_error=verify_failed")
        uid = c.execute("SELECT user_id FROM verifs WHERE h=?", (h,)).fetchone()["user_id"]
        c.execute("UPDATE users SET verified=1 WHERE id=?", (uid,))
    return RedirectResponse("/world")


@app.post("/api/resend-verify")
def resend_verify(request: Request):
    csrf(request)
    u = user_of(request)
    if not u:
        raise HTTPException(401, "Sign in first.")
    limit("rv:%d" % u["id"], 3, 3600)
    if not is_verified(u["id"]):
        send_verification(u["id"], u["email"])
    return {"ok": True}


@app.post("/api/login")
def login(body: Login, request: Request, response: Response):
    csrf(request)
    limit("ip:" + request.client.host, 20)
    limit("em:" + body.email.lower(), 5)
    with db() as c:
        row = c.execute("SELECT id,pw FROM users WHERE email=? OR lower(username)=?", (body.email.lower(),) * 2).fetchone()
    try:
        ok = ph.verify(row["pw"] if row else DUMMY, body.password) and row is not None
    except (VerificationError, InvalidHashError):
        ok = False
    if not ok:
        raise HTTPException(401, "Wrong email, username or password.")
    start_session(response, row["id"])
    return {"ok": True}


class Forgot(BaseModel):
    email: str = Field(max_length=254)


class Reset(BaseModel):
    token: str = Field(min_length=20, max_length=100)
    password: str = Field(min_length=12, max_length=128)


@app.post("/api/forgot")
def forgot(body: Forgot, request: Request):
    csrf(request)
    limit("fp:" + request.client.host, 5, 3600)
    limit("fe:" + body.email.lower(), 3, 3600)
    with db() as c:
        row = c.execute("SELECT id FROM users WHERE email=?", (body.email.lower(),)).fetchone()
        if row:
            tok = secrets.token_urlsafe(32)
            c.execute("INSERT INTO resets(h,user_id,exp) VALUES(?,?,?)", (hashlib.sha256(tok.encode()).hexdigest(), row["id"], int(time.time()) + 1200))
            send_mail(body.email.lower(), "Reset your AliGuard password", f"Open this link within 20 minutes to choose a new password:\n{BASE_URL}/#reset={tok}\n\nIf you did not ask for this, ignore this message.")
    return {"ok": True}  # always the same answer (prevents account enumeration)


@app.post("/api/reset")
def reset(body: Reset, request: Request):
    csrf(request)
    limit("rs:" + request.client.host, 10, 3600)
    h = hashlib.sha256(body.token.encode()).hexdigest()
    with db() as c:
        cur = c.execute("UPDATE resets SET used=1 WHERE h=? AND used=0 AND exp>?", (h, int(time.time())))  # single-use, 20 min
        if cur.rowcount != 1:
            raise HTTPException(400, "This reset link is invalid or expired. Request a new one.")
        uid = c.execute("SELECT user_id FROM resets WHERE h=?", (h,)).fetchone()["user_id"]
        c.execute("UPDATE users SET pw=? WHERE id=?", (ph.hash(body.password), uid))
        c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))  # sign out all old sessions
    return {"ok": True}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    csrf(request)
    tok = request.cookies.get("ag_session")
    if tok:
        with db() as c:
            c.execute("DELETE FROM sessions WHERE h=?", (hashlib.sha256(tok.encode()).hexdigest(),))
    response.delete_cookie("ag_session", path="/")
    return {"ok": True}


@app.post("/api/buy/{service_id}")
def buy(service_id: str, request: Request):
    """TEST MODE: activates directly. With real payments only a signed provider webhook may activate a service."""
    csrf(request)
    u = user_of(request)
    if not u:
        raise HTTPException(401, "Sign in first.")
    if service_id not in {s["id"] for s in SERVICES}:
        raise HTTPException(404, "Unknown service.")
    if not PAYMENTS_TEST_MODE:  # real payments are not built yet: never hand out plans for free in production
        raise HTTPException(503, "Payments are not available yet.")
    if not is_verified(u["id"]):
        raise HTTPException(403, "Please verify your email first. Check your inbox (or use Resend).")
    exp = int(time.time()) + 30 * 86400
    with db() as c:
        c.execute("INSERT INTO entitlements VALUES(?,?,?) ON CONFLICT(user_id,service) DO UPDATE SET exp=excluded.exp", (u["id"], service_id, exp))
    result = {"ok": True, "exp": exp}
    url = sso_redirect_url(u["email"], service_id)
    if url:  # present only when SSO_SHARED_SECRET is configured; frontend redirects the user there
        result["sso_url"] = url
    return result


@app.get("/api/sso-url")
def sso_url(request: Request):
    """Lets a signed-in user jump into aliguard-full without buying anything first (e.g. a
    'Go to dashboard' link once they already have an active plan)."""
    u = user_of(request)
    if not u:
        raise HTTPException(401, "Sign in first.")
    if not is_verified(u["id"]):
        raise HTTPException(403, "Please verify your email first.")
    url = sso_redirect_url(u["email"])
    if not url:
        raise HTTPException(503, "App handoff isn't configured yet.")
    return {"url": url}


@app.get("/api/config")
def config():
    return {"google": bool(GOOGLE_ID and GOOGLE_SECRET)}


@app.get("/api/google/start")
def google_start(request: Request):
    limit("gs:" + request.client.host, 20)
    if not (GOOGLE_ID and GOOGLE_SECRET):
        return RedirectResponse("/#auth_error=google_off")
    state = secrets.token_urlsafe(24)
    q = urllib.parse.urlencode({"client_id": GOOGLE_ID, "redirect_uri": BASE_URL + "/api/google/callback", "response_type": "code",
                                "scope": "openid email profile", "state": state, "prompt": "select_account"})
    r = RedirectResponse("https://accounts.google.com/o/oauth2/v2/auth?" + q)
    r.set_cookie("ag_oauth", state, max_age=600, httponly=True, samesite="lax", secure=SECURE, path="/api/google")
    return r


def _post_json(url: str, data: dict) -> dict:
    req = urllib.request.Request(url, urllib.parse.urlencode(data).encode(), {"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=10) as f:
        return json.load(f)


@app.get("/api/google/callback")
def google_callback(request: Request, code: str = "", state: str = ""):
    limit("gc:" + request.client.host, 20)
    cookie = request.cookies.get("ag_oauth", "")
    if not (code and state and cookie and secrets.compare_digest(state, cookie)):  # state check blocks login-CSRF
        return RedirectResponse("/#auth_error=google_failed")
    try:
        tok = _post_json("https://oauth2.googleapis.com/token", {"code": code, "client_id": GOOGLE_ID, "client_secret": GOOGLE_SECRET,
                                                                 "redirect_uri": BASE_URL + "/api/google/callback", "grant_type": "authorization_code"})
        req = urllib.request.Request("https://openidconnect.googleapis.com/v1/userinfo", headers={"Authorization": "Bearer " + tok["access_token"]})
        with urllib.request.urlopen(req, timeout=10) as f:
            info = json.load(f)
    except Exception:
        return RedirectResponse("/#auth_error=google_failed")
    email = str(info.get("email", "")).lower()
    if not info.get("email_verified") or not re.match(EMAIL, email):
        return RedirectResponse("/#auth_error=google_failed")
    with db() as c:
        row = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if row:
            uid = row["id"]
            if not is_verified(uid):  # someone may have pre-registered this email with a password they know: kill it and its sessions
                c.execute("UPDATE users SET pw=? WHERE id=?", (ph.hash(secrets.token_urlsafe(32)), uid))
                c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
            c.execute("UPDATE users SET verified=1 WHERE id=?", (uid,))
        else:
            base = re.sub(r"[^A-Za-z0-9_]", "", email.split("@")[0])[:14].ljust(3, "0")
            name = base
            while c.execute("SELECT 1 FROM users WHERE lower(username)=?", (name.lower(),)).fetchone():
                name = base + str(secrets.randbelow(9000) + 1000)
            uid = c.execute("INSERT INTO users(email,username,pw,created,verified) VALUES(?,?,?,?,1)",
                            (email, name, ph.hash(secrets.token_urlsafe(32)), int(time.time()))).lastrowid  # random password: Google-only account
    r = RedirectResponse("/world")
    start_session(r, uid)
    r.delete_cookie("ag_oauth", path="/api/google")
    return r


app.mount("/static", StaticFiles(directory=ROOT / "frontend"), name="static")


@app.get("/")
def index():
    return FileResponse(ROOT / "frontend" / "index.html")


@app.get("/world")
def world(request: Request):
    if not user_of(request):  # the cyber world is members-only, enforced on the server
        return RedirectResponse("/")
    return FileResponse(ROOT / "frontend" / "world.html")
