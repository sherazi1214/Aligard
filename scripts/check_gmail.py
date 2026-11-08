"""Gmail connect ki setup check: `python scripts/check_gmail.py` (aliguard/ ke root se). Secrets print nahi hote."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
ok = True


def line(good: bool, msg: str, fix: str = ""):
    global ok
    ok = ok and good
    print(("[OK]   " if good else "[FAIL] ") + msg + (f"\n       -> {fix}" if not good and fix else ""))


env = Path(".env")
line(env.is_file(), f".env file is folder mein hai ({os.getcwd()})",
     "Is folder mein 'cp .env.example .env' chalayein, aur yahin se backend chalayein")
if env.is_file():
    keys = {}
    for raw in env.read_text(errors="ignore").splitlines():
        if "=" in raw and not raw.lstrip().startswith("#"):
            k, _, v = raw.partition("=")
            keys.setdefault(k.strip(), []).append(v.strip())
    for k in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"):
        vals = keys.get(k, [])
        line(bool(vals) and bool(vals[-1].split("#")[0].strip().strip("\"'")), f".env mein {k} bhari hui hai",
             f"{k}=<value> likhein (barabar ke aas paas space nahi, quotes nahi)" if k not in keys else
             f"{k} ki value khali hai" + (" (aur ye key kai bar likhi hai, aakhri wali jeetti hai)" if len(vals) > 1 else ""))
        if len(vals) > 1:
            print(f"       note: {k} {len(vals)} bar likhi hai; sirf aakhri wali use hoti hai")

from backend.app.config import get_settings  # noqa: E402

s = get_settings()
line(s.gmail_configured, "Backend ko Google ID + secret mil gaye (gmail_configured=True)",
     "Upar ke FAIL theek karein. Docker/Render mein .env automatic nahi jati")
print(f"       redirect URI (Google Console mein EXACT yehi daalein): {s.oauth_redirect_uri}")
line(s.oauth_redirect_uri.startswith(("http://localhost", "http://127.0.0.1", "https://")),
     "Redirect URI ka format theek hai", "BASE_URL ya GOOGLE_REDIRECT_URI check karein")
try:
    import redis
    redis.Redis.from_url(s.redis_url, socket_connect_timeout=2).ping()
    line(True, "Redis chal raha hai (OAuth state ke liye lazmi)")
except Exception:
    line(False, "Redis se rabta nahi ho raha", "'docker compose up -d' chalayein")
print("\nSab theek hai." if ok else "\nUpar ke FAIL theek karke dobara chalayein.")
