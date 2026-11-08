"""Settings - sab configuration environment variables / .env se aati hai.
Koi bhi password ya key code mein hardcode nahi hoti."""
import re
from functools import lru_cache

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_WEAK_DEFAULT = "dev-only-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    secret_key: str = _WEAK_DEFAULT
    log_level: str = "INFO"
    database_url: str = "postgresql+psycopg://aliguard:aliguard_dev_pw@localhost:5432/aliguard"
    redis_url: str = "redis://localhost:6379/0"
    cors_origins: str = "http://localhost:3000,http://localhost:8000"

    # --- Phase 2: auth ---
    base_url: str = "http://localhost:8000"  # emails ke links isi se bante hain
    # Fernet key (TOTP secret encrypt karne ke liye). Production mein lazmi.
    encryption_key: str = ""
    cookie_secure: bool | None = None  # None => production mein True, warna False
    trust_proxy_headers: bool = False  # sirf tab True jab reverse proxy ke peeche ho

    session_absolute_minutes: int = 1440
    session_idle_minutes: int = 30
    mfa_pending_minutes: int = 5
    mfa_max_attempts: int = 5
    verify_token_hours: int = 24
    reset_token_minutes: int = 20

    lockout_threshold: int = 5
    lockout_base_minutes: int = 1
    lockout_max_minutes: int = 60
    login_ip_limit: int = 20  # 10 minute window
    login_email_limit: int = 10
    signup_ip_limit: int = 10  # 1 ghanta window
    forgot_limit: int = 5  # per IP aur per email, 1 ghanta window
    mfa_ip_limit: int = 20

    hibp_enabled: bool = True

    # --- Phase 5: portal SSO handoff ---
    # aliguard-portal ke sath shared secret (dono taraf .env mein SSO_SHARED_SECRET).
    # Khali ho to /api/auth/sso band rehta hai (404-jaisa behave karta hai).
    # Token ki expiry khud token ke andar hoti hai (portal set karta hai), yahan koi TTL setting nahi.
    sso_shared_secret: str = ""

    # --- Billing (plans + payments) ---
    # stripe = asli payments (Stripe Checkout, card Stripe ke page par). mock = sirf dev/test, production mein band.
    payments_provider: str = "mock"
    stripe_secret_key: str = ""  # sk_live_... / sk_test_... (kabhi frontend/log mein nahi)
    stripe_webhook_secret: str = ""  # whsec_... (webhook signature verify)
    stripe_price_pro: str = ""  # Stripe Dashboard ka recurring Price id (price_...)
    stripe_price_business: str = ""
    stripe_api_base: str = "https://api.stripe.com"
    stripe_http_timeout_seconds: float = 10.0
    webhook_tolerance_seconds: int = 300  # purane (replayed) webhook reject
    price_pro_label: str = "$9"  # sirf UI mein dikhane ke liye; asli price Stripe Price se aati hai
    price_business_label: str = "$29"
    billing_user_limit: int = 10  # checkout/portal/sync per user, 1 ghanta

    # --- Phase 3A: Gmail connect + manual check ---
    # Google Cloud Console se (OAuth client, type "Web application"). Khali ho to Gmail connect band rehta hai.
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = ""  # khali ho to BASE_URL + /api/gmail/callback
    gmail_max_accounts_per_user: int = 10  # global hard ceiling; asli hadd plan se aati hai (billing/plans.py)
    oauth_state_ttl_seconds: int = 600
    google_http_timeout_seconds: float = 10.0
    google_http_retries: int = 3

    check_max_body_bytes: int = 100_000  # /api/check request body ki hadd
    check_user_limit: int = 30  # per user, 10 minute window

    email_backend: str = "console"  # console (sirf dev) | smtp
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "AliGuard <no-reply@localhost>"

    # --- Phase 3B: worker, actions, alerts ---
    worker_poll_seconds: float = 15.0  # scheduler har itne second baad due accounts dekhta hai
    worker_concurrency: int = 4  # ek sath kitne (alag users ke) accounts
    worker_account_interval_seconds: int = 120  # ek account ke do runs ke beech
    worker_run_budget_seconds: int = 120  # ek account run ki zyada se zyada muddat
    worker_max_messages_per_run: int = 100
    worker_initial_backfill: int = 10  # naye connect par inbox ki aakhri itni emails (0 = band)
    worker_backoff_base_seconds: int = 60  # fail hone par: base * 2^(n-1)
    worker_backoff_max_seconds: int = 3600
    gmail_call_pause_seconds: float = 0.05  # Gmail calls ke beech chhota waqfa (quota ka khayal)
    gmail_max_message_bytes: int = 6_000_000  # isse bari email ke sirf headers analyze hote hain

    # "High confidence" PHISHING hi quarantine hoti hai (baqi sirf label + alert)
    quarantine_min_confidence: float = 0.7
    alert_max_per_hour: int = 10  # per user; zyada par ek "throttled" notice, baqi skip
    alert_dedupe_seconds: int = 3600  # wahi sender+subject dobara aaye to dobara alert nahi
    alert_max_attempts: int = 3

    # Telegram bot (BotFather se). Khali ho to Telegram alerts band rehte hain.
    telegram_bot_token: str = ""
    telegram_bot_username: str = ""  # bina @ ke; deep link t.me/<username>?start=<code> ke liye
    telegram_link_ttl_seconds: int = 600
    telegram_poll_timeout_seconds: int = 20

    # --- Phase 4: hardening, observability, budgets ---
    log_format: str = ""  # json | text; khali => production mein json, warna text
    sentry_dsn: str = ""  # khali => Sentry band
    global_rate_limit_per_minute: int = 300  # per IP, har page/API par (0 = band); /health aur /static mustasna
    worker_heartbeat_max_age_seconds: int = 180  # /health/worker is se purana heartbeat => 503
    scan_retention_days: int = 90  # purane scan rows (sender/subject/verdict) is ke baad delete
    audit_retention_days: int = 365
    maintenance_interval_seconds: int = 3600
    encryption_keys_old: str = ""  # key rotation: comma-separated purani Fernet keys (sirf decrypt)
    operator_name: str = "AliGuard operator"  # Privacy/Terms pages par
    support_email: str = ""  # Privacy/Terms pages par (production mein zaroor set karein)

    # Paid third-party layers: key khali => layer band. Limits CALL COUNT ki hain (dollar nahi).
    vt_api_key: str = ""
    vt_daily_call_limit: int = 400  # VirusTotal free tier ~500/din
    vt_user_daily_call_limit: int = 100
    openai_api_key: str = ""
    # Link sandbox (headless Chromium). Default band: chalane se pehle docs/SANDBOX.md padho.
    sandbox_enabled: bool = False
    sandbox_max_urls: int = 2
    sandbox_timeout_ms: int = 12000
    # Domain age (RDAP). Default band: domain naam rdap.org ko jata hai (third party), privacy policy mein likhna hoga.
    domain_intel_enabled: bool = False
    openai_model: str = "gpt-4o-mini"  # deploy se pehle OpenAI ki current model list se confirm karein
    openai_daily_call_limit: int = 500
    openai_user_daily_call_limit: int = 50

    @property
    def old_encryption_key_list(self) -> list[str]:
        return [k.strip() for k in self.encryption_keys_old.split(",") if k.strip()]

    @property
    def effective_log_format(self) -> str:
        return self.log_format or ("json" if self.is_production else "text")

    @model_validator(mode="before")
    @classmethod
    def _normalize_database_url(cls, data):
        # Render/Heroku style "postgres://" ya "postgresql://" ko SQLAlchemy+psycopg3 driver URL banao
        if isinstance(data, dict):
            url = data.get("database_url")
            if isinstance(url, str):
                for prefix in ("postgres://", "postgresql://"):
                    if url.startswith(prefix):
                        data["database_url"] = "postgresql+psycopg://" + url[len(prefix):]
        return data

    @property
    def telegram_configured(self) -> bool:
        return bool(self.telegram_bot_token and self.telegram_bot_username)

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def gmail_configured(self) -> bool:
        return bool(self.google_client_id and self.google_client_secret)

    @property
    def oauth_redirect_uri(self) -> str:
        return self.google_redirect_uri or f"{self.base_url.rstrip('/')}/api/gmail/callback"

    @property
    def secure_cookies(self) -> bool:
        return self.is_production if self.cookie_secure is None else self.cookie_secure

    @field_validator("google_client_id", "google_client_secret", "google_redirect_uri", mode="before")
    @classmethod
    def _clean_google(cls, v):
        """Spaces/quotes hatao; agar value sirf '# comment' hai (.env mein inline comment) to khali samjho."""
        if not isinstance(v, str):
            return v
        v = v.strip().strip('"').strip("'").strip()
        return "" if v.startswith("#") else v

    @model_validator(mode="after")
    def _check_production_secret(self):
        # Production mein kamzor secret key ho to app start hi nahi hogi
        if self.telegram_bot_token and not re.fullmatch(r"[A-Za-z0-9_]{3,64}", self.telegram_bot_username):
            # Deep link username se banta hai; ghalat/khali username par Telegram link kaam hi nahi karega
            raise ValueError("TELEGRAM_BOT_USERNAME (bina @ ke) lazmi hai jab TELEGRAM_BOT_TOKEN set ho")
        if self.is_production and (self.secret_key == _WEAK_DEFAULT or len(self.secret_key) < 32):
            raise ValueError("Production mein SECRET_KEY kam az kam 32 random characters ki ho")
        if self.is_production:
            # Production mein TOTP encryption key aur asli email backend lazmi
            if not self.encryption_key:
                raise ValueError("Production mein ENCRYPTION_KEY (Fernet key) lazmi hai")
            if self.email_backend != "smtp":
                raise ValueError("Production mein EMAIL_BACKEND=smtp lazmi hai (console sirf dev ke liye)")
            if not self.secure_cookies:
                raise ValueError("Production mein cookies Secure honi chahiye")
            # Gmail tokens Fernet se encrypt hote hain; production mein redirect URI https honi chahiye
            if self.gmail_configured and not self.oauth_redirect_uri.startswith("https://"):
                raise ValueError("Production mein Google redirect URI https:// honi chahiye")
        if self.payments_provider not in ("stripe", "mock"):
            raise ValueError("PAYMENTS_PROVIDER stripe ya mock hona chahiye")
        if self.is_production and self.payments_provider != "stripe":
            raise ValueError("Production mein PAYMENTS_PROVIDER=stripe lazmi hai (mock se bina payment plan milta hai)")
        if self.payments_provider == "stripe":
            if not re.fullmatch(r"(sk|rk)_(live|test)_[A-Za-z0-9]{10,}", self.stripe_secret_key):
                raise ValueError("STRIPE_SECRET_KEY (sk_live_/sk_test_) lazmi hai jab PAYMENTS_PROVIDER=stripe ho")
            if not self.stripe_webhook_secret.startswith("whsec_"):
                raise ValueError("STRIPE_WEBHOOK_SECRET (whsec_...) lazmi hai")
            if not (self.stripe_price_pro.startswith("price_") and self.stripe_price_business.startswith("price_")):
                raise ValueError("STRIPE_PRICE_PRO aur STRIPE_PRICE_BUSINESS (price_...) lazmi hain")
            if self.is_production and self.stripe_secret_key.startswith(("sk_test_", "rk_test_")):
                raise ValueError("Production mein Stripe live key chahiye, test key nahi")
            if self.is_production and not self.base_url.startswith("https://"):
                raise ValueError("Production mein BASE_URL https:// honi chahiye (payment redirect)")
        if self.sso_shared_secret and len(self.sso_shared_secret) < 32:
            raise ValueError("SSO_SHARED_SECRET kam az kam 32 random characters ki ho (ya khali chhoren)")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
