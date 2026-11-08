# AliGuard Frontend (Sentinel UI)

> Ye folder ab poore AliGuard repo ka hissa hai (`../`). Compose/Caddy/Render/CI ki jo setup yahan README mein likhi hai
> wo ab root par ready hai: `../docker-compose.prod.yml`, `../deploy/Caddyfile`, `../render.yaml`, `../docs/DEPLOY.md`.

Black-glass cyber UI for the AliGuard backend. Next.js 14 + TypeScript, koi UI library nahi.
Backend mein koi code change nahi chahiye.

## Pages
`/` landing (live dissection demo) · `/login` `/login/2fa` `/signup` `/verify-email` `/forgot-password` `/reset-password`
· `/dashboard` (Threat Core radar, live feed, Gmail accounts, scan report drawer) · `/scanner` (link/message check)
· `/settings` (alerts, thresholds, whitelist, Telegram, 2FA, password, delete data)
`/privacy` aur `/terms` backend ke apne pages par proxy hote hain.

## Ye kaise kaam karta hai
Browser sirf frontend ke domain se baat karta hai. `next.config.js` `/api/*` ko backend par proxy karta hai,
isliye session cookie (SameSite=Lax), CSRF aur Gmail OAuth callback bina kisi CORS ke chalte hain.

## Local chalana
```bash
# 1) backend (alag terminal) - .env mein ye cheezein:
#    BASE_URL=http://localhost:3000
#    CORS_ORIGINS=http://localhost:3000
#    (Google Console redirect URI: http://localhost:3000/api/gmail/callback)
uvicorn backend.app.main:app --port 8000
python -m backend.app.worker

# 2) frontend
cp .env.example .env.local     # BACKEND_URL=http://127.0.0.1:8000
npm install
npm run dev                    # http://localhost:3000
```

## Production (zaroori)
1. **Backend ka `BASE_URL` frontend ka domain ho** (verify/reset email links `BASE_URL/verify-email?...` banate hain,
   aur CSRF Origin check bhi isi par hota hai). `CORS_ORIGINS` mein bhi wahi domain.
2. **Google redirect URI** = `https://<frontend-domain>/api/gmail/callback`.
3. **`BACKEND_URL` build se pehle set karein** (rewrites build par bake hote hain).

### Render (frontend ke liye Web Service, Node)
Build: `npm ci && npm run build` · Start: `npm start` · Env: `BACKEND_URL=https://<aliguard-web>.onrender.com`.
Phir backend ke `BASE_URL`/`CORS_ORIGINS` ko is frontend ke domain par update karke redeploy karein.

### VPS (Docker + Caddy)
`docker build -t aliguard-frontend --build-arg BACKEND_URL=http://web:8000 .` phir compose mein `frontend` service
(port 3000) jorein, aur Caddyfile aisi karein:
```
{$DOMAIN} {
	encode zstd gzip
	@api path /api/* /health* /privacy /terms /static/*
	handle @api { reverse_proxy web:8000 }
	handle { reverse_proxy frontend:3000 }
}
```

## Customize
Rang `src/app/globals.css` ke `:root` mein, copy components mein. Radar: `src/components/ThreatCore.tsx`.
Animations `prefers-reduced-motion` ka khayal rakhti hain.
