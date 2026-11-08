"""Postmortem = "is mail ke saath asal mein kya mila" ka saaf, STORE-SAFE khulasa.
Saare URLs defanged (hxxp, [.]), lambai par hadd, page ka text/screenshot kabhi shamil nahi.
Attacker-controlled strings hain: UI sirf text ke taur par dikhaye (React/textContent)."""
from __future__ import annotations

from engine.urls import defang


def _d(u: str, n: int = 300) -> str:
    return defang(str(u)[:n])


def build_postmortem(sandbox: list[dict], attachments: list[dict], domains: list[dict],
                     qr_urls: list[str]) -> dict:
    sbx = []
    for r in sandbox[:5]:
        sbx.append({
            "url": _d(r.get("url", "")), "final_url": _d(r.get("final_url", "")),
            "redirect_chain": [_d(u) for u in (r.get("redirect_chain") or [])[:10]],
            "status": r.get("status"), "title": str(r.get("title", ""))[:120],
            "elapsed_ms": r.get("elapsed_ms"), "error": r.get("error"),
            "hidden_iframes": r.get("hidden_iframes", 0),
            "downloads": [str(x)[:80] for x in (r.get("downloads") or [])[:5]],
            "blocked_targets": len(r.get("blocked_targets") or []),
            "forms": [{"action": _d(f.get("action", "")) if f.get("action") else "",
                       "has_password": bool(f.get("has_password")), "method": f.get("method", "get")}
                      for f in (r.get("forms") or [])[:5]],
            "findings": [s.get("text", "")[:200] for s in (r.get("signals") or [])[:10]],
            "points": r.get("points", 0),
        })
    att = [{**{k: v for k, v in a.items() if k != "urls"}, "urls": [_d(u) for u in a.get("urls", [])[:5]]}
           for a in attachments[:10]]
    return {"version": 1, "sandbox": sbx, "attachments": att,
            "domains": [dict(d) for d in domains[:5]], "qr_links": [_d(u) for u in qr_urls[:5]]}
