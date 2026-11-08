# Link Sandbox (postmortem)

Shak wali mail ke 1-2 links isolated headless Chromium mein khulte hain. Browser dekhta hai: redirect chain, login form
(password), form kahan submit hota hai, page kis brand ka lagta hai vs asli domain, auto-download, hidden iframe.
Har cheez `Signal(layer="sandbox")` ban kar score mein judti hai aur `sandbox_reports` mein poora postmortem aata hai.

## Kab chalta hai
- `SANDBOX_ENABLED=true` ho, mail mein URL ho, score >= `sandbox_min_score` (15) ho, aur VirusTotal/feed ka hard hit na ho.
- Bilkul saaf mails ke links kabhi nahi khulte (cost + risk kam).

## Chalane se pehle (zaroori)
1. `pip install -r requirements-sandbox.txt && playwright install --with-deps chromium`
2. **Alag container/VM mein chalao**, jis se internal network, DB, Redis aur cloud metadata (169.254.169.254) tak raasta na ho.
   Code har request par private IP block karta hai, lekin DNS-rebinding se asli hifazat network-level isolation hai.
3. Resource limits (CPU/RAM), aur concurrency limit lagao: ek time par 2-3 browsers se zyada nahi.
4. Egress sirf 80/443.

## Limits (honest)
- Cloaking: kuch phishing pages bot pehchan kar saaf page dikhate hain. Sandbox sirf ek signal hai, akela hukm nahi.
- CAPTCHA/geo-blocked pages khulte nahi: `sandbox_error:*` note aata hai, points nahi.
- Abhi sandbox_reports scans table mein save nahi hote (sirf API response mein); DB column aglay step mein.
- Asli phishing URLs par live test nahi hua, sirf local fake page par.
