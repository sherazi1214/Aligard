(() => {
  const $ = (s) => document.querySelector(s);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x !== undefined) e.textContent = x; return e; };
  const calm = matchMedia("(prefers-reduced-motion:reduce)").matches;
  async function api(path, method = "GET", body) {
    const r = await fetch("/api" + path, { method, credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Requested-With": "aliguard" }, body: body ? JSON.stringify(body) : undefined });
    let d = {}; try { d = await r.json(); } catch (e) { /* non-json */ }
    if (!r.ok) { const err = new Error(typeof d.detail === "string" ? d.detail : "Something went wrong."); err.status = r.status; throw err; }
    return d;
  }

  // Matrix rain
  const cv = $("#rain"), cx = cv.getContext("2d"); let cols = []; const fs = 16, glyphs = "01<>/{}#$%ABCDEF";
  function size() { cv.width = innerWidth; cv.height = innerHeight; cols = Array(Math.ceil(cv.width / fs)).fill(0).map(() => Math.random() * -50); }
  function rain() {
    if (document.hidden) return;
    cx.fillStyle = "rgba(3,8,6,.12)"; cx.fillRect(0, 0, cv.width, cv.height); cx.font = fs + "px monospace";
    cols.forEach((y, i) => { cx.fillStyle = Math.random() < 0.04 ? "#ff2b44" : "#19ff7a";
      cx.fillText(glyphs[(Math.random() * glyphs.length) | 0], i * fs, y * fs); cols[i] = y * fs > cv.height && Math.random() > 0.975 ? 0 : y + 1; });
  }
  size(); addEventListener("resize", size); if (!calm) setInterval(rain, 60);

  // Cursor glow
  addEventListener("pointermove", (e) => { document.documentElement.style.setProperty("--mx", e.clientX + "px"); document.documentElement.style.setProperty("--my", e.clientY + "px"); });

  // Entry overlay
  const enter = $("#enter"), steps = ["Authenticating...", "Verifying session...", "Loading threat radar...", "Access granted."];
  let si = 0;
  const stepper = setInterval(() => { si++; if (si < steps.length) $("#enterTxt").textContent = steps[si]; else clearInterval(stepper); }, calm ? 1 : 420);
  const openWorld = () => setTimeout(() => enter.classList.add("out"), calm ? 0 : 1800);

  // Typewriter
  const phrases = ["Your inbox is under watch.", "Your chats are under watch.", "Your website is under watch.", "Shields up. Stay one step ahead."];
  function typer() {
    const out = $("#typed"); let p = 0, i = 0, del = false;
    if (calm) { out.textContent = phrases[0]; return; }
    (function tick() {
      const w = phrases[p]; out.textContent = w.slice(0, i);
      if (!del && i === w.length) { del = true; return setTimeout(tick, 1500); }
      if (del && i === 0) { del = false; p = (p + 1) % phrases.length; }
      i += del ? -1 : 1; setTimeout(tick, del ? 28 : 55);
    })();
  }

  // Counters
  function count(b) {
    const end = parseFloat(b.dataset.n), d = +b.dataset.d || 0, t0 = performance.now(), dur = 1800;
    const fmt = (v) => end >= 1e6 ? (v / 1e6).toFixed(1) + "M" : end >= 1e3 ? Math.round(v / 1e3) + "K" : v.toFixed(d);
    (function f(t) { const k = Math.min(1, (t - t0) / dur), v = end * (1 - Math.pow(1 - k, 3)); b.textContent = calm ? fmt(end) : fmt(v); if (k < 1 && !calm) requestAnimationFrame(f); })(t0);
  }

  // Scroll reveal + counters
  const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("vis"); io.unobserve(e.target); } }), { threshold: 0.12 });
  document.querySelectorAll(".rv").forEach((n) => io.observe(n));
  const io2 = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { count(e.target); io2.unobserve(e.target); } }), { threshold: 0.5 });
  document.querySelectorAll(".stat b").forEach((n) => io2.observe(n));

  // Simulated threat feed (terminal and ticker)
  const events = [
    ["bad", "[BLOCKED] phishing email: sender domain imitates a bank"], ["bad", "[BLOCKED] fake courier link spreading in a group chat"],
    ["info", "[SCAN] checking security headers on a protected website"], ["bad", "[BLOCKED] 340 password guesses from one address"],
    ["ok", "[OK] outdated plugin patched, risk closed"], ["bad", "[BLOCKED] prize scam asking for a card number"],
    ["info", "[SCAN] SSL certificate valid for 61 more days"], ["bad", "[QUARANTINE] attachment with a hidden script"],
    ["ok", "[OK] two-factor sign-in confirmed for a member"], ["bad", "[BLOCKED] login page cloned from a popular service"],
  ];
  const term = $("#term"), track = $("#track");
  const time = () => new Date().toTimeString().slice(0, 8);
  function push() { const [k, t] = events[(Math.random() * events.length) | 0]; term.append(el("p", k, time() + "  " + t)); while (term.children.length > 11) term.firstChild.remove(); }
  for (let i = 0; i < 6; i++) push(); if (!calm) setInterval(push, 1700);
  [...events, ...events].forEach(([k, t]) => { const s = el("span"); const m = t.match(/^\[(\w+)\]\s*(.*)$/); const b = el("b", "", m[1] + " "); s.append(b, m[2]); track.append(s); });

  // Network canvas: attacks (red) travel toward the shield and are absorbed
  const nc = $("#net"), nx = nc.getContext("2d"); let W = 0, H = 0, nodes = [], pk = [];
  function nsize() { const r = nc.parentElement.getBoundingClientRect(); W = nc.width = r.width; H = nc.height = r.height;
    nodes = Array.from({ length: 16 }, (_, i) => { const a = (i / 16) * Math.PI * 2 + Math.random() * 0.3, d = Math.min(W, H) * (0.34 + Math.random() * 0.12);
      return { a, d, x: W / 2 + Math.cos(a) * d, y: H / 2 + Math.sin(a) * d, bad: Math.random() < 0.55 }; }); }
  function npush() { const n = nodes[(Math.random() * nodes.length) | 0]; if (n) pk.push({ n, t: 0, bad: n.bad }); }
  function ndraw() {
    if (document.hidden || !W) return requestAnimationFrame(ndraw);
    nx.clearRect(0, 0, W, H); const cx0 = W / 2, cy0 = H / 2, tt = performance.now() / 1000;
    nodes.forEach((n) => { n.x = cx0 + Math.cos(n.a + tt * 0.05) * n.d; n.y = cy0 + Math.sin(n.a + tt * 0.05) * n.d;
      nx.strokeStyle = "rgba(25,255,122,.12)"; nx.beginPath(); nx.moveTo(n.x, n.y); nx.lineTo(cx0, cy0); nx.stroke();
      nx.fillStyle = n.bad ? "#ff2b44" : "#19e6ff"; nx.beginPath(); nx.arc(n.x, n.y, 4, 0, 7); nx.fill(); });
    pk = pk.filter((p) => { p.t += 0.012; const x = p.n.x + (cx0 - p.n.x) * p.t, y = p.n.y + (cy0 - p.n.y) * p.t;
      nx.fillStyle = p.bad ? "#ff2b44" : "#19ff7a"; nx.shadowBlur = 12; nx.shadowColor = nx.fillStyle; nx.beginPath(); nx.arc(x, y, 3.2, 0, 7); nx.fill(); nx.shadowBlur = 0; return p.t < 0.86; });
    const pulse = 26 + Math.sin(tt * 3) * 3; nx.strokeStyle = "#19ff7a"; nx.lineWidth = 2; nx.shadowBlur = 20; nx.shadowColor = "#19ff7a";
    nx.beginPath(); nx.arc(cx0, cy0, pulse, 0, 7); nx.stroke(); nx.shadowBlur = 0; nx.lineWidth = 1;
    nx.fillStyle = "#19ff7a"; nx.font = "700 14px monospace"; nx.textAlign = "center"; nx.fillText("AG", cx0, cy0 + 5);
    requestAnimationFrame(ndraw);
  }
  nsize(); addEventListener("resize", nsize); if (!calm) { setInterval(npush, 420); ndraw(); }

  // Link lab (basic local heuristics, a demo and not a real scan)
  $("#lab-f").onsubmit = (e) => {
    e.preventDefault(); const raw = $("#lab-in").value.trim(), v = $("#verdict"); v.className = "verdict"; v.replaceChildren();
    if (!raw) return; let u;
    try { u = new URL(/^[a-z]+:\/\//i.test(raw) ? raw : "http://" + raw); } catch (x) { v.className = "verdict show warn"; v.append(el("h3", "", "That does not look like a link"), el("p", "", "Paste a full address such as https://example.com/page")); return; }
    const flags = [], h = u.hostname.toLowerCase();
    if (u.protocol !== "https:") flags.push("Not using HTTPS, so the connection is not encrypted.");
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) flags.push("The address is a raw IP number instead of a name.");
    if (h.startsWith("xn--") || h.includes(".xn--")) flags.push("Uses look-alike (punycode) characters that can imitate a real brand.");
    if (u.username || raw.includes("@")) flags.push("Contains an @ sign, a trick used to hide the real destination.");
    if ((h.match(/-/g) || []).length >= 2) flags.push("Many hyphens in the domain, common in fake brand sites.");
    if (h.split(".").length > 4) flags.push("Unusually many subdomains, which can hide the true domain.");
    if (/\.(top|xyz|click|loan|work|gq|tk|ml|cf|zip|country)$/.test(h)) flags.push("Ends with a top-level domain often used in throwaway scam sites.");
    if (/(login|verify|secure|account|update|wallet|bank|signin|password|prize|claim)/.test(h + u.pathname)) flags.push("Contains pressure words like login, verify, secure or claim.");
    if (raw.length > 120) flags.push("Very long address, often used to bury the suspicious part.");
    const lvl = flags.length >= 3 ? "bad" : flags.length ? "warn" : "safe";
    v.className = "verdict show " + lvl;
    v.append(el("h3", "", lvl === "bad" ? "HIGH RISK: likely phishing" : lvl === "warn" ? "CAUTION: some warning signs" : "No common warning signs found"));
    if (flags.length) { const ul = el("ul"); flags.forEach((f) => ul.append(el("li", "", f))); v.append(ul); }
    else v.append(el("p", "", "This only checks the shape of the link. Stay careful with unknown senders."));
  };

  // Flip cards: tap to toggle on touch screens
  document.querySelectorAll(".flip").forEach((b) => (b.onclick = () => b.classList.toggle("on")));

  // Plans
  let me = { user: null, active: {} }, services = [];
  const ICON = { gmail: "@", whatsapp: "✆", website: "⌬" };
  function tilt(c) {
    c.onpointermove = (e) => { const r = c.getBoundingClientRect(), x = (e.clientX - r.left) / r.width, y = (e.clientY - r.top) / r.height;
      c.style.setProperty("--px", x * 100 + "%"); c.style.setProperty("--py", y * 100 + "%");
      if (!calm) { c.style.setProperty("--ry", (x - 0.5) * 10 + "deg"); c.style.setProperty("--rx", (0.5 - y) * 10 + "deg"); } };
    c.onpointerleave = () => { c.style.setProperty("--rx", "0deg"); c.style.setProperty("--ry", "0deg"); };
  }
  function render() {
    $("#uname").textContent = me.user.username;
    const box = $("#cards"); box.replaceChildren();
    services.forEach((s) => {
      const exp = me.active && me.active[s.id], c = el("article", "card " + s.tone);
      const ul = el("ul"); s.points.forEach((p) => ul.append(el("li", "", p)));
      const price = el("div", "price", "Rs " + s.price.toLocaleString()); price.append(el("small", "", " / month"));
      const st = el("div", "st " + (exp ? "on" : "off"), exp ? "Shield active until " + new Date(exp * 1000).toISOString().slice(0, 10) : "Not protected yet");
      const b = el("button", "btn " + (s.tone === "r" ? "red" : ""), exp ? "Protected" : "Activate (test mode)"); b.disabled = !!exp;
      b.onclick = async () => {
        b.disabled = true;
        try {
          const r = await api("/buy/" + s.id, "POST");
          if (r.sso_url) { location.href = r.sso_url; return; } // hand off into the AliGuard app, already signed in
          await load();
        } catch (x) { b.disabled = false; $("#note").textContent = x.message; $("#note").className = "note err"; }
      };
      c.append(el("div", "ico", ICON[s.id] || "#"), el("h3", "", s.name), el("p", "", s.tagline), ul, price, st, b);
      if (exp) { // already have this plan: offer a direct hop into the app instead of re-buying
        const open = el("a", "btn ghost", "Open AliGuard app");
        open.onclick = async (e) => { e.preventDefault(); try { const r = await api("/sso-url"); location.href = r.url; } catch (x) { $("#note").textContent = x.message; $("#note").className = "note err"; } };
        c.append(open);
      }
      tilt(c); box.append(c);
    });
    $("#note").textContent = me.test_mode ? "Test mode: no real payment is taken yet." : ""; $("#note").className = "note";
    if (me.user.verified === false) { // email not confirmed yet: plans stay locked until it is
      $("#note").textContent = "Confirm your email to activate plans. We sent you a link. ";
      const rs = el("a", "", "Resend"); rs.href = "#"; rs.onclick = async (e) => { e.preventDefault(); try { await api("/resend-verify", "POST"); $("#note").textContent = "Verification email sent."; } catch (x) { $("#note").textContent = x.message; $("#note").className = "note err"; } };
      $("#note").append(rs); $("#note").className = "note err";
    }
  }
  async function load() { me = await api("/me"); if (!me.user) { location.replace("/"); return; } services = await api("/services"); render(); }

  $("#out").onclick = async () => { try { await api("/logout", "POST"); } finally { location.replace("/"); } };
  load().then(() => { clearInterval(stepper); $("#enterTxt").textContent = "Welcome, " + me.user.username; openWorld(); typer(); })
    .catch((e) => { if (e.status === 401) location.replace("/"); else { $("#enterTxt").textContent = "Server is not reachable."; } });
})();
