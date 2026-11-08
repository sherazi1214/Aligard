(() => {
  const $ = (s) => document.querySelector(s);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x !== undefined) e.textContent = x; return e; };
  async function api(path, method = "GET", body) {
    const r = await fetch("/api" + path, { method, credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Requested-With": "aliguard" }, body: body ? JSON.stringify(body) : undefined });
    let d = {}; try { d = await r.json(); } catch (e) { /* non-json */ }
    if (!r.ok) throw new Error(typeof d.detail === "string" ? d.detail : "Check your details and try again.");
    return d;
  }

  // Matrix rain (green, with an occasional red drop)
  const cv = $("#rain"), cx = cv.getContext("2d"); let cols = [], fs = 16;
  const glyphs = "01アイウエオカキクケコサシスセソ<>/{}#$%";
  function size() { cv.width = innerWidth; cv.height = innerHeight; cols = Array(Math.ceil(cv.width / fs)).fill(0).map(() => Math.random() * -50); }
  function rain() {
    if (document.hidden) return;
    cx.fillStyle = "rgba(4,7,6,.12)"; cx.fillRect(0, 0, cv.width, cv.height); cx.font = fs + "px monospace";
    cols.forEach((y, i) => {
      cx.fillStyle = Math.random() < 0.03 ? "#ff2b44" : "#19ff7a";
      cx.fillText(glyphs[(Math.random() * glyphs.length) | 0], i * fs, y * fs);
      cols[i] = y * fs > cv.height && Math.random() > 0.975 ? 0 : y + 1;
    });
  }
  size(); addEventListener("resize", size); setInterval(rain, 60);

  // Intrusion boot sequence
  const lines = ["> connecting to the open internet...", "> scanning for threats...", "[!] phishing link found in an inbox",
    "[!] fake courier message found on WhatsApp", "[!] unprotected login page found on a website", "> AliGuard online. Shields up."];
  const boot = $("#boot"), log = $("#bootlog");
  function endBoot() { sessionStorage.setItem("ag_boot", "1"); boot.classList.add("out"); setTimeout(() => (boot.hidden = true), 700); }
  if (sessionStorage.getItem("ag_boot") || matchMedia("(prefers-reduced-motion:reduce)").matches) boot.hidden = true;
  else {
    $("#skip").onclick = endBoot; let i = 0;
    const next = () => { if (boot.hidden || i >= lines.length) { if (!boot.hidden) setTimeout(endBoot, 700); return; }
      const s = el("span", lines[i].startsWith("[!]") ? "bad" : "", lines[i++] + "\n"); log.append(s); setTimeout(next, 650); };
    next();
  }

  // Portal
  let mode = "login", resetToken = "", googleOn = false;
  const dlg = $("#auth"), pw = $("#pw"), pw2 = $("#pw2");
  const T = { login: ["Sign in", "Sign in", "Welcome back. Your shields are waiting."],
    signup: ["Create account", "Create account", "Join the cyber world in under a minute."],
    forgot: ["Reset password", "Send reset link", "We will email you a one-time link."],
    reset: ["Choose a new password", "Save new password", "Pick a strong password you have not used before."] };
  function openAuth(m, msg) {
    mode = m; const su = m === "signup", lg = m === "login", fg = m === "forgot", rs = m === "reset";
    $("#authtitle").textContent = T[m][0]; $("#go").textContent = T[m][1]; $("#authsub").textContent = T[m][2];
    $("#f-google").hidden = !(su || lg); $("#f-user").hidden = !su; $("#f-email").hidden = rs; $("#f-pw").hidden = fg; $("#f-pw2").hidden = !(su || rs);
    $("#emaillbl").textContent = lg ? "Gmail or username" : "Gmail"; $("#email").placeholder = lg ? "name@gmail.com or username" : "name@gmail.com";
    $("#email").type = lg ? "text" : "email";
    $("#pwlbl").textContent = rs ? "New password" : "Password"; $("#meter").hidden = $("#meterlbl").hidden = !(su || rs);
    $("#forgot").hidden = !lg;
    $("#swap").textContent = lg ? "Create an account instead" : su ? "I already have an account" : "Back to sign in";
    pw.autocomplete = lg ? "current-password" : "new-password";
    pw.value = pw2.value = ""; meter(); matchHint();
    document.querySelectorAll(".eye").forEach((b) => setEye(b, false));
    $("#err").textContent = ""; $("#ok").textContent = msg || ""; if (!dlg.open) dlg.showModal();
    (rs ? pw : su ? $("#username") : $("#email")).focus();
  }

  // Eye icon: click to show or hide the password next to it
  function setEye(b, show) {
    const inp = b.parentElement.querySelector("input"); inp.type = show ? "text" : "password";
    b.classList.toggle("on", show); b.setAttribute("aria-pressed", show); b.setAttribute("aria-label", show ? "Hide password" : "Show password");
  }
  document.querySelectorAll(".eye").forEach((b) => (b.onclick = () => setEye(b, b.getAttribute("aria-pressed") !== "true")));

  // Password strength meter and match hint
  function meter() {
    const v = pw.value; let n = 0;
    if (v.length >= 12) n++; if (v.length >= 16) n++; if (/[a-z]/.test(v) && /[A-Z]/.test(v)) n++; if (/\d/.test(v) && /[^A-Za-z0-9]/.test(v)) n++;
    if (v.length < 12) n = 0;
    const m = $("#meter"); m.dataset.n = n;
    $("#meterlbl").textContent = !v ? "Use 12 or more characters" : v.length < 12 ? (12 - v.length) + " more character(s) needed" : ["", "Okay", "Good", "Strong", "Excellent"][n] || "Okay";
  }
  function matchHint() {
    const h = $("#matchlbl"); if (!pw2.value) { h.textContent = ""; h.className = "hint"; return; }
    const ok = pw.value === pw2.value; h.textContent = ok ? "Passwords match" : "Passwords do not match"; h.className = "hint " + (ok ? "good" : "bad");
  }
  pw.oninput = () => { meter(); matchHint(); }; pw2.oninput = matchHint;

  $("#swap").onclick = () => openAuth(mode === "login" ? "signup" : "login");
  $("#forgot").onclick = () => openAuth("forgot");
  $("#close").onclick = () => dlg.close();
  $("#cta").onclick = () => openAuth("signup");
  $("#google").onclick = (e) => { if (!googleOn) { e.preventDefault(); $("#err").textContent = "Google sign-in is not set up on this server yet. Use your details below."; } };

  function validate() {
    const u = $("#username").value.trim(), e = $("#email").value.trim();
    if (mode === "signup") {
      if (!/^[A-Za-z0-9_]{3,20}$/.test(u)) return "Username must be 3-20 letters, numbers or underscores.";
      if (!/^[^@\s]{1,64}@[^@\s]{1,200}\.[^@\s]{2,}$/.test(e)) return "Enter a valid Gmail address.";
    }
    if (mode === "login" && (!e || !pw.value)) return "Enter your Gmail or username and your password.";
    if (mode === "forgot" && !e) return "Enter your Gmail address.";
    if ((mode === "signup" || mode === "reset") && pw.value.length < 12) return "Your password needs at least 12 characters.";
    if ((mode === "signup" || mode === "reset") && pw.value !== pw2.value) return "The two passwords do not match.";
    return "";
  }
  $("#authform").onsubmit = async (e) => {
    e.preventDefault(); $("#err").textContent = ""; $("#ok").textContent = "";
    const bad = validate(); if (bad) { $("#err").textContent = bad; return; }
    const go = $("#go"); go.disabled = true; let navigating = false;
    try {
      if (mode === "forgot") { await api("/forgot", "POST", { email: $("#email").value });
        $("#ok").textContent = "If that email has an account, a reset link has been sent. (Dev mode: the link is printed in the server console.)"; return; }
      if (mode === "reset") { await api("/reset", "POST", { token: resetToken, password: pw.value });
        resetToken = ""; history.replaceState(null, "", "/"); openAuth("login", "Password changed. Sign in with the new one."); return; }
      const body = mode === "login" ? { email: $("#email").value.trim(), password: pw.value }
        : { username: $("#username").value.trim(), email: $("#email").value.trim(), password: pw.value, confirm: pw2.value };
      await api(mode === "login" ? "/login" : "/signup", "POST", body);
      pw.value = pw2.value = ""; go.textContent = "Entering the cyber world..."; navigating = true; location.href = "/world";
    } catch (x) { $("#err").textContent = x.message; }
    finally { if (!navigating) go.disabled = false; }
  };

  async function start() {
    try {
      const [me, cfg] = await Promise.all([api("/me"), api("/config")]);
      if (me.user) { location.replace("/world"); return; }
      googleOn = cfg.google;
    } catch (e) { /* landing page still works offline */ }
    const m = location.hash.match(/^#reset=([\w-]{20,})$/);
    if (m) { resetToken = m[1]; openAuth("reset"); }
    const er = location.hash.match(/^#auth_error=(\w+)$/);
    if (er) { history.replaceState(null, "", "/"); openAuth("login");
      $("#err").textContent = er[1] === "google_off" ? "Google sign-in is not set up on this server yet." : er[1] === "verify_failed" ? "That verification link is invalid or expired. Sign in and press Resend." : "Google sign-in failed. Please try again."; }
  }
  start();
})();
