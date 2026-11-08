// AliGuard UI. CSP 'self' ke liye inline script nahi. Server/user ka koi bhi text sirf textContent se dikhta hai.
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var statusEl = $("#status"), errorEl = $("#error");

  function show(el, text) {
    statusEl.hidden = true; errorEl.hidden = true;
    if (!text) return;
    el.textContent = text; el.hidden = false;
    if (el === errorEl) errorEl.focus();
  }
  function cookie(name) {
    var m = document.cookie.split("; ").filter(function (c) { return c.indexOf(name + "=") === 0; })[0];
    return m ? decodeURIComponent(m.slice(name.length + 1)) : "";
  }
  async function csrf() {
    if (!cookie("aliguard_csrf")) await fetch("/api/auth/csrf", { credentials: "same-origin" });
    return cookie("aliguard_csrf");
  }
  async function post(url, body) {
    var res = await fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": await csrf() },
      body: JSON.stringify(body || {})
    });
    var data = {};
    try { data = await res.json(); } catch (e) { /* khali body */ }
    if (!res.ok) {
      var d = data.detail;
      throw new Error(typeof d === "string" ? d : "Request nakam hui. Dobara try karein.");
    }
    return data;
  }

  async function get(url) {
    var res = await fetch(url, { credentials: "same-origin" });
    var data = {};
    try { data = await res.json(); } catch (e) { /* khali body */ }
    if (res.status === 401) { location.href = "/login"; throw new Error("Login zaroori hai"); }
    if (!res.ok) {
      var d = data.detail;
      throw new Error(typeof d === "string" ? d : "Request nakam hui. Dobara try karein.");
    }
    return data;
  }
  // dashboard.js in helpers ko use karta hai (alag file, CSP ke liye inline script nahi)
  window.AliGuard = { get: get, post: post, show: function (kind, text) { show(kind === "error" ? errorEl : statusEl, text); } };

  // Token URL se hidden field mein, phir URL se hata do
  var tokenInput = $('input[name="token"]');
  if (tokenInput) {
    var t = new URLSearchParams(location.search).get("token");
    if (t) { tokenInput.value = t; history.replaceState(null, "", location.pathname); }
  }

  document.querySelectorAll(".toggle-password").forEach(function (b) {
    b.addEventListener("click", function () {
      var inp = document.getElementById(b.getAttribute("aria-controls"));
      var showing = inp.type === "text";
      inp.type = showing ? "password" : "text";
      b.textContent = showing ? "Dikhayein" : "Chhupayein";
      b.setAttribute("aria-pressed", String(!showing));
    });
  });

  document.querySelectorAll("form[data-endpoint]").forEach(function (form) {
    form.addEventListener("submit", async function (ev) {
      ev.preventDefault();
      show(errorEl, "");
      var body = {};
      new FormData(form).forEach(function (v, k) { if (k.slice(-8) !== "_confirm") body[k] = String(v); });
      var conf = form.dataset.confirm;
      if (conf) {
        var a = form.elements[conf], c = form.elements[conf + "_confirm"];
        if (a && c && a.value !== c.value) { show(errorEl, "Dono passwords ek jaise nahi hain"); return; }
      }
      var btn = form.querySelector('button[type="submit"]');
      btn.disabled = true;
      try {
        var data = await post(form.dataset.endpoint, body);
        if (form.hasAttribute("data-show-codes") && data.recovery_codes) {
          $("#codes").textContent = data.recovery_codes.join("\n");
          $("#totp-box").hidden = true; $("#codes-box").hidden = false;
          return;
        }
        if (data.status === "2fa_required" && form.dataset.next2fa) { location.href = form.dataset.next2fa; return; }
        if (form.hasAttribute("data-reload")) { location.reload(); return; }
        if (form.dataset.next) { location.href = form.dataset.next; return; }
        if (form.hasAttribute("data-reset-on-success")) form.reset();
        show(statusEl, data.message || "Ho gaya");
      } catch (e) {
        show(errorEl, e.message);
      } finally {
        btn.disabled = false;
      }
    });
    if (form.hasAttribute("data-autosubmit") && form.elements.token && form.elements.token.value) {
      form.requestSubmit();
    }
  });

  document.querySelectorAll("button[data-action]").forEach(function (b) {
    b.addEventListener("click", async function () {
      var act = b.dataset.action;
      try {
        if (act === "logout" || act === "logout-all") {
          await post("/api/auth/" + act); location.href = "/login";
        } else if (act === "totp-setup") {
          var d = await post("/api/auth/2fa/setup");
          $("#totp-qr").src = d.qr_data_uri;           // data: URI, CSP img-src mein allowed
          $("#totp-secret").textContent = d.secret;
          $("#totp-box").hidden = false; b.hidden = true;
        } else if (act === "reload") { location.reload(); }
      } catch (e) { show(errorEl, e.message); }
    });
  });
})();
