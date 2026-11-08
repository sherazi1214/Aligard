(function () {
  "use strict";
  var AG = window.AliGuard;
  if (!AG) return;
  var $ = function (s) { return document.querySelector(s); };
  var state = null;
  function el(tag, text, cls) { var n = document.createElement(tag); if (text !== undefined) n.textContent = String(text); if (cls) n.className = cls; return n; }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  function cookie(name) {
    var row = document.cookie.split("; ").filter(function (x) { return x.indexOf(name + "=") === 0; })[0];
    return row ? decodeURIComponent(row.slice(name.length + 1)) : "";
  }
  async function request(url, method, body) {
    var csrf = cookie("aliguard_csrf");
    if (!csrf) { await fetch("/api/auth/csrf", { credentials: "same-origin" }); csrf = cookie("aliguard_csrf"); }
    var opts = { method: method, credentials: "same-origin", headers: { "X-CSRF-Token": csrf } };
    if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    var res = await fetch(url, opts), data = {};
    try { data = await res.json(); } catch (e) { /* response body optional */ }
    if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Request nakam hui.");
    return data;
  }
  function renderWhitelist(items) {
    var list = $("#whitelist-list"); clear(list);
    if (!items.length) { list.appendChild(el("li", "Whitelist khali hai.", "muted")); return; }
    items.forEach(function (item) {
      var li = el("li"), label = el("span", item.kind + ": " + item.value), btn = el("button", "Remove", "danger");
      btn.type = "button";
      btn.addEventListener("click", async function () {
        try { await request("/api/settings/whitelist/" + encodeURIComponent(item.id), "DELETE"); await load(); AG.show("ok", "Whitelist entry remove ho gayi."); }
        catch (e) { AG.show("error", e.message); }
      });
      li.appendChild(label); li.appendChild(btn); list.appendChild(li);
    });
  }
  function render(data) {
    state = data;
    $("#alerts_enabled").checked = data.alerts_enabled;
    $("#email_alerts").checked = data.email_alerts;
    $("#telegram_alerts").checked = data.telegram_alerts;
    $("#suspicious_threshold").value = data.suspicious_threshold;
    $("#phishing_threshold").value = data.phishing_threshold;
    $("#suspicious_threshold").min = data.minimum_suspicious_threshold;
    $("#phishing_threshold").min = data.minimum_phishing_threshold;
    $("#min-suspicious").textContent = data.minimum_suspicious_threshold;
    $("#min-phishing").textContent = data.minimum_phishing_threshold;
    $("#telegram-status").textContent = !data.telegram_configured ? "Server par Telegram bot configure nahi hai." : (data.telegram_linked ? "Telegram linked hai." : "Telegram abhi linked nahi hai.");
    $("#telegram-link").disabled = !data.telegram_configured;
    $("#telegram-unlink").disabled = !data.telegram_linked;
    renderWhitelist(data.whitelist || []);
  }
  async function load() { render(await AG.get("/api/settings")); }

  $("#settings-form").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var suspicious = Number($("#suspicious_threshold").value), phishing = Number($("#phishing_threshold").value);
    if (!Number.isInteger(suspicious) || !Number.isInteger(phishing) || phishing <= suspicious) { AG.show("error", "Phishing threshold suspicious threshold se bara hona chahiye."); return; }
    try {
      var data = await request("/api/settings", "PATCH", {
        alerts_enabled: $("#alerts_enabled").checked, email_alerts: $("#email_alerts").checked,
        telegram_alerts: $("#telegram_alerts").checked, suspicious_threshold: suspicious, phishing_threshold: phishing
      });
      render(data); AG.show("ok", "Settings save ho gayi.");
    } catch (e) { AG.show("error", e.message); }
  });

  $("#whitelist-form").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var value = $("#whitelist-value").value.trim();
    if (!value) { AG.show("error", "Email ya domain likhein."); return; }
    try { await request("/api/settings/whitelist", "POST", { kind: $("#whitelist-kind").value, value: value }); $("#whitelist-value").value = ""; await load(); AG.show("ok", "Whitelist entry add ho gayi."); }
    catch (e) { AG.show("error", e.message); }
  });

  $("#telegram-link").addEventListener("click", async function () {
    try {
      var data = await request("/api/settings/telegram/link", "POST", {});
      if (typeof data.url !== "string" || data.url.indexOf("https://t.me/") !== 0) throw new Error("Telegram link ghalat hai.");
      window.open(data.url, "_blank", "noopener,noreferrer");
      AG.show("ok", "Telegram link limited time ke liye bana hai. Bot par /start link complete karein.");
    } catch (e) { AG.show("error", e.message); }
  });
  $("#telegram-unlink").addEventListener("click", async function () {
    if (!window.confirm("Telegram alerts unlink karein?")) return;
    try { await request("/api/settings/telegram/link", "DELETE"); await load(); AG.show("ok", "Telegram unlink ho gaya."); }
    catch (e) { AG.show("error", e.message); }
  });
  $("#delete-data").addEventListener("click", async function () {
    if (!window.confirm("Ye irreversible hai. Kya aap waqai apna AliGuard account aur sara local data delete karna chahte hain?")) return;
    var phrase = window.prompt("Confirm karne ke liye DELETE_MY_DATA likhein:");
    if (phrase !== "DELETE_MY_DATA") { AG.show("error", "Deletion cancel ho gayi."); return; }
    try { await request("/api/settings/data?confirm=DELETE_MY_DATA", "DELETE"); location.href = "/signup"; }
    catch (e) { AG.show("error", e.message); }
  });
  load().catch(function (e) { AG.show("error", e.message); });
})();
