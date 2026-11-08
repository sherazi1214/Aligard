// AliGuard dashboard. CSP 'self': inline script nahi. Server ka koi bhi text (sender, subject, reasons, URLs)
// sirf textContent se dikhta hai; class/attribute mein server ki string kabhi nahi jati.
(function () {
  "use strict";
  var AG = window.AliGuard;
  if (!AG) { return; }
  var $ = function (s, r) { return (r || document).querySelector(s); };

  var VERDICT_CLASS = { SAFE: "v-safe", SUSPICIOUS: "v-susp", PHISHING: "v-phish" };
  var GMAIL_MSG = {
    connected: "Gmail connect ho gaya.",
    denied: "Aap ne ijazat nahi di, Gmail connect nahi hua.",
    scope: "Zaroori Gmail ijazat (gmail.modify) nahi di gayi, isliye connect nahi hua.",
    limit: "Gmail accounts ki hadd poori ho gayi.",
    mismatch: "Aap ne type kiye gaye Gmail se alag Google account se login kiya. Wohi account chunein.",
    session: "Login dobara karke try karein.",
    error: "Gmail connect nahi ho saka. Dobara try karein."
  };
  var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  var state = { page: 1, pageSize: 20, verdict: "", q: "", pages: 1 };

  function el(tag, text, cls) {
    var n = document.createElement(tag);
    if (cls) { n.className = cls; }
    if (text !== undefined && text !== null) { n.textContent = String(text); }
    return n;
  }
  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }
  function fmtTime(iso) {
    var d = new Date(iso);
    return isNaN(d.getTime()) ? "-" : d.toLocaleString();
  }
  function badge(verdict) {
    var cls = Object.prototype.hasOwnProperty.call(VERDICT_CLASS, verdict) ? VERDICT_CLASS[verdict] : "";
    return el("span", verdict, "badge " + cls);
  }
  function fail(e) { AG.show("error", e && e.message ? e.message : "Request nakam hui."); }

  // ---------- tabs ----------
  var tabs = Array.prototype.slice.call(document.querySelectorAll('[role="tab"]'));
  function selectTab(tab) {
    tabs.forEach(function (t) {
      var on = t === tab;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
    });
    tab.focus();
  }
  tabs.forEach(function (t, i) {
    t.addEventListener("click", function () { selectTab(t); });
    t.addEventListener("keydown", function (ev) {
      var next = ev.key === "ArrowRight" ? i + 1 : ev.key === "ArrowLeft" ? i - 1 : null;
      if (next === null) { return; }
      ev.preventDefault();
      selectTab(tabs[(next + tabs.length) % tabs.length]);
    });
  });

  // ---------- stats ----------
  async function loadStats() {
    var s = await AG.get("/api/scans/stats");
    $("#st-scanned").textContent = String(s.scanned);
    $("#st-suspicious").textContent = String(s.suspicious + s.phishing);
    $("#st-quarantined").textContent = String(s.quarantined);
  }

  // ---------- gmail accounts ----------
  async function loadAccounts() {
    var data = await AG.get("/api/gmail/accounts");
    var list = $("#accounts"), note = $("#gmail-note"), btn = $("#connect-btn");
    clear(list);
    data.accounts.forEach(function (a) {
      var li = el("li");
      var info = el("span");
      info.appendChild(el("strong", a.email));
      info.appendChild(el("span", " (" + a.status + ")", "muted"));
      if (a.last_run_at) { info.appendChild(el("span", " - aakhri scan: " + fmtTime(a.last_run_at), "muted")); }
      li.appendChild(info);
      if (a.status !== "disconnected" && UUID_RE.test(a.id)) {
        var b = el("button", "Disconnect", "danger");
        b.type = "button";
        b.addEventListener("click", function () { disconnect(a.id, a.email); });
        li.appendChild(b);
      }
      list.appendChild(li);
    });
    if (!data.configured) {
      note.textContent = "Gmail connect abhi server par configure nahi hai.";
      note.hidden = false; btn.hidden = true;
    } else {
      var active = data.accounts.filter(function (a) { return a.status !== "disconnected"; }).length;
      var reconnectNeeded = data.accounts.some(function (a) { return a.status === "needs_reauth"; });
      note.hidden = true; btn.hidden = active >= data.max_accounts && !reconnectNeeded;
    }
  }
  async function connect() {
    var inp = $("#gmail-input");
    var data = await AG.post("/api/gmail/connect", { email: inp ? inp.value.trim() || null : null });
    // Sirf Google ke apne domain par jao (server response par bhi andha bharosa nahi)
    if (typeof data.auth_url !== "string" || data.auth_url.indexOf("https://accounts.google.com/") !== 0) {
      throw new Error("Connect link ghalat mila.");
    }
    location.href = data.auth_url;
  }
  async function disconnect(id, email) {
    if (!window.confirm(email + " ko disconnect karein? Tokens delete aur Google par revoke honge.")) { return; }
    try {
      await AG.post("/api/gmail/accounts/" + encodeURIComponent(id) + "/disconnect");
      AG.show("ok", "Disconnect ho gaya.");
      await loadAccounts(); await loadScans(); await loadStats();
    } catch (e) { fail(e); }
  }

  // ---------- scan log ----------
  async function loadScans() {
    var qs = new URLSearchParams({ page: String(state.page), page_size: String(state.pageSize) });
    if (state.verdict) { qs.set("verdict", state.verdict); }
    if (state.q) { qs.set("q", state.q); }
    var data = await AG.get("/api/scans?" + qs.toString());
    var body = $("#scan-body");
    clear(body);
    data.items.forEach(function (s) {
      var tr = el("tr");
      tr.appendChild(el("td", fmtTime(s.created_at)));
      tr.appendChild(el("td", s.sender));
      tr.appendChild(el("td", s.subject));
      var tdv = el("td"); tdv.appendChild(badge(s.verdict)); tr.appendChild(tdv);
      tr.appendChild(el("td", s.score));
      tr.appendChild(el("td", s.action_taken));
      var tdb = el("td");
      if (UUID_RE.test(s.id)) {
        var b = el("button", "Tafseel", "secondary");
        b.type = "button";
        b.addEventListener("click", function () { openDetail(s.id); });
        tdb.appendChild(b);
      }
      tr.appendChild(tdb);
      body.appendChild(tr);
    });
    $("#scan-empty").hidden = data.items.length > 0;
    state.pages = Math.max(1, Math.ceil(data.total / data.page_size));
    $("#page-info").textContent = "Page " + data.page + " / " + state.pages + " (" + data.total + " scans)";
    $("#prev").disabled = data.page <= 1;
    $("#next").disabled = data.page >= state.pages;
  }

  function dlRow(dl, label, valueNode) {
    dl.appendChild(el("dt", label));
    var dd = el("dd"); dd.appendChild(valueNode); dl.appendChild(dd);
  }
  function listNode(items) {
    if (!items || !items.length) { return el("span", "-", "muted"); }
    var ul = el("ul");
    items.forEach(function (x) { ul.appendChild(el("li", x)); });
    return ul;
  }
  function layerNode(scores) {
    var names = Object.keys(scores || {});
    if (!names.length) { return el("span", "-", "muted"); }
    var ul = el("ul");
    names.forEach(function (n) {
      var v = scores[n];
      ul.appendChild(el("li", n + ": " + (v === null || v === undefined ? "chali nahi" : v)));
    });
    return ul;
  }
  async function openDetail(id) {
    try {
      var d = await AG.get("/api/scans/" + encodeURIComponent(id));
      var box = $("#detail-body"); clear(box);
      var dl = el("dl");
      dlRow(dl, "Sender", el("span", d.sender));
      dlRow(dl, "Subject", el("span", d.subject));
      dlRow(dl, "Verdict", badge(d.verdict));
      dlRow(dl, "Score", el("span", d.score));
      dlRow(dl, "Wajah", listNode(d.reasons));
      dlRow(dl, "Kis layer ne kya kaha", layerNode(d.layer_scores));
      dlRow(dl, "URLs (defanged)", listNode(d.urls));
      dlRow(dl, "Action", el("span", d.action_taken));
      dlRow(dl, "Model", el("span", d.model_version || "-"));
      box.appendChild(dl);
      var actions = el("div", undefined, "detail-actions");
      if (d.action_taken === "quarantined") {
        var restore = el("button", "Email restore karein", "secondary"); restore.type = "button";
        restore.addEventListener("click", async function () {
          if (!window.confirm("Is email ko Gmail Inbox mein wapas lana hai?")) return;
          try { await AG.post("/api/scans/" + encodeURIComponent(id) + "/restore"); AG.show("ok", "Email restore ho gayi."); await loadScans(); await loadStats(); await openDetail(id); }
          catch (e) { fail(e); }
        }); actions.appendChild(restore);
      }
      var feedback = el("button", "Ye phishing nahi thi", "secondary"); feedback.type = "button";
      feedback.addEventListener("click", async function () {
        try { await AG.post("/api/scans/" + encodeURIComponent(id) + "/feedback", { kind: "not_phishing" }); feedback.disabled = true; feedback.textContent = "Feedback record ho gaya"; AG.show("ok", "Feedback record ho gaya."); }
        catch (e) { fail(e); }
      }); actions.appendChild(feedback); box.appendChild(actions);
      $("#detail").hidden = false;
      $("#detail-h").focus();
    } catch (e) { fail(e); }
  }

  // ---------- manual checks ----------
  function renderResult(target, r) {
    clear(target);
    var dl = el("dl");
    dlRow(dl, "Verdict", badge(r.verdict));
    dlRow(dl, "Score", el("span", r.score + " / 100"));
    dlRow(dl, "Bharosa", el("span", Math.round((r.confidence || 0) * 100) + "%"));
    dlRow(dl, "Wajah", listNode(r.reasons));
    dlRow(dl, "Kis layer ne kya kaha", layerNode(r.layer_scores));
    dlRow(dl, "URLs (defanged)", listNode(r.defanged_urls));
    if (r.degraded) { dlRow(dl, "Note", el("span", "Kuch layers nahi chali, nateeja adhoora ho sakta hai.")); }
    var wrap = el("div"); wrap.appendChild(dl);
    target.appendChild(wrap);
  }
  document.querySelectorAll("form[data-check]").forEach(function (form) {
    form.addEventListener("submit", async function (ev) {
      ev.preventDefault();
      var body = { kind: form.dataset.check };
      new FormData(form).forEach(function (v, k) { body[k] = String(v); });
      var btn = form.querySelector('button[type="submit"]');
      btn.disabled = true;
      try {
        var r = await AG.post("/api/check", body);
        renderResult(document.getElementById("result-" + form.dataset.check), r);
      } catch (e) { fail(e); } finally { btn.disabled = false; }
    });
  });

  // ---------- wiring ----------
  $("#filters").addEventListener("submit", function (ev) {
    ev.preventDefault();
    state.verdict = $("#f-verdict").value; state.q = $("#f-q").value.trim(); state.page = 1;
    loadScans().catch(fail);
  });
  document.querySelectorAll("button[data-dash]").forEach(function (b) {
    b.addEventListener("click", function () {
      var act = b.dataset.dash;
      if (act === "connect") { connect().catch(fail); }
      else if (act === "prev" && state.page > 1) { state.page -= 1; loadScans().catch(fail); }
      else if (act === "next" && state.page < state.pages) { state.page += 1; loadScans().catch(fail); }
      else if (act === "close-detail") { $("#detail").hidden = true; }
    });
  });

  // OAuth se wapas: ?gmail=<code>; sirf fixed messages (URL ka text kabhi nahi dikhate)
  var gm = new URLSearchParams(location.search).get("gmail");
  if (gm !== null) {
    history.replaceState(null, "", location.pathname);
    if (Object.prototype.hasOwnProperty.call(GMAIL_MSG, gm)) {
      AG.show(gm === "connected" ? "ok" : "error", GMAIL_MSG[gm]);
    }
  }
  Promise.all([loadStats(), loadAccounts(), loadScans()]).catch(fail);
})();
