"use client";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import PostmortemView from "@/components/PostmortemView";
import ThreatCore, { type Blip } from "@/components/ThreatCore";
import { Button, Drawer, Field, Meter, VerdictBadge } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { hashStr, timeAgo, useCountUp, useDebounced } from "@/lib/hooks";
import { useToast } from "@/lib/toast";
import { verdictTone, type GmailAccounts, type ScanDetail, type ScanList, type ScanSummary, type Stats, type Tone, type Verdict } from "@/lib/types";

const GMAIL_MSG: Record<string, [string, string]> = {
  connected: ["ok", "Gmail connected. The worker will start scanning shortly."],
  denied: ["err", "Permission was denied, Gmail was not connected."],
  scope: ["err", "The required Gmail permission (gmail.modify) was not granted."],
  limit: ["err", "Gmail account limit reached."],
  mismatch: ["err", "You signed in to a different Google account than the address you typed. Try again with the same account."],
  session: ["err", "Session expired. Log in again and retry."],
  error: ["err", "Could not connect Gmail. Please try again."],
};
const PAGE_SIZE = 12;
const FILTERS: { v: "" | Verdict; label: string }[] = [
  { v: "", label: "All" }, { v: "PHISHING", label: "Phishing" }, { v: "SUSPICIOUS", label: "Suspicious" }, { v: "SAFE", label: "Safe" },
];
const ACTION_LABEL: Record<string, string> = {
  quarantined: "quarantined", restored: "restored", labeled: "labelled", none: "no action", pending: "pending", failed: "action failed",
};

function Stat({ label, value, tone }: { label: string; value: number; tone: Tone }) {
  const n = useCountUp(value);
  return (
    <div className={`stat stat--${tone}`}>
      <div className="stat__n">{n.toLocaleString()}</div>
      <div className="stat__l">{label}</div>
    </div>
  );
}

function Inner() {
  const router = useRouter();
  const params = useSearchParams();
  const toast = useToast();

  const [stats, setStats] = useState<Stats | null>(null);
  const [accounts, setAccounts] = useState<GmailAccounts | null>(null);
  const [list, setList] = useState<ScanList | null>(null);
  const [recent, setRecent] = useState<ScanSummary[]>([]);
  const [page, setPage] = useState(1);
  const [verdict, setVerdict] = useState<"" | Verdict>("");
  const [q, setQ] = useState("");
  const dq = useDebounced(q);
  const [loadingList, setLoadingList] = useState(true);
  const [connecting, setConnecting] = useState(false);
  const [gmailInput, setGmailInput] = useState("");
  const [selId, setSelId] = useState<string | null>(null);
  const [detail, setDetail] = useState<ScanDetail | null>(null);
  const [detailBusy, setDetailBusy] = useState(false);
  const seen = useRef<Set<string> | null>(null);
  const [fresh, setFresh] = useState<Set<string>>(new Set());

  // gmail callback result
  useEffect(() => {
    const g = params.get("gmail");
    if (!g) return;
    const m = GMAIL_MSG[g] ?? GMAIL_MSG.error;
    toast(m[0] as "ok" | "err", m[1]);
    router.replace("/dashboard");
  }, [params, router, toast]);

  const loadTop = useCallback(async () => {
    try {
      const [s, a, r] = await Promise.all([
        api<Stats>("/api/scans/stats"),
        api<GmailAccounts>("/api/gmail/accounts"),
        api<ScanList>("/api/scans?page_size=28"),
      ]);
      setStats(s); setAccounts(a); setRecent(r.items);
    } catch { /* silent: poll dobara try karega */ }
  }, []);

  const loadList = useCallback(async (silent = false) => {
    if (!silent) setLoadingList(true);
    try {
      const qs = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) });
      if (verdict) qs.set("verdict", verdict);
      if (dq.trim()) qs.set("q", dq.trim());
      const r = await api<ScanList>(`/api/scans?${qs}`);
      setList(r);
      const ids = new Set(r.items.map((i) => i.id));
      if (seen.current && silent) {
        const added = r.items.filter((i) => !seen.current!.has(i.id)).map((i) => i.id);
        if (added.length) { setFresh(new Set(added)); setTimeout(() => setFresh(new Set()), 4000); }
      }
      seen.current = ids;
    } catch (e) {
      if (!silent) toast("err", e instanceof ApiError ? e.message : "Could not load scans");
    } finally { if (!silent) setLoadingList(false); }
  }, [page, verdict, dq, toast]);

  useEffect(() => { void loadTop(); }, [loadTop]);
  useEffect(() => { seen.current = null; void loadList(); }, [loadList]);
  useEffect(() => { setPage(1); }, [verdict, dq]);

  // live refresh
  useEffect(() => {
    const id = setInterval(() => {
      if (document.hidden) return;
      void loadTop(); void loadList(true);
    }, 30000);
    return () => clearInterval(id);
  }, [loadTop, loadList]);

  // detail
  useEffect(() => {
    if (!selId) { setDetail(null); return; }
    let cancel = false;
    setDetailBusy(true); setDetail(null);
    api<ScanDetail>(`/api/scans/${selId}`)
      .then((d) => { if (!cancel) setDetail(d); })
      .catch((e) => { if (!cancel) { toast("err", e instanceof ApiError ? e.message : "Could not load scan"); setSelId(null); } })
      .finally(() => { if (!cancel) setDetailBusy(false); });
    return () => { cancel = true; };
  }, [selId, toast]);

  async function connect() {
    setConnecting(true);
    try {
      const r = await api<{ auth_url: string }>("/api/gmail/connect", { method: "POST", body: { email: gmailInput.trim() || null } });
      window.location.href = r.auth_url;
    } catch (e) { toast("err", e instanceof ApiError ? e.message : "Connect failed"); setConnecting(false); }
  }
  // Portal se Gmail plan khareed kar aaye (?connect=gmail): welcome card dikhta hai jis mein "Connect Gmail" button hai.
  // Param turant hata dete hain (refresh par dobara nahi aata); card tab tak rehta hai jab tak inbox connect na ho ya user band na kare.
  const [welcome, setWelcome] = useState(false);
  useEffect(() => {
    if (params.get("connect") !== "gmail") return;
    setWelcome(true);
    router.replace("/dashboard");
  }, [params, router]);

  async function disconnect(id: string, email: string) {
    if (!window.confirm(`Disconnect ${email}? Scanning for this account will stop.`)) return;
    try { await api(`/api/gmail/accounts/${id}/disconnect`, { method: "POST" }); toast("ok", "Account disconnected."); void loadTop(); }
    catch (e) { toast("err", e instanceof ApiError ? e.message : "Disconnect failed"); }
  }
  async function restore(id: string) {
    try {
      await api(`/api/scans/${id}/restore`, { method: "POST" });
      toast("ok", "Email restored to your inbox.");
      setDetail((d) => (d ? { ...d, action_taken: "restored" } : d));
      void loadTop(); void loadList(true);
    } catch (e) { toast("err", e instanceof ApiError ? e.message : "Restore failed"); }
  }
  async function feedback(id: string) {
    try { await api(`/api/scans/${id}/feedback`, { method: "POST", body: { kind: "not_phishing" } }); toast("ok", "Thanks, feedback recorded."); }
    catch (e) { toast("err", e instanceof ApiError ? e.message : "Feedback failed"); }
  }

  const flagged = stats ? stats.suspicious + stats.phishing : 0;
  const share = stats && stats.scanned ? Math.round((flagged / stats.scanned) * 100) : 0;
  const coreTone: Tone = !stats || stats.scanned === 0 ? "idle" : stats.phishing > 0 ? (share >= 20 ? "danger" : "warn") : stats.suspicious > 0 ? "warn" : "safe";
  const blips: Blip[] = useMemo(() => recent.map((s, idx) => ({
    angle: hashStr(s.id) % 360, r: (hashStr(s.id + "r") % 100) / 100, tone: verdictTone(s.verdict), fresh: idx < 2 && fresh.has(s.id),
  })), [recent, fresh]);
  const scannedN = useCountUp(stats?.scanned ?? 0);
  const totalPages = list ? Math.max(1, Math.ceil(list.total / list.page_size)) : 1;
  const noAccounts = accounts && accounts.accounts.filter((a) => a.status !== "disconnected").length === 0;

  return (
    <div className="dash">
      <section className="dash__banner">
        <div>
          <h1 className="page-title">Command center</h1>
          <p className="muted">Live view of every email AliGuard has inspected, what it decided, and why.</p>
        </div>
        <div className={`threat-level threat-level--${coreTone}`}>
          <span className="threat-level__l">threat level</span>
          <strong>{coreTone === "idle" ? "standing by" : coreTone === "safe" ? "low" : coreTone === "warn" ? "elevated" : "high"}</strong>
        </div>
      </section>
      {welcome && accounts?.configured && noAccounts ? (
        <section className="dash__welcome glass" style={{ gridColumn: "1 / -1", padding: 28, display: "grid", gap: 12, justifyItems: "center", textAlign: "center" }}>
          <h2>Plan active! Ab apna Gmail connect karein</h2>
          <p className="muted">Button dabane par Google aap ke is device par signed-in saare Gmail accounts dikhayega. Jo account protect karna hai usay chunein aur Allow karein.</p>
          <form onSubmit={(ev) => { ev.preventDefault(); void connect(); }} style={{ display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap", justifyContent: "center", width: "100%" }}>
            <div style={{ flex: "1 1 260px", maxWidth: 360, textAlign: "left" }}>
              <Field label="Gmail address" type="email" name="gmail" autoComplete="email" placeholder="name@gmail.com"
                value={gmailInput} onChange={(ev) => setGmailInput(ev.target.value)} />
            </div>
            <Button type="submit" loading={connecting}>Connect Gmail</Button>
            <Button type="button" variant="ghost" onClick={() => setWelcome(false)}>Baad mein</Button>
          </form>
        </section>
      ) : null}
      <section className="dash__core glass">
        <div className="dash__corewrap">
          <ThreatCore value={share} tone={coreTone} size={300} blips={blips}>
            <div className="core-score">{stats ? scannedN.toLocaleString() : "--"}</div>
            <div className="core-sub">emails scanned</div>
            <div className={`core-verdict core-verdict--${coreTone} is-on`}>{stats && stats.scanned ? `${share}% flagged` : "standing by"}</div>
          </ThreatCore>
        </div>
        <div className="dash__stats">
          <Stat label="Safe" value={stats?.safe ?? 0} tone="safe" />
          <Stat label="Suspicious" value={stats?.suspicious ?? 0} tone="warn" />
          <Stat label="Phishing" value={stats?.phishing ?? 0} tone="danger" />
          <Stat label="Quarantined" value={stats?.quarantined ?? 0} tone="idle" />
        </div>
      </section>

      <section className="dash__gmail glass">
        <div className="panel-head">
          <h2>Connected inboxes</h2>
        </div>
        {accounts?.configured ? (
          <form onSubmit={(ev) => { ev.preventDefault(); void connect(); }} style={{ display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap", marginBottom: 12 }}>
            <div style={{ flex: "1 1 240px" }}>
              <Field label="Gmail address" type="email" name="gmail" autoComplete="email" placeholder="name@gmail.com"
                value={gmailInput} onChange={(ev) => setGmailInput(ev.target.value)} />
            </div>
            <Button type="submit" loading={connecting}>Connect</Button>
          </form>
        ) : null}
        {!accounts ? <div className="skeleton" /> : !accounts.configured ? (
          <p className="muted">Gmail connection is not configured on this server yet.</p>
        ) : accounts.accounts.length === 0 ? (
          <div className="empty">
            <div className="empty__ring" aria-hidden="true" />
            <p>No inbox is being watched. Type your Gmail above and click Connect.</p>
          </div>
        ) : (
          <ul className="accts">
            {accounts.accounts.map((a) => (
              <li key={a.id}>
                <span className={`dot dot--${a.status === "active" ? "ok" : a.status === "disconnected" ? "off" : "bad"}`} />
                <div className="accts__info">
                  <strong>{a.email}</strong>
                  <span>{a.status === "needs_reauth" ? "needs reconnect" : a.status}{a.last_run_at ? ` · last scan ${timeAgo(a.last_run_at)}` : ""}</span>
                </div>
                {a.status === "needs_reauth" ? <Button variant="ghost" className="btn--sm" onClick={connect}>Reconnect</Button> : null}
                {a.status !== "disconnected" ? <button className="linkish linkish--danger" onClick={() => void disconnect(a.id, a.email)}>Disconnect</button> : null}
              </li>
            ))}
          </ul>
        )}
        {noAccounts && accounts?.configured ? null : null}
      </section>

      <section className="dash__feed glass">
        <div className="panel-head panel-head--wrap">
          <h2>Threat feed <span className="live-tag"><i />live</span></h2>
          <div className="feed-tools">
            <div className="seg" role="tablist" aria-label="Filter by verdict">
              {FILTERS.map((f) => (
                <button key={f.label} role="tab" aria-selected={verdict === f.v} className={verdict === f.v ? "is-on" : ""} onClick={() => setVerdict(f.v)}>{f.label}</button>
              ))}
            </div>
            <input className="search" placeholder="Search sender or subject" aria-label="Search scans" value={q} onChange={(e) => setQ(e.target.value)} maxLength={100} />
          </div>
        </div>

        {loadingList && !list ? (
          <div className="feed-skel">{Array.from({ length: 5 }, (_, i) => <div key={i} className="skeleton" />)}</div>
        ) : !list || list.items.length === 0 ? (
          <div className="empty">
            <div className="empty__ring" aria-hidden="true" />
            <p>{verdict || dq ? "Nothing matches this filter." : "No emails scanned yet. Results appear here as the worker processes your inbox."}</p>
          </div>
        ) : (
          <ul className="feed" aria-busy={loadingList}>
            {list.items.map((s) => (
              <li key={s.id}>
                <button className={`row row--${verdictTone(s.verdict)} ${fresh.has(s.id) ? "row--fresh" : ""}`} onClick={() => setSelId(s.id)}>
                  <span className="row__score">{s.score}</span>
                  <span className="row__main">
                    <span className="row__subj">{s.subject || "(no subject)"}</span>
                    <span className="row__from">{s.sender || "unknown sender"}</span>
                  </span>
                  <span className="row__meta">
                    <VerdictBadge v={s.verdict} />
                    <span className="row__time">{s.action_taken && s.action_taken !== "none" ? `${ACTION_LABEL[s.action_taken] ?? s.action_taken} · ` : ""}{timeAgo(s.created_at)}</span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}

        {list && list.total > 0 ? (
          <div className="pager">
            <span>{list.total.toLocaleString()} results</span>
            <div>
              <button className="btn btn--ghost btn--sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}><span>Prev</span></button>
              <span className="pager__n">{page} / {totalPages}</span>
              <button className="btn btn--ghost btn--sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}><span>Next</span></button>
            </div>
          </div>
        ) : null}
      </section>

      <Drawer open={!!selId} onClose={() => setSelId(null)} title="Scan report">
        {detailBusy || !detail ? <div className="feed-skel"><div className="skeleton" /><div className="skeleton" /><div className="skeleton" /></div> : (
          <div className="report">
            <div className="report__top">
              <ThreatCore value={detail.score} tone={verdictTone(detail.verdict)} size={150}>
                <div className="core-score core-score--sm">{detail.score}</div>
              </ThreatCore>
              <div>
                <VerdictBadge v={detail.verdict} />
                <h3 className="report__subj">{detail.subject || "(no subject)"}</h3>
                <p className="report__from">{detail.sender || "unknown sender"}</p>
                <p className="report__meta">{new Date(detail.created_at).toLocaleString()}{detail.action_taken && detail.action_taken !== "none" ? ` · ${ACTION_LABEL[detail.action_taken] ?? detail.action_taken}` : ""}</p>
              </div>
            </div>

            <h4>Why this verdict</h4>
            {detail.reasons.length ? <ul className="reasons">{detail.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul> : <p className="muted">No specific signals were recorded.</p>}

            <h4>Detection layers</h4>
            <div className="meters">
              {Object.entries(detail.layer_scores).map(([k, v]) => <Meter key={k} label={k} value={v} />)}
            </div>

            <PostmortemView pm={detail.postmortem} />

            {detail.urls.length ? (<><h4>Links found (defanged)</h4><ul className="urls">{detail.urls.map((u, i) => <li key={i}>{u}</li>)}</ul></>) : null}

            <div className="report__actions">
              {detail.action_taken === "quarantined" ? <Button onClick={() => void restore(detail.id)}>Restore to inbox</Button> : null}
              {detail.verdict !== "SAFE" ? <Button variant="ghost" onClick={() => void feedback(detail.id)}>This is not phishing</Button> : null}
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}

export default function DashboardPage() { return <Suspense><Inner /></Suspense>; }
