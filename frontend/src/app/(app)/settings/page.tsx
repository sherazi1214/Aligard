"use client";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Button, Field, PasswordField, Toggle } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";
import { useToast } from "@/lib/toast";
import type { SettingsData } from "@/lib/types";

function errMsg(e: unknown, fallback: string) { return e instanceof ApiError ? e.message : fallback; }

function Alerts({ s, onChange }: { s: SettingsData; onChange: (s: SettingsData) => void }) {
  const toast = useToast();
  const [sus, setSus] = useState(s.suspicious_threshold);
  const [phi, setPhi] = useState(s.phishing_threshold);
  const [busy, setBusy] = useState(false);
  useEffect(() => { setSus(s.suspicious_threshold); setPhi(s.phishing_threshold); }, [s.suspicious_threshold, s.phishing_threshold]);

  async function patch(body: Partial<SettingsData>) {
    try { onChange(await api<SettingsData>("/api/settings", { method: "PATCH", body })); }
    catch (e) { toast("err", errMsg(e, "Could not save")); }
  }
  async function saveThresholds() {
    setBusy(true);
    try { onChange(await api<SettingsData>("/api/settings", { method: "PATCH", body: { suspicious_threshold: sus, phishing_threshold: phi } })); toast("ok", "Sensitivity updated."); }
    catch (e) { toast("err", errMsg(e, "Could not save")); }
    finally { setBusy(false); }
  }
  async function linkTelegram() {
    try { const r = await api<{ url: string }>("/api/settings/telegram/link", { method: "POST" }); window.open(r.url, "_blank", "noopener,noreferrer"); toast("info", "Open Telegram and press Start, then refresh this page."); }
    catch (e) { toast("err", errMsg(e, "Telegram link failed")); }
  }
  async function unlinkTelegram() {
    try { await api("/api/settings/telegram/link", { method: "DELETE" }); onChange({ ...s, telegram_linked: false, telegram_alerts: false }); toast("ok", "Telegram unlinked."); }
    catch (e) { toast("err", errMsg(e, "Unlink failed")); }
  }
  const dirty = sus !== s.suspicious_threshold || phi !== s.phishing_threshold;
  const bad = phi <= sus || sus < s.minimum_suspicious_threshold || phi < s.minimum_phishing_threshold;

  return (
    <>
      <section className="set glass">
        <h2>Alerts</h2>
        <Toggle checked={s.alerts_enabled} onChange={(v) => void patch({ alerts_enabled: v })} label="Alerts enabled" sub="Master switch for every alert channel." />
        <Toggle checked={s.email_alerts} disabled={!s.alerts_enabled} onChange={(v) => void patch({ email_alerts: v })} label="Email alerts" sub="Get an email when something dangerous is caught." />
        <Toggle checked={s.telegram_alerts} disabled={!s.alerts_enabled || !s.telegram_linked} onChange={(v) => void patch({ telegram_alerts: v })} label="Telegram alerts" sub={s.telegram_linked ? "Linked." : "Link Telegram first."} />
        {s.telegram_configured ? (
          <div className="set__row">
            {s.telegram_linked ? <Button variant="ghost" className="btn--sm" onClick={unlinkTelegram}>Unlink Telegram</Button> : <Button variant="ghost" className="btn--sm" onClick={linkTelegram}>Link Telegram</Button>}
          </div>
        ) : null}
      </section>

      <section className="set glass">
        <h2>Sensitivity</h2>
        <p className="muted">Lower thresholds catch more, but may flag legitimate mail.</p>
        <div className="band" aria-hidden="true">
          <span className="band__safe" style={{ width: `${sus}%` }}>safe</span>
          <span className="band__warn" style={{ width: `${Math.max(0, phi - sus)}%` }}>suspicious</span>
          <span className="band__danger" style={{ width: `${Math.max(0, 100 - phi)}%` }}>phishing</span>
        </div>
        <label className="range"><span>Suspicious from <b>{sus}</b></span>
          <input type="range" min={0} max={99} value={sus} onChange={(e) => setSus(Number(e.target.value))} aria-label="Suspicious threshold" /></label>
        <label className="range"><span>Phishing from <b>{phi}</b></span>
          <input type="range" min={1} max={100} value={phi} onChange={(e) => setPhi(Number(e.target.value))} aria-label="Phishing threshold" /></label>
        {bad ? <p className="form__err">Phishing must be above suspicious. Minimums: {s.minimum_suspicious_threshold} / {s.minimum_phishing_threshold}.</p> : null}
        <div className="set__row"><Button onClick={saveThresholds} loading={busy} disabled={!dirty || bad}>Apply</Button></div>
      </section>
    </>
  );
}

function Whitelist({ s, onChange }: { s: SettingsData; onChange: (s: SettingsData) => void }) {
  const toast = useToast();
  const [kind, setKind] = useState<"sender" | "domain">("domain");
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  async function add(e: FormEvent) {
    e.preventDefault(); setBusy(true);
    try {
      const r = await api<{ id: string; kind: "sender" | "domain"; value: string }>("/api/settings/whitelist", { method: "POST", body: { kind, value } });
      onChange({ ...s, whitelist: [...s.whitelist, { ...r, created_at: new Date().toISOString() }] });
      setValue(""); toast("ok", "Added to whitelist.");
    } catch (ex) { toast("err", errMsg(ex, "Could not add")); }
    finally { setBusy(false); }
  }
  async function remove(id: string) {
    try { await api(`/api/settings/whitelist/${id}`, { method: "DELETE" }); onChange({ ...s, whitelist: s.whitelist.filter((w) => w.id !== id) }); }
    catch (ex) { toast("err", errMsg(ex, "Could not remove")); }
  }
  return (
    <section className="set glass">
      <h2>Trusted senders</h2>
      <p className="muted">Mail from these is never flagged.</p>
      <form onSubmit={add} className="inline-form">
        <select className="field__input select" value={kind} onChange={(e) => setKind(e.target.value as "sender" | "domain")} aria-label="Type">
          <option value="domain">Domain</option><option value="sender">Sender</option>
        </select>
        <input className="field__input" placeholder={kind === "domain" ? "example.com" : "person@example.com"} value={value} onChange={(e) => setValue(e.target.value)} aria-label="Value" />
        <Button type="submit" loading={busy} disabled={value.trim().length < 3}>Add</Button>
      </form>
      {s.whitelist.length ? (
        <ul className="chips">
          {s.whitelist.map((w) => (
            <li key={w.id}><em>{w.kind}</em>{w.value}<button onClick={() => void remove(w.id)} aria-label={`Remove ${w.value}`}>x</button></li>
          ))}
        </ul>
      ) : <p className="muted">Nothing whitelisted.</p>}
    </section>
  );
}

function Security() {
  const toast = useToast();
  const router = useRouter();
  const { me, refresh } = useSession();
  const [cur, setCur] = useState(""); const [nw, setNw] = useState(""); const [busyPw, setBusyPw] = useState(false);
  const [qr, setQr] = useState<{ secret: string; qr_data_uri: string } | null>(null);
  const [code, setCode] = useState(""); const [codes, setCodes] = useState<string[] | null>(null);
  const [offPw, setOffPw] = useState(""); const [offCode, setOffCode] = useState(""); const [offOpen, setOffOpen] = useState(false);

  async function changePw(e: FormEvent) {
    e.preventDefault(); setBusyPw(true);
    try { const r = await api<{ message: string }>("/api/auth/change-password", { method: "POST", body: { current_password: cur, new_password: nw } }); toast("ok", r.message); setCur(""); setNw(""); }
    catch (ex) { toast("err", errMsg(ex, "Password change failed")); }
    finally { setBusyPw(false); }
  }
  async function setup() { try { setQr(await api("/api/auth/2fa/setup", { method: "POST" })); } catch (ex) { toast("err", errMsg(ex, "2FA setup failed")); } }
  async function enable(e: FormEvent) {
    e.preventDefault();
    try { const r = await api<{ recovery_codes: string[] }>("/api/auth/2fa/enable", { method: "POST", body: { code } }); setCodes(r.recovery_codes); setQr(null); setCode(""); await refresh(); toast("ok", "Two-factor enabled."); }
    catch (ex) { toast("err", errMsg(ex, "Code rejected")); }
  }
  async function disable(e: FormEvent) {
    e.preventDefault();
    try { await api("/api/auth/2fa/disable", { method: "POST", body: { password: offPw, code: offCode } }); setOffOpen(false); setOffPw(""); setOffCode(""); await refresh(); toast("ok", "Two-factor disabled."); }
    catch (ex) { toast("err", errMsg(ex, "Could not disable")); }
  }
  async function logoutAll() {
    try { await api("/api/auth/logout-all", { method: "POST" }); router.replace("/login"); }
    catch (ex) { toast("err", errMsg(ex, "Failed")); }
  }

  return (
    <section className="set glass">
      <h2>Security</h2>
      <h4>Two-factor authentication</h4>
      {codes ? (
        <div className="codes">
          <p className="warn-note">Save these recovery codes now. They are shown only once.</p>
          <ul>{codes.map((c) => <li key={c}>{c}</li>)}</ul>
          <Button variant="ghost" className="btn--sm" onClick={() => setCodes(null)}>I saved them</Button>
        </div>
      ) : me.totp_enabled ? (
        offOpen ? (
          <form onSubmit={disable} className="form">
            <PasswordField label="Password" value={offPw} onChange={(e) => setOffPw(e.target.value)} autoComplete="current-password" />
            <Field label="Authenticator code" inputMode="numeric" value={offCode} onChange={(e) => setOffCode(e.target.value)} />
            <div className="set__row"><Button variant="danger" type="submit">Disable 2FA</Button><Button variant="ghost" type="button" onClick={() => setOffOpen(false)}>Cancel</Button></div>
          </form>
        ) : <div className="set__row"><span className="ok-note">Enabled</span><Button variant="ghost" className="btn--sm" onClick={() => setOffOpen(true)}>Disable</Button></div>
      ) : qr ? (
        <form onSubmit={enable} className="twofa">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src={qr.qr_data_uri} alt="Scan this QR code with your authenticator app" width={168} height={168} />
          <div>
            <p className="muted">Scan with Google Authenticator, Authy or similar. Or enter the key manually:</p>
            <code className="secret">{qr.secret}</code>
            <Field label="6-digit code" inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" />
            <Button type="submit" disabled={code.replace(/\s/g, "").length < 6}>Enable</Button>
          </div>
        </form>
      ) : <div className="set__row"><span className="muted">Off</span><Button variant="ghost" className="btn--sm" onClick={setup}>Set up 2FA</Button></div>}

      <h4>Change password</h4>
      <form onSubmit={changePw} className="form">
        <PasswordField label="Current password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} />
        <PasswordField label="New password" autoComplete="new-password" hint="Minimum 12 characters." value={nw} onChange={(e) => setNw(e.target.value)} />
        <div className="set__row"><Button type="submit" loading={busyPw} disabled={!cur || nw.length < 12}>Update password</Button></div>
      </form>

      <h4>Sessions</h4>
      <div className="set__row"><Button variant="ghost" onClick={logoutAll}>Log out of all devices</Button></div>
    </section>
  );
}

function Danger() {
  const toast = useToast();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  async function wipe() {
    setBusy(true);
    try { await api("/api/settings/data?confirm=DELETE_MY_DATA", { method: "DELETE" }); router.replace("/"); }
    catch (e) { toast("err", errMsg(e, "Deletion failed")); setBusy(false); }
  }
  return (
    <section className="set set--danger glass">
      <h2>Danger zone</h2>
      <p className="muted">Permanently erases your account, Gmail connections, scan history and settings. Google access is revoked. This cannot be undone.</p>
      {open ? (
        <div className="form">
          <Field label="Type DELETE_MY_DATA to confirm" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
          <div className="set__row"><Button variant="danger" onClick={wipe} loading={busy} disabled={confirm !== "DELETE_MY_DATA"}>Erase everything</Button><Button variant="ghost" onClick={() => { setOpen(false); setConfirm(""); }}>Cancel</Button></div>
        </div>
      ) : <div className="set__row"><Button variant="danger" onClick={() => setOpen(true)}>Delete my account and data</Button></div>}
    </section>
  );
}

export default function SettingsPage() {
  const toast = useToast();
  const [s, setS] = useState<SettingsData | null>(null);
  const load = useCallback(async () => {
    try { setS(await api<SettingsData>("/api/settings")); } catch (e) { toast("err", errMsg(e, "Could not load settings")); }
  }, [toast]);
  useEffect(() => { void load(); }, [load]);

  return (
    <div className="settings">
      <h1 className="page-title">Settings</h1>
      <p className="page-sub">Tune how strict AliGuard is, choose where alerts reach you, and keep full control of your data.</p>
      {!s ? <div className="settings__grid"><div className="skeleton skeleton--tall" /><div className="skeleton skeleton--tall" /></div> : (
        <div className="settings__grid">
          <div className="settings__col"><Alerts s={s} onChange={setS} /><Whitelist s={s} onChange={setS} /></div>
          <div className="settings__col"><Security /><Danger /></div>
        </div>
      )}
    </div>
  );
}
