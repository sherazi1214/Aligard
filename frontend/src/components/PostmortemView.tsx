"use client";
import type { Postmortem } from "@/lib/types";

/* Postmortem: engine ne link/attachment ke saath asal mein kya paya. Saari strings attacker-controlled hain,
   isliye sirf React text (auto-escaped) mein dikhti hain; koi dangerouslySetInnerHTML nahi, koi live link nahi
   (URLs pehle se defanged aate hain). */
export default function PostmortemView({ pm }: { pm?: Postmortem | null }) {
  if (!pm) return null;
  const sbx = pm.sandbox ?? [], att = pm.attachments ?? [], dom = pm.domains ?? [], qr = pm.qr_links ?? [];
  if (!sbx.length && !att.length && !dom.length && !qr.length) return null;
  return (
    <section className="pm">
      <h4>Postmortem</h4>
      {pm.truncated ? <p className="muted">Report was shortened for size.</p> : null}

      {sbx.map((s, i) => (
        <div className="pm__card" key={`s${i}`}>
          <div className="pm__title">Link opened in sandbox{s.error ? <span className="pm__tag pm__tag--warn">{s.error}</span> : null}</div>
          <ol className="pm__chain">
            {(s.redirect_chain.length ? s.redirect_chain : [s.url]).map((h, j, a) => (
              <li key={j} className={j === a.length - 1 ? "pm__hop pm__hop--end" : "pm__hop"}>{h}</li>
            ))}
          </ol>
          <dl className="pm__kv">
            {s.title ? <><dt>Page title</dt><dd>{s.title}</dd></> : null}
            <dt>Login form</dt><dd>{s.forms.some((f) => f.has_password) ? <span className="pm__tag pm__tag--bad">asks for password</span> : "none"}</dd>
            {s.forms.filter((f) => f.action).map((f, k) => <div key={k} className="pm__row"><dt>Form sends to</dt><dd>{f.action}</dd></div>)}
            {s.downloads.length ? <><dt>Auto-download</dt><dd>{s.downloads.join(", ")}</dd></> : null}
            {s.hidden_iframes ? <><dt>Hidden iframes</dt><dd>{s.hidden_iframes}</dd></> : null}
            {s.blocked_targets ? <><dt>Blocked internal targets</dt><dd>{s.blocked_targets}</dd></> : null}
          </dl>
          {s.findings.length ? <ul className="pm__find">{s.findings.map((f, k) => <li key={k}>{f}</li>)}</ul> : null}
        </div>
      ))}

      {att.length ? (
        <div className="pm__card">
          <div className="pm__title">Attachments inspected</div>
          {att.map((a, i) => (
            <div key={i} className="pm__att">
              <b>{a.name}</b> <span className="muted">({a.real_type}, {Math.round(a.size / 1024)} KB)</span>
              {a.findings.length ? <ul className="pm__find">{a.findings.map((f, k) => <li key={k}>{f}</li>)}</ul> : <span className="pm__tag pm__tag--ok">clean</span>}
              {a.urls.map((u, k) => <div key={k} className="pm__hop">{u}</div>)}
            </div>
          ))}
        </div>
      ) : null}

      {qr.length ? (
        <div className="pm__card">
          <div className="pm__title">Hidden inside a QR code</div>
          {qr.map((u, i) => <div key={i} className="pm__hop pm__hop--end">{u}</div>)}
        </div>
      ) : null}

      {dom.length ? (
        <div className="pm__card">
          <div className="pm__title">Domain age</div>
          <dl className="pm__kv">
            {dom.map((d, i) => (
              <div key={i} className="pm__row"><dt>{d.domain}</dt>
                <dd>{d.age_days === null ? "unknown" : <span className={`pm__tag pm__tag--${d.age_days < 30 ? "bad" : d.age_days < 90 ? "warn" : "ok"}`}>{d.age_days} days old</span>}</dd></div>
            ))}
          </dl>
        </div>
      ) : null}
    </section>
  );
}
