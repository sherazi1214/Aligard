"use client";
import { useEffect, useRef, useState, type FormEvent } from "react";
import ThreatCore from "@/components/ThreatCore";
import { Button, Meter } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { useCountUp } from "@/lib/hooks";
import { useToast } from "@/lib/toast";
import { verdictTone, type CheckResult } from "@/lib/types";

const STEPS = [
  "parsing message structure",
  "heuristics: wording, urgency, lookalike domains",
  "classifier: scoring phishing probability",
  "reputation: checking every link",
  "deep analysis: resolving borderline signals",
  "merging layer scores",
];
const SAMPLE = {
  sender: "PayPaI Support <security@paypa1-verify.example>",
  subject: "Urgent: your account will be suspended",
  text: "Dear customer, we detected unusual activity on your account. Verify your identity within 24 hours: http://paypa1-verify.example/login or your account will be permanently closed.",
};
const MIN_SCAN_MS = 2200;

export default function ScannerPage() {
  const toast = useToast();
  const [kind, setKind] = useState<"link" | "message">("link");
  const [url, setUrl] = useState("");
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState(0);
  const [result, setResult] = useState<CheckResult | null>(null);
  const [err, setErr] = useState("");
  const resRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!busy) return;
    setStep(0);
    const id = setInterval(() => setStep((s) => Math.min(STEPS.length, s + 1)), 380);
    return () => clearInterval(id);
  }, [busy]);

  const score = useCountUp(result?.score ?? 0, 1200);

  async function run(e: FormEvent) {
    e.preventDefault();
    setErr(""); setResult(null); setBusy(true);
    const started = Date.now();
    try {
      const body = kind === "link" ? { kind, url } : { kind, sender, subject, text };
      const r = await api<CheckResult>("/api/check", { method: "POST", body });
      const wait = Math.max(0, MIN_SCAN_MS - (Date.now() - started));
      await new Promise((res) => setTimeout(res, wait));
      setResult(r);
      setTimeout(() => resRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
    } catch (ex) {
      const m = ex instanceof ApiError ? ex.message : "Scan failed";
      setErr(m); toast("err", m);
    } finally { setBusy(false); }
  }

  function loadSample() {
    setKind("message"); setSender(SAMPLE.sender); setSubject(SAMPLE.subject); setText(SAMPLE.text); setResult(null); setErr("");
  }

  const canRun = kind === "link" ? url.trim().length > 0 : text.trim().length > 0 || subject.trim().length > 0;

  return (
    <div className="scan">
      <section className="scan__in glass">
        <div className="panel-head">
          <h2>Threat scanner</h2>
          <button className="linkish" type="button" onClick={loadSample}>Load a sample phish</button>
        </div>
        <p className="muted">Paste a suspicious link or message. Nothing is stored, and links are never opened.</p>
        <div className="seg seg--wide" role="tablist" aria-label="What to scan">
          <button role="tab" aria-selected={kind === "link"} className={kind === "link" ? "is-on" : ""} onClick={() => setKind("link")}>Link</button>
          <button role="tab" aria-selected={kind === "message"} className={kind === "message" ? "is-on" : ""} onClick={() => setKind("message")}>Message</button>
        </div>
        <form onSubmit={run} className="form" noValidate>
          {kind === "link" ? (
            <label className="field"><span className="field__label">URL</span>
              <input className="field__input" placeholder="https://example.com/login" value={url} maxLength={2048} onChange={(e) => setUrl(e.target.value)} spellCheck={false} />
            </label>
          ) : (
            <>
              <div className="two">
                <label className="field"><span className="field__label">Sender</span>
                  <input className="field__input" placeholder="Name <address@domain>" value={sender} maxLength={320} onChange={(e) => setSender(e.target.value)} />
                </label>
                <label className="field"><span className="field__label">Subject</span>
                  <input className="field__input" value={subject} maxLength={500} onChange={(e) => setSubject(e.target.value)} />
                </label>
              </div>
              <label className="field"><span className="field__label">Message body</span>
                <textarea className="field__input field__input--area" rows={7} value={text} maxLength={50000} onChange={(e) => setText(e.target.value)} />
              </label>
            </>
          )}
          {err ? <p className="form__err" role="alert">{err}</p> : null}
          <Button type="submit" loading={busy} disabled={!canRun}>Run scan</Button>
        </form>
      </section>

      <section className="scan__out glass" ref={resRef} aria-live="polite">
        {busy ? (
          <div className="scanning">
            <ThreatCore value={0} tone="idle" scanning size={260}>
              <div className="core-sub">analysing</div>
            </ThreatCore>
            <ul className="console">
              {STEPS.slice(0, step).map((s, i) => <li key={s} className={i === step - 1 ? "is-last" : ""}><span>&gt;</span>{s}</li>)}
            </ul>
          </div>
        ) : result ? (
          <div className="result">
            <div className="result__top">
              <ThreatCore value={result.score} tone={verdictTone(result.verdict)} size={250}>
                <div className="core-score">{score}</div>
                <div className={`core-verdict core-verdict--${verdictTone(result.verdict)} is-on glitch-once`}>{result.verdict.toLowerCase()}</div>
              </ThreatCore>
              <div className="result__sum">
                <h3 className={`result__word result__word--${verdictTone(result.verdict)}`}>
                  {result.verdict === "SAFE" ? "No threat found" : result.verdict === "SUSPICIOUS" ? "Treat with caution" : "Do not trust this"}
                </h3>
                <p className="muted">Confidence {Math.round(result.confidence * 100)}%{result.model_version ? ` · model ${result.model_version}` : ""}</p>
                {result.degraded ? <p className="warn-note">One or more detection layers were unavailable, so this result may be less accurate.</p> : null}
              </div>
            </div>
            <h4>Why</h4>
            {result.reasons.length ? <ul className="reasons">{result.reasons.map((r, i) => <li key={i} style={{ animationDelay: `${i * 90}ms` }}>{r}</li>)}</ul> : <p className="muted">No risky signals were detected.</p>}
            <h4>Detection layers</h4>
            <div className="meters">{Object.entries(result.layer_scores).map(([k, v]) => <Meter key={k} label={k} value={v} />)}</div>
            {result.defanged_urls.length ? (<><h4>Links found (defanged)</h4><ul className="urls">{result.defanged_urls.map((u, i) => <li key={i}>{u}</li>)}</ul></>) : null}
          </div>
        ) : (
          <div className="empty empty--tall">
            <ThreatCore value={0} tone="idle" size={220}><div className="core-sub">awaiting input</div></ThreatCore>
            <p>Results appear here.</p>
          </div>
        )}
      </section>
    </div>
  );
}
