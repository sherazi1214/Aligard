"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { Wordmark } from "@/components/Logo";
import ThreatCore from "@/components/ThreatCore";
import Reveal from "@/components/Reveal";
import { prefersReducedMotion, useCountUp } from "@/lib/hooks";
import type { Tone, Verdict } from "@/lib/types";

interface Sample {
  from: string; subject: string; verdict: Verdict; score: number;
  signals: { text: string; pts: number }[];
}
const SAMPLES: Sample[] = [
  {
    from: "PayPaI Support <security@paypa1-verify.example>",
    subject: "Urgent: account will be suspended in 24 hours",
    verdict: "PHISHING", score: 97,
    signals: [
      { text: "lookalike domain: paypa1-verify.example", pts: 38 },
      { text: "urgency pressure: \"within 24 hours\"", pts: 22 },
      { text: "link text does not match destination", pts: 19 },
      { text: "classifier: credential-harvest pattern", pts: 18 },
    ],
  },
  {
    from: "Daraz Deals <promo@daraz-offers.example>",
    subject: "Your parcel could not be delivered, pay Rs. 49",
    verdict: "SUSPICIOUS", score: 61,
    signals: [
      { text: "unexpected payment request", pts: 24 },
      { text: "sender domain registered 6 days ago", pts: 22 },
      { text: "classifier: mild delivery-scam similarity", pts: 15 },
    ],
  },
  {
    from: "GitHub <noreply@github.com>",
    subject: "Your weekly digest is ready",
    verdict: "SAFE", score: 4,
    signals: [
      { text: "sender authenticated (SPF, DKIM, DMARC)", pts: 0 },
      { text: "no tracking redirects or lookalike links", pts: 0 },
      { text: "classifier: matches known-good pattern", pts: 4 },
    ],
  },
];
const tone = (v: Verdict): Tone => (v === "SAFE" ? "safe" : v === "SUSPICIOUS" ? "warn" : "danger");

function LiveDissection() {
  const [i, setI] = useState(0);
  const [typed, setTyped] = useState(0);
  const [shown, setShown] = useState(0);
  const [final, setFinal] = useState(false);
  const s = SAMPLES[i];
  const reduce = typeof window !== "undefined" && prefersReducedMotion();

  useEffect(() => {
    if (reduce) { setTyped(s.subject.length); setShown(s.signals.length); setFinal(true); return; }
    setTyped(0); setShown(0); setFinal(false);
    const timers: ReturnType<typeof setTimeout>[] = [];
    let t = 500;
    const typeStep = 24;
    for (let k = 1; k <= s.subject.length; k++) timers.push(setTimeout(() => setTyped(k), t + k * typeStep));
    t += s.subject.length * typeStep + 450;
    s.signals.forEach((_, k) => timers.push(setTimeout(() => setShown(k + 1), t + k * 620)));
    t += s.signals.length * 620 + 350;
    timers.push(setTimeout(() => setFinal(true), t));
    timers.push(setTimeout(() => setI((x) => (x + 1) % SAMPLES.length), t + 3600));
    return () => timers.forEach(clearTimeout);
  }, [i, s, reduce]);

  const score = useCountUp(final ? s.score : 0, 1100);
  const total = s.signals.slice(0, shown).reduce((a, b) => a + b.pts, 0);

  return (
    <div className="dissect glass" aria-label="Live demonstration of an email being analysed">
      <div className="dissect__bar"><i /><i /><i /><span>incoming / analysing</span></div>
      <div className="dissect__grid">
        <div className="dissect__mail">
          <div className="dissect__from">{s.from}</div>
          <div className="dissect__subj">{s.subject.slice(0, typed)}<b className="caret" /></div>
          <ul className="dissect__sigs">
            {s.signals.slice(0, shown).map((g) => (
              <li key={g.text} className="sig-in"><span>{g.text}</span><em>{g.pts > 0 ? `+${g.pts}` : "ok"}</em></li>
            ))}
          </ul>
          <div className="dissect__sum">signal weight <b>{total}</b></div>
        </div>
        <div className="dissect__core">
          <ThreatCore value={final ? s.score : 0} tone={final ? tone(s.verdict) : "idle"} scanning={!final} size={190}>
            <div className="core-score">{score}</div>
            <div className={`core-verdict core-verdict--${tone(s.verdict)} ${final ? "is-on" : ""}`}>{final ? s.verdict.toLowerCase() : "scanning"}</div>
          </ThreatCore>
        </div>
      </div>
    </div>
  );
}


function HeroShield() {
  return (
    <div className="shield" aria-hidden="true">
      <svg viewBox="0 0 520 520" className="shield__svg">
        <defs><linearGradient id="hv" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#a98bff" /><stop offset="1" stopColor="#ff3df0" /></linearGradient></defs>
        <circle className="shield__r1" cx="260" cy="260" r="240" fill="none" stroke="#8b5cff" strokeOpacity=".4" strokeDasharray="3 9" />
        <circle className="shield__r2" cx="260" cy="260" r="190" fill="none" stroke="#a98bff" strokeOpacity=".5" strokeDasharray="60 22" />
        <circle cx="260" cy="260" r="140" fill="rgba(139,92,255,.12)" stroke="#a98bff" strokeOpacity=".7" />
        <path d="M260 150 350 184v66c0 56-38 92-90 112-52-20-90-56-90-112v-66z" fill="rgba(20,8,50,.92)" stroke="url(#hv)" strokeWidth="4" />
        <path d="m222 262 28 28 52-58" fill="none" stroke="url(#hv)" strokeWidth="9" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <span className="chip chip--a">lookalike domain +38</span>
      <span className="chip chip--b">urgency wording +22</span>
      <span className="chip chip--c">verdict: quarantined</span>
    </div>
  );
}

const LAYERS = [
  { name: "Heuristics", text: "Lookalike domains, urgency wording, mismatched links, risky attachments." },
  { name: "Neural classifier", text: "Trained model scores the message the way phishing actually reads." },
  { name: "Reputation", text: "Every link is checked against domain age and threat feeds." },
  { name: "Deep analysis", text: "Optional LLM pass for the cases that sit on the line." },
];

const TICKER = [
  "lookalike domain: paypa1-verify.example", "urgency pressure: account suspended in 24h", "link text does not match destination",
  "credential-harvest login form detected", "fake delivery fee: pay Rs. 49 to release parcel", "sender domain registered 6 days ago",
  "invoice.pdf.exe double-extension attachment", "CEO-fraud style wire transfer request", "QR code pointing to a fresh domain",
  "reply-to differs from sender address", "SPF / DKIM / DMARC authentication failed", "shortened link hiding a redirect chain",
];

const KPIS = [
  { n: "4", l: "detection layers on every email" },
  { n: "1-click", l: "restore of anything quarantined" },
  { n: "0", l: "emails ever permanently deleted" },
  { n: "24/7", l: "background inbox monitoring" },
];

const ICONS: Record<string, string> = {
  shield: "M12 3 4 6v5c0 5 3.4 8.4 8 10 4.6-1.6 8-5 8-10V6l-8-3Zm-1 12-3-3 1.4-1.4L11 12.2l4.1-4.1L16.5 9.5 11 15Z",
  eye: "M12 5C6.5 5 2.7 9 1.5 12c1.2 3 5 7 10.5 7s9.3-4 10.5-7C21.3 9 17.5 5 12 5Zm0 11a4 4 0 1 1 0-8 4 4 0 0 1 0 8Zm0-2a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z",
  brain: "M9 3a3 3 0 0 0-3 3v.2A3.5 3.5 0 0 0 4 9.5c0 1 .4 1.9 1.1 2.5A3.5 3.5 0 0 0 6 18a3 3 0 0 0 6 0V6a3 3 0 0 0-3-3Zm6 0a3 3 0 0 0-3 3v12a3 3 0 0 0 6 0 3.5 3.5 0 0 0 .9-6c.7-.6 1.1-1.5 1.1-2.5A3.5 3.5 0 0 0 18 6.2V6a3 3 0 0 0-3-3Z",
  link: "M10.6 13.4a4 4 0 0 1 0-5.7l3-3a4 4 0 0 1 5.7 5.7l-1.5 1.5-1.4-1.4 1.5-1.5a2 2 0 1 0-2.9-2.8l-3 3a2 2 0 0 0 0 2.8l-1.4 1.4Zm2.8-2.8a4 4 0 0 1 0 5.7l-3 3a4 4 0 0 1-5.7-5.7l1.5-1.5 1.4 1.4-1.5 1.5a2 2 0 1 0 2.9 2.8l3-3a2 2 0 0 0 0-2.8l1.4-1.4Z",
  bell: "M12 22a2.5 2.5 0 0 0 2.5-2.5h-5A2.5 2.5 0 0 0 12 22Zm7-6V11a7 7 0 0 0-5-6.7V3a2 2 0 1 0-4 0v1.3A7 7 0 0 0 5 11v5l-2 2v1h18v-1l-2-2Z",
  lock: "M17 9V7a5 5 0 0 0-10 0v2H5v12h14V9h-2Zm-8-2a3 3 0 0 1 6 0v2H9V7Zm4 10.7V19h-2v-1.3a2 2 0 1 1 2 0Z",
};
function Icon({ name }: { name: keyof typeof ICONS }) {
  return <svg viewBox="0 0 24 24" width="26" height="26" aria-hidden="true" className="ficon"><path d={ICONS[name]} fill="currentColor" /></svg>;
}

const FEATURES: { icon: keyof typeof ICONS; tone: "g" | "r"; title: string; text: string }[] = [
  { icon: "eye", tone: "g", title: "Reads like an analyst", text: "Wording, urgency, tone, sender behaviour and structure are examined together, not as one blunt keyword filter." },
  { icon: "brain", tone: "r", title: "Trained neural classifier", text: "A model trained on phishing families scores every message, so new phrasing of old scams is still recognised." },
  { icon: "link", tone: "g", title: "Link & domain forensics", text: "Redirect chains are unwrapped, lookalike domains flagged, and domain age checked before you ever click." },
  { icon: "shield", tone: "r", title: "Quarantine, never delete", text: "Dangerous mail is moved out of your inbox instantly and can be restored in one click if we were wrong." },
  { icon: "bell", tone: "g", title: "Instant alerts", text: "Get an email or Telegram message the moment a high-risk message is caught, with the reason attached." },
  { icon: "lock", tone: "r", title: "You hold the switch", text: "Revocable Gmail access, 2FA, tunable thresholds, and a delete-everything button. Your data stays yours." },
];

const THREATS = [
  "Credential harvesting", "Brand impersonation", "CEO / invoice fraud", "Fake delivery fees", "Lookalike domains", "Malicious attachments",
  "QR-code phishing", "Redirect chains", "Reply-to spoofing", "Account-suspension scams", "Prize & lottery bait", "Payment-link traps",
];

const TERM = [
  ["info", "worker online, polling inbox"],
  ["info", "fetched message  id=7f3a...c19  from=security@paypa1-verify.example"],
  ["warn", "heuristics: lookalike domain, urgency wording (+60)"],
  ["warn", "reputation: domain registered 6 days ago (+22)"],
  ["bad", "classifier: credential-harvest similarity 0.97"],
  ["bad", "verdict=PHISHING  score=97  -> quarantine"],
  ["ok", "message moved out of inbox, alert sent"],
  ["info", "fetched message  id=2be1...a07  from=noreply@github.com"],
  ["ok", "sender authenticated (SPF, DKIM, DMARC)"],
  ["ok", "verdict=SAFE  score=4  -> no action"],
];

function LiveTerminal() {
  const [n, setN] = useState(1);
  useEffect(() => {
    if (prefersReducedMotion()) { setN(TERM.length); return; }
    const id = setInterval(() => setN((x) => (x >= TERM.length + 3 ? 1 : x + 1)), 1100);
    return () => clearInterval(id);
  }, []);
  const lines = TERM.slice(0, Math.min(n, TERM.length));
  return (
    <div className="term glass" aria-label="Sample worker activity log">
      <div className="term__bar"><i /><i /><i /><span>aliguard-worker  ~  sample activity</span><em>demo</em></div>
      <ul className="term__body">
        {lines.map(([k, t], i) => (
          <li key={`${i}-${t}`} className={`t-${k}`}><b>{k === "bad" ? "[ x ]" : k === "warn" ? "[ ! ]" : k === "ok" ? "[ + ]" : "[ i ]"}</b>{t}</li>
        ))}
        <li className="t-cursor"><b>&gt;</b><span className="caret" /></li>
      </ul>
    </div>
  );
}

const FAQ = [
  { q: "Will AliGuard ever delete my emails?", a: "No. Flagged mail is quarantined, which means it is moved out of your inbox, never destroyed. Every quarantined message can be restored from the dashboard in one click." },
  { q: "How does it decide something is phishing?", a: "Four layers work together: heuristics, a trained classifier, link and domain reputation, and an optional deep-analysis pass. You always see the reasons and the score of each layer in the scan report." },
  { q: "What access does it need to my Gmail?", a: "It connects through Google's own permission screen, and you can revoke access at any time from the dashboard or from your Google account. Disconnecting stops scanning immediately." },
  { q: "Can I tune how strict it is?", a: "Yes. Set your own suspicious and phishing thresholds, and whitelist senders or whole domains you trust, all from Settings." },
  { q: "What if it flags a legitimate email?", a: "Restore it with one click and mark it as not phishing. That feedback is recorded so the same sender is treated more carefully next time." },
];

export default function Landing() {
  const loop = [...TICKER, ...TICKER];
  return (
    <div className="landing">
      <div className="ticker" aria-hidden="true">
        <span className="ticker__tag"><i />patterns we catch</span>
        <div className="ticker__viewport"><div className="ticker__track">{loop.map((t, i) => <span key={i}><b>//</b> {t}</span>)}</div></div>
      </div>

      <header className="land-nav">
        <Wordmark />
        <nav>
          <a href="#features" className="land-nav__link">Features</a>
          <a href="#how" className="land-nav__link">How it works</a>
          <a href="#faq" className="land-nav__link">FAQ</a>
          <Link href="/login" className="btn btn--ghost btn--sm"><span>Log in</span></Link>
          <Link href="/signup" className="btn btn--primary btn--sm"><span>Get protected</span></Link>
        </nav>
      </header>

      <section className="hero">
        <div className="hero__copy">
          <p className="status-pill"><i />engine online <em>4 detection layers armed</em></p>
          <h1 className="hero__title">Your inbox, under <span className="grad">armed watch.</span></h1>
          <p className="hero__sub">
            AliGuard reads every incoming email through four detection layers, quarantines phishing before you ever see it,
            and tells you exactly why it made the call. No guesswork, no black box, just evidence.
          </p>
          <div className="hero__cta">
            <Link href="/signup" className="btn btn--primary btn--lg"><span>Create free account</span></Link>
            <Link href="/login" className="btn btn--ghost btn--lg"><span>I already have one</span></Link>
          </div>
          <p className="hero__note">Connects to Gmail with revocable access. Quarantine is always one click from undone.</p>
        </div>
        <HeroShield />
      </section>

      <Reveal>
        <section className="kpis" aria-label="Key facts">
          {KPIS.map((k) => (<div key={k.l} className="kpi glass"><div className="kpi__n">{k.n}</div><div className="kpi__l">{k.l}</div></div>))}
        </section>
      </Reveal>

      <Reveal>
        <section id="how" className="pipeline glass" aria-label="How detection works">
          <div className="pipeline__in"><span>Email arrives</span></div>
          <div className="pipeline__rail" aria-hidden="true"><i /></div>
          <ul className="pipeline__layers">
            {LAYERS.map((l) => (
              <li key={l.name}><h3>{l.name}</h3><p>{l.text}</p></li>
            ))}
          </ul>
          <div className="pipeline__rail" aria-hidden="true"><i /></div>
          <div className="pipeline__out"><span>One verdict, with reasons</span></div>
        </section>
      </Reveal>

      <Reveal>
        <section className="sec sec--demo">
          <div className="sec__head"><h2>Watch an email get taken apart</h2><p>This is a live sample: every signal that fires adds to the score, and the verdict arrives with its reasons.</p></div>
          <div className="demo-wrap"><LiveDissection /></div>
        </section>
      </Reveal>

      <Reveal>
        <section id="features" className="sec">
          <div className="sec__head">
            <h2>Built like a security operations center. Simple like an app.</h2>
            <p>Everything a security team would set up by hand, running quietly behind your inbox and explained in plain language.</p>
          </div>
          <div className="features">
            {FEATURES.map((f) => (
              <article key={f.title} className={`feature glass feature--${f.tone}`}>
                <div className="feature__icon"><Icon name={f.icon} /></div>
                <h3>{f.title}</h3>
                <p>{f.text}</p>
              </article>
            ))}
          </div>
        </section>
      </Reveal>

      <Reveal>
        <section className="sec sec--split">
          <div>
            <div className="sec__head sec__head--left">
              <h2>See the decision, not just the result.</h2>
              <p>
                Every scan produces a readable report: the final verdict, a score out of 100, the exact signals that fired,
                the score from each layer and every link found, safely defanged. When AliGuard quarantines a message you
                know why, and you can undo it in a click.
              </p>
            </div>
            <ul className="threats" aria-label="Threat types covered">
              {THREATS.map((t, i) => (<li key={t} style={{ animationDelay: `${(i % 6) * 0.35}s` }}>{t}</li>))}
            </ul>
          </div>
          <LiveTerminal />
        </section>
      </Reveal>

      <Reveal>
        <section className="sec">
          <div className="sec__head">
            <h2>Protected in three steps</h2>
            <p>No agents to install and no rules to write.</p>
          </div>
          <ol className="steps">
            <li className="glass"><span className="steps__n">1</span><h3>Create your account</h3><p>Sign up, verify your email and secure the login with two-factor authentication if you like.</p></li>
            <li className="glass"><span className="steps__n">2</span><h3>Connect Gmail</h3><p>Approve access on Google's own screen. Pick the inbox to protect. You can revoke it any time.</p></li>
            <li className="glass"><span className="steps__n">3</span><h3>Relax, it is watching</h3><p>New mail is scanned in the background. Threats are quarantined and you are alerted with the reasons.</p></li>
          </ol>
        </section>
      </Reveal>

      <Reveal>
        <section id="faq" className="sec sec--narrow">
          <div className="sec__head"><h2>Questions, answered straight</h2></div>
          <div className="faq">
            {FAQ.map((f) => (
              <details key={f.q} className="faq__item glass">
                <summary>{f.q}</summary>
                <p>{f.a}</p>
              </details>
            ))}
          </div>
        </section>
      </Reveal>

      <Reveal>
        <section className="cta glass">
          <div className="cta__copy">
            <h2>Phishing only needs one click. Don't give it that chance.</h2>
            <p>Put a four-layer shield between the attackers and your inbox. It takes about two minutes to set up.</p>
          </div>
          <div className="cta__btns">
            <Link href="/signup" className="btn btn--primary btn--lg"><span>Activate protection</span></Link>
            <Link href="/login" className="btn btn--ghost btn--lg"><span>Log in</span></Link>
          </div>
        </section>
      </Reveal>

      <footer className="land-foot">
        <Wordmark />
        <p className="land-foot__tag">AI-powered phishing defence for your inbox.</p>
        <nav><Link href="/privacy">Privacy</Link><Link href="/terms">Terms</Link><Link href="/login">Log in</Link></nav>
      </footer>
    </div>
  );
}
