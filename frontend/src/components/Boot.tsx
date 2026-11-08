"use client";
import { useEffect, useState } from "react";
import { Logo } from "./Logo";

const LINES = [
  "establishing secure channel .......... ok",
  "mounting detection layers ............ ok",
  "heuristics engine ................... armed",
  "neural classifier ................... online",
  "reputation + threat feeds ........... linked",
  "session vault ....................... sealed",
  "quarantine controller ............... ready",
];

/** Har session mein sirf ek baar: red alert flicker -> green terminal boot -> glitch-dissolve. Click/key se skip. */
export default function Boot() {
  const [show, setShow] = useState(true);
  const [leaving, setLeaving] = useState(false);
  const [step, setStep] = useState(0);

  useEffect(() => {
    let done = false;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let seen = false;
    try { seen = sessionStorage.getItem("ag_boot") === "1"; } catch { /* private mode */ }
    if (seen || reduce) { setShow(false); return; }
    try { sessionStorage.setItem("ag_boot", "1"); } catch { /* ignore */ }

    const timers: ReturnType<typeof setTimeout>[] = [];
    LINES.forEach((_, i) => timers.push(setTimeout(() => setStep(i + 1), 450 + i * 300)));
    const finish = () => {
      if (done) return;
      done = true;
      setLeaving(true);
      timers.push(setTimeout(() => setShow(false), 700));
    };
    timers.push(setTimeout(finish, 450 + LINES.length * 300 + 500));
    const skip = () => finish();
    window.addEventListener("keydown", skip);
    window.addEventListener("pointerdown", skip);
    return () => {
      timers.forEach(clearTimeout);
      window.removeEventListener("keydown", skip);
      window.removeEventListener("pointerdown", skip);
    };
  }, []);

  if (!show) return null;
  const pct = Math.round((step / LINES.length) * 100);
  return (
    <div className={`boot ${leaving ? "boot--leave" : ""}`} role="presentation" aria-hidden="true">
      <div className="boot__alert">arming AliGuard protection layers</div>
      <div className="boot__inner">
        <Logo size={64} />
        <div className="boot__title">Ali<span>Guard</span> Sentinel</div>
        <ul className="boot__lines">
          {LINES.slice(0, step).map((l) => (
            <li key={l}><span className="boot__ok">[ ok ]</span>{l}</li>
          ))}
        </ul>
        <div className="boot__bar"><span style={{ width: `${pct}%` }} /></div>
        <div className="boot__pct"><span>{pct}%</span><span className="boot__hint">press any key to skip</span></div>
      </div>
    </div>
  );
}
