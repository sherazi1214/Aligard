import Link from "next/link";
import type { ReactNode } from "react";
import { Wordmark } from "./Logo";

const POINTS = [
  ["Four-layer detection", "Heuristics, neural classifier, link reputation and deep analysis on every email."],
  ["Quarantine, never delete", "Anything flagged is moved out of your inbox and restorable in one click."],
  ["Explainable verdicts", "Every decision comes with the score, the signals and the reasons behind it."],
  ["Locked down by design", "Revocable Gmail access, optional 2FA and a full delete-my-data switch."],
];

export default function AuthFrame({ title, sub, children, footer }: { title: string; sub?: string; children: ReactNode; footer?: ReactNode }) {
  return (
    <div className="auth">
      <aside className="auth__side" aria-label="About AliGuard">
        <Link href="/" className="auth__brand"><Wordmark /></Link>
        <h2 className="auth__headline">Zero-trust for your inbox.</h2>
        <p className="auth__lead">Attackers only need one careless click. AliGuard watches every message so you never have to gamble on it.</p>
        <ul className="auth__points">
          {POINTS.map(([t, d]) => (<li key={t}><i /><div><strong>{t}</strong><span>{d}</span></div></li>))}
        </ul>
        <p className="auth__status"><i />secure channel active</p>
      </aside>
      <section className="auth__card glass" aria-labelledby="auth-title">
        <span className="auth__edge" aria-hidden="true" />
        <Link href="/" className="auth__brand auth__brand--mobile"><Wordmark /></Link>
        <h1 id="auth-title" className="auth__title">{title}</h1>
        {sub ? <p className="auth__sub">{sub}</p> : null}
        {children}
        {footer ? <div className="auth__foot">{footer}</div> : null}
      </section>
    </div>
  );
}
