"use client";
import { useEffect, useRef, useState, type InputHTMLAttributes, type ReactNode } from "react";
import type { Verdict } from "@/lib/types";

export function VerdictBadge({ v }: { v: Verdict }) {
  const cls = v === "SAFE" ? "v-safe" : v === "SUSPICIOUS" ? "v-warn" : "v-danger";
  return <span className={`vbadge ${cls}`}><i />{v === "SAFE" ? "Safe" : v === "SUSPICIOUS" ? "Suspicious" : "Phishing"}</span>;
}

export function Spinner() { return <span className="spinner" aria-hidden="true" />; }

export function Button({
  children, loading, variant = "primary", ...rest
}: { loading?: boolean; variant?: "primary" | "ghost" | "danger" } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button {...rest} disabled={rest.disabled || loading} className={`btn btn--${variant} ${rest.className ?? ""}`}>
      {loading ? <Spinner /> : null}
      <span>{children}</span>
    </button>
  );
}

export function Field({ label, hint, ...rest }: { label: string; hint?: string } & InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="field">
      <span className="field__label">{label}</span>
      <input {...rest} className="field__input" />
      {hint ? <span className="field__hint">{hint}</span> : null}
    </label>
  );
}

export function PasswordField({ label, hint, ...rest }: { label: string; hint?: string } & InputHTMLAttributes<HTMLInputElement>) {
  const [show, setShow] = useState(false);
  return (
    <label className="field">
      <span className="field__label">{label}</span>
      <span className="field__wrap">
        <input {...rest} type={show ? "text" : "password"} className="field__input" />
        <button type="button" className="field__eye" onClick={() => setShow((s) => !s)} aria-label={show ? "Hide password" : "Show password"}>
          {show ? "hide" : "show"}
        </button>
      </span>
      {hint ? <span className="field__hint">{hint}</span> : null}
    </label>
  );
}

export function Toggle({ checked, onChange, label, sub, disabled }: {
  checked: boolean; onChange: (v: boolean) => void; label: string; sub?: string; disabled?: boolean;
}) {
  return (
    <div className="toggle-row">
      <div>
        <div className="toggle-row__label">{label}</div>
        {sub ? <div className="toggle-row__sub">{sub}</div> : null}
      </div>
      <button
        type="button" role="switch" aria-checked={checked} aria-label={label} disabled={disabled}
        className={`switch ${checked ? "switch--on" : ""}`} onClick={() => onChange(!checked)}
      ><span /></button>
    </div>
  );
}

export function Drawer({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: string; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    ref.current?.focus();
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="drawer-wrap" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <aside className="drawer glass" role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} ref={ref}>
        <header className="drawer__head">
          <h2>{title}</h2>
          <button className="icon-btn" onClick={onClose} aria-label="Close">esc</button>
        </header>
        <div className="drawer__body">{children}</div>
      </aside>
    </div>
  );
}

/** Chhota bar: value 0-100 */
export function Meter({ label, value }: { label: string; value: number | null }) {
  const off = value === null || value === undefined;
  const v = off ? 0 : Math.max(0, Math.min(100, value as number));
  const tone = v >= 70 ? "danger" : v >= 40 ? "warn" : "safe";
  return (
    <div className="meter">
      <div className="meter__top"><span>{label}</span><span>{off ? "offline" : Math.round(v)}</span></div>
      <div className="meter__track"><span className={`meter__fill meter__fill--${tone}`} style={{ width: off ? "0%" : `${v}%` }} /></div>
    </div>
  );
}
