"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Wordmark } from "./Logo";
import { useSession } from "@/lib/session";
import type { ReactNode } from "react";

const NAV = [
  { href: "/dashboard", label: "Command" },
  { href: "/scanner", label: "Scanner" },
  { href: "/settings", label: "Settings" },
];

export default function AppShell({ children }: { children: ReactNode }) {
  const path = usePathname();
  const { me, logout } = useSession();
  return (
    <div className="shell">
      <header className="topbar glass">
        <Link href="/dashboard" className="topbar__brand"><Wordmark /></Link>
        <nav className="topbar__nav" aria-label="Main">
          {NAV.map((n) => (
            <Link key={n.href} href={n.href} className={path.startsWith(n.href) ? "is-active" : ""} aria-current={path.startsWith(n.href) ? "page" : undefined}>
              {n.label}
            </Link>
          ))}
        </nav>
        <div className="topbar__user">
          <span className="live-dot" title="Engine online" />
          <Link href="/plans" className="plan-chip" title="Plan and billing">{me.billing.plan ?? "no plan"}</Link>
          <span className="topbar__email">{me.email}</span>
          <button className="btn btn--ghost btn--sm" onClick={() => void logout()}><span>Log out</span></button>
        </div>
      </header>
      <div className="statusbar" aria-hidden="true">
        <span><i />engine online</span>
        <span>4 detection layers armed</span>
        <span>session encrypted</span>
        <span className="statusbar__r"><i />quarantine ready</span>
      </div>
      <main className="shell__main">{children}</main>
    </div>
  );
}
