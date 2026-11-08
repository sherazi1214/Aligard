"use client";
import type { ReactNode } from "react";
import { SessionProvider } from "@/lib/session";
import { Wordmark } from "@/components/Logo";

export default function BillingLayout({ children }: { children: ReactNode }) {
  return (
    <SessionProvider>
      <div className="billing">
        <header className="billing__top"><Wordmark /></header>
        {children}
      </div>
    </SessionProvider>
  );
}
