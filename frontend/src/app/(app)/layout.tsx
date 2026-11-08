"use client";
import type { ReactNode } from "react";
import AppShell from "@/components/AppShell";
import Gate from "@/components/Gate";
import { SessionProvider } from "@/lib/session";

export default function AppLayout({ children }: { children: ReactNode }) {
  return (
    <SessionProvider>
      <AppShell><Gate>{children}</Gate></AppShell>
    </SessionProvider>
  );
}
