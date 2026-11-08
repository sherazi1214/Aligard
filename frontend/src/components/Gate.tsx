"use client";
import { useRouter, useSearchParams, usePathname } from "next/navigation";
import { Suspense, useEffect, useState, type ReactNode } from "react";
import { Button, Field } from "./ui";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";
import { useToast } from "@/lib/toast";

const MSG: Record<string, string> = {
  denied: "Permission was denied, Gmail was not connected.",
  scope: "The required Gmail permission was not granted.",
  limit: "Your plan's Gmail inbox limit is reached. Upgrade for more inboxes.",
  mismatch: "You signed in to a different Google account than the Gmail address you typed. Try again with the same account.",
  plan: "Choose a plan first.", session: "Session expired. Log in again.", error: "Could not connect Gmail. Please try again.",
};

function GmailGate() {
  const toast = useToast();
  const params = useSearchParams();
  const [busy, setBusy] = useState(false);
  const [email, setEmail] = useState("");
  const g = params.get("gmail");
  useEffect(() => { if (g && g !== "connected") toast("err", MSG[g] ?? MSG.error); }, [g, toast]);
  async function connect() {
    setBusy(true);
    try { const r = await api<{ auth_url: string }>("/api/gmail/connect", { method: "POST", body: { email: email.trim() || null } }); window.location.href = r.auth_url; }
    catch (e) { toast("err", e instanceof ApiError ? e.message : "Connect failed"); setBusy(false); }
  }
  return (
    <section className="glass" style={{ maxWidth: 560, margin: "40px auto", padding: 32, display: "grid", gap: 14, justifyItems: "center", textAlign: "center" }}>
      <h1 className="page-title" style={{ marginBottom: 0 }}>Connect your Gmail to start</h1>
      <p className="muted">AliGuard works only after a Gmail inbox is connected. Google will show your signed-in accounts; pick the one to protect and allow access. You can disconnect any time.</p>
      <form onSubmit={(ev) => { ev.preventDefault(); void connect(); }} style={{ display: "grid", gap: 12, width: "100%", textAlign: "left" }}>
        <Field label="Your Gmail address" type="email" name="gmail" autoComplete="email" placeholder="name@gmail.com"
          value={email} onChange={(ev) => setEmail(ev.target.value)} hint="Google will open with this account selected. Click Allow to finish." />
        <Button type="submit" loading={busy}>Connect Gmail</Button>
      </form>
    </section>
  );
}

/** Plan nahi => /plans. Plan hai par Gmail nahi => dashboard/scanner ki jagah Connect Gmail screen. */
export default function Gate({ children }: { children: ReactNode }) {
  const { me } = useSession();
  const router = useRouter();
  const path = usePathname();
  useEffect(() => { if (!me.billing.active) router.replace("/plans"); }, [me.billing.active, router]);
  if (!me.billing.active) return null;
  const needsGmail = path.startsWith("/dashboard") || path.startsWith("/scanner");
  if (needsGmail && !me.gmail_connected) return <Suspense><GmailGate /></Suspense>;
  return <>{children}</>;
}
