"use client";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { Button } from "@/components/ui";
import { api, ApiError } from "@/lib/api";

function Inner() {
  const router = useRouter();
  const token = useSearchParams().get("token") ?? "";
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  async function pay() {
    setBusy(true); setErr("");
    try { await api("/api/billing/mock/complete", { method: "POST", body: { token } }); router.replace("/billing/success"); }
    catch (e) { setErr(e instanceof ApiError ? e.message : "Failed"); setBusy(false); }
  }
  return (
    <main className="plans" style={{ textAlign: "center", maxWidth: 520 }}>
      <h1 className="page-title">Test payment</h1>
      <p className="muted">Development mode only. In production this step is Stripe&apos;s secure card page. No card is collected here.</p>
      {err ? <p className="form__err">{err}</p> : null}
      <Button loading={busy} onClick={pay}>Simulate successful payment</Button>
    </main>
  );
}
export default function MockPage() { return <Suspense><Inner /></Suspense>; }
