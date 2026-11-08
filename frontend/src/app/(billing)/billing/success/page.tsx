"use client";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Billing } from "@/lib/types";

function Inner() {
  const router = useRouter();
  const sid = useSearchParams().get("session_id");
  const [state, setState] = useState<"wait" | "ok" | "fail">("wait");

  useEffect(() => {
    let stop = false;
    (async () => {
      for (let i = 0; i < 12 && !stop; i++) {
        try {
          // Server asks Stripe itself whether this session was paid; the URL alone grants nothing.
          const r = sid ? await api<{ current: Billing }>("/api/billing/sync", { method: "POST", body: { session_id: sid } })
                        : { current: (await api<{ current: Billing }>("/api/billing/plans")).current };
          if (r.current.active) { setState("ok"); setTimeout(() => router.replace("/dashboard"), 1200); return; }
        } catch { /* retry */ }
        await new Promise((r) => setTimeout(r, 2000));
      }
      if (!stop) setState("fail");
    })();
    return () => { stop = true; };
  }, [sid, router]);

  return (
    <main className="plans" style={{ textAlign: "center" }}>
      {state === "wait" ? <><h1 className="page-title">Confirming your payment...</h1><p className="muted">Please do not close this page.</p></> : null}
      {state === "ok" ? <><h1 className="page-title">Payment successful</h1><p className="muted">Opening your dashboard...</p></> : null}
      {state === "fail" ? <><h1 className="page-title">Payment not confirmed yet</h1>
        <p className="muted">If you were charged, your plan activates automatically within a few minutes.</p>
        <button className="btn btn--primary" onClick={() => router.replace("/plans")}><span>Back to plans</span></button></> : null}
    </main>
  );
}
export default function SuccessPage() { return <Suspense><Inner /></Suspense>; }
