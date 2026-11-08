"use client";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { Button } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";
import { useToast } from "@/lib/toast";
import type { PlansData } from "@/lib/types";

function Inner() {
  const router = useRouter();
  const params = useSearchParams();
  const toast = useToast();
  const { me, logout } = useSession();
  const [data, setData] = useState<PlansData | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => { api<PlansData>("/api/billing/plans").then(setData).catch(() => toast("err", "Could not load plans")); }, [toast]);
  useEffect(() => { if (params.get("checkout") === "cancelled") toast("err", "Payment cancelled. You were not charged."); }, [params, toast]);

  async function choose(id: string, paid: boolean) {
    setBusy(id);
    try {
      if (!paid) {
        await api("/api/billing/free", { method: "POST" });
        router.push("/dashboard");
      } else {
        const r = await api<{ url: string }>("/api/billing/checkout", { method: "POST", body: { plan: id } });
        window.location.href = r.url; // Stripe's secure page (card is entered there, never on our site)
        return;
      }
    } catch (e) { toast("err", e instanceof ApiError ? e.message : "Something went wrong"); }
    setBusy(null);
  }
  async function manage() {
    setBusy("manage");
    try { const r = await api<{ url: string }>("/api/billing/portal", { method: "POST" }); window.location.href = r.url; return; }
    catch (e) { toast("err", e instanceof ApiError ? e.message : "Could not open billing"); }
    setBusy(null);
  }

  const cur = data?.current;
  return (
    <main className="plans">
      <h1 className="page-title">Choose your plan</h1>
      <p className="muted">Signed in as {me.email}. Start free with no card, or upgrade for more protection.</p>
      {data?.provider === "mock" ? <p className="form__err">Test mode: no real payment is taken.</p> : null}
      <div className="plans__grid">
        {(data?.plans ?? []).map((p) => {
          const isCur = cur?.active && cur.plan === p.id;
          return (
            <section key={p.id} className={`plan glass ${p.id === "pro" ? "plan--hot" : ""}`}>
              {p.id === "pro" ? <span className="plan__tag">Most popular</span> : null}
              <h2>{p.name}</h2>
              <p className="plan__price">{p.price}{p.interval ? <small> / {p.interval}</small> : null}</p>
              <p className="muted">{p.tagline}</p>
              <ul className="plan__list">{p.features.map((f) => <li key={f}>{f}</li>)}</ul>
              <p className="plan__card">{p.card_required ? "Card required (secure checkout by Stripe)" : "No card needed"}</p>
              {isCur ? (
                cur?.can_manage ? <Button variant="ghost" loading={busy === "manage"} onClick={manage}>Manage billing</Button>
                  : <Button variant="ghost" onClick={() => router.push("/dashboard")}>Current plan - open app</Button>
              ) : (
                <Button loading={busy === p.id} disabled={!!busy} onClick={() => void choose(p.id, p.paid)}>
                  {p.paid ? `Pay and start ${p.name}` : "Start free"}
                </Button>
              )}
            </section>
          );
        })}
      </div>
      <p className="muted" style={{ textAlign: "center", marginTop: 24 }}>
        <button className="linkish" onClick={() => void logout()}>Log out</button>
      </p>
    </main>
  );
}
export default function PlansPage() { return <Suspense><Inner /></Suspense>; }
