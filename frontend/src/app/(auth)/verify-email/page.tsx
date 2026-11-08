"use client";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import AuthFrame from "@/components/AuthFrame";
import { api, ApiError } from "@/lib/api";

// FIX: verify token ek bar chalta hai. Next dev (StrictMode/Suspense) component do bar mount kar deta hai,
// to ye request 2 bar jati thi: pehli kamyab, doosri "link expire" dikhati thi. Ab har token ki ek hi request
// (module level cache) banti hai aur dono mounts ko wahi natija milta hai.
const inflight = new Map<string, Promise<{ message: string }>>();
function verifyOnce(token: string) {
  let p = inflight.get(token);
  if (!p) {
    p = api<{ message: string }>("/api/auth/verify-email", { method: "POST", body: { token } });
    inflight.set(token, p);
  }
  return p;
}

function Inner() {
  const token = useSearchParams().get("token") ?? "";
  const [state, setState] = useState<"loading" | "ok" | "err">("loading");
  const [msg, setMsg] = useState("");

  useEffect(() => {
    if (!token) { setState("err"); setMsg("Verification link adhoora hai."); return; }
    verifyOnce(token)
      .then((r) => { setState("ok"); setMsg(r.message); })
      .catch((e) => { setState("err"); setMsg(e instanceof ApiError ? e.message : "Verify nakam hua"); });
  }, [token]);

  return (
    <AuthFrame title={state === "loading" ? "Verifying" : state === "ok" ? "Identity confirmed" : "Link rejected"} footer={<Link href="/login">Go to login</Link>}>
      <div className="sent">
        <div className={`sent__ring sent__ring--${state}`} aria-hidden="true"><i /></div>
        <p role="status">{state === "loading" ? "Validating your link..." : msg}</p>
      </div>
    </AuthFrame>
  );
}

export default function VerifyEmailPage() { return <Suspense><Inner /></Suspense>; }
