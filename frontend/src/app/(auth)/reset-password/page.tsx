"use client";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useState, type FormEvent } from "react";
import AuthFrame from "@/components/AuthFrame";
import { Button, PasswordField } from "@/components/ui";
import { api, ApiError } from "@/lib/api";

function Inner() {
  const token = useSearchParams().get("token") ?? "";
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [done, setDone] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setErr("");
    if (pw !== pw2) { setErr("Dono passwords match nahi karte"); return; }
    setBusy(true);
    try {
      const r = await api<{ message: string }>("/api/auth/reset-password", { method: "POST", body: { token, password: pw } });
      setDone(r.message);
    } catch (ex) { setErr(ex instanceof ApiError ? ex.message : "Reset nakam hua"); }
    finally { setBusy(false); }
  }

  return (
    <AuthFrame title="Set a new password" sub="Minimum 12 characters." footer={<Link href="/login">Back to login</Link>}>
      {done ? <div className="sent"><div className="sent__ring" aria-hidden="true"><i /></div><p>{done}</p></div> : (
        <form onSubmit={submit} className="form" noValidate>
          <PasswordField label="New password" autoComplete="new-password" required value={pw} onChange={(e) => setPw(e.target.value)} />
          <PasswordField label="Confirm new password" autoComplete="new-password" required value={pw2} onChange={(e) => setPw2(e.target.value)} />
          {!token ? <p className="form__err">Reset link adhoora hai. Email wala link dobara kholein.</p> : null}
          {err ? <p className="form__err" role="alert">{err}</p> : null}
          <Button type="submit" loading={busy} disabled={!token}>Update password</Button>
        </form>
      )}
    </AuthFrame>
  );
}

export default function ResetPage() { return <Suspense><Inner /></Suspense>; }
