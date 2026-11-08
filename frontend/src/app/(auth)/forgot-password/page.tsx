"use client";
import Link from "next/link";
import { useState, type FormEvent } from "react";
import AuthFrame from "@/components/AuthFrame";
import { Button, Field } from "@/components/ui";
import { api, ApiError } from "@/lib/api";

export default function ForgotPage() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [done, setDone] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setErr("");
    try {
      const r = await api<{ message: string }>("/api/auth/forgot-password", { method: "POST", body: { email } });
      setDone(r.message);
    } catch (ex) { setErr(ex instanceof ApiError ? ex.message : "Request nakam"); }
    finally { setBusy(false); }
  }

  return (
    <AuthFrame title="Recover access" sub="We will send a one-time reset link." footer={<Link href="/login">Back to login</Link>}>
      {done ? <div className="sent"><div className="sent__ring" aria-hidden="true"><i /></div><p>{done}</p></div> : (
        <form onSubmit={submit} className="form" noValidate>
          <Field label="Email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
          {err ? <p className="form__err" role="alert">{err}</p> : null}
          <Button type="submit" loading={busy}>Send reset link</Button>
        </form>
      )}
    </AuthFrame>
  );
}
