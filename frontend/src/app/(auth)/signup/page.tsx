"use client";
import Link from "next/link";
import { useState, type FormEvent } from "react";
import AuthFrame from "@/components/AuthFrame";
import { Button, Field, PasswordField } from "@/components/ui";
import { api, ApiError } from "@/lib/api";

export default function SignupPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [done, setDone] = useState("");

  const lenOk = password.length >= 12;
  async function submit(e: FormEvent) {
    e.preventDefault();
    setErr("");
    if (password !== confirm) { setErr("Dono passwords match nahi karte"); return; }
    setBusy(true);
    try {
      const r = await api<{ message: string }>("/api/auth/signup", { method: "POST", body: { email, password } });
      setDone(r.message);
    } catch (ex) { setErr(ex instanceof ApiError ? ex.message : "Signup nakam hua"); }
    finally { setBusy(false); }
  }

  if (done) {
    return (
      <AuthFrame title="Check your inbox" footer={<Link href="/login">Go to login</Link>}>
        <div className="sent">
          <div className="sent__ring" aria-hidden="true"><i /></div>
          <p>{done}</p>
        </div>
      </AuthFrame>
    );
  }

  return (
    <AuthFrame title="Create your shield" sub="Verification link will be sent to your email." footer={<>Already enrolled? <Link href="/login">Log in</Link></>}>
      <form onSubmit={submit} className="form" noValidate>
        <Field label="Email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        <PasswordField label="Password" autoComplete="new-password" required value={password} onChange={(e) => setPassword(e.target.value)}
          hint={lenOk ? "Length ok. Breached passwords are rejected by the server." : `${Math.max(0, 12 - password.length)} more characters needed (min 12)`} />
        <PasswordField label="Confirm password" autoComplete="new-password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        {err ? <p className="form__err" role="alert">{err}</p> : null}
        <Button type="submit" loading={busy}>Create account</Button>
      </form>
    </AuthFrame>
  );
}
