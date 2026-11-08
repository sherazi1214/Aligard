"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
import AuthFrame from "@/components/AuthFrame";
import { Button, Field, PasswordField } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { useToast } from "@/lib/toast";

export default function LoginPage() {
  const router = useRouter();
  const toast = useToast();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [unverified, setUnverified] = useState(false);

  useEffect(() => {
    api("/api/auth/me").then(() => router.replace("/dashboard")).catch(() => {});
  }, [router]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setErr(""); setUnverified(false);
    try {
      const r = await api<{ status: string }>("/api/auth/login", { method: "POST", body: { email, password } });
      router.push(r.status === "2fa_required" ? "/login/2fa" : "/dashboard");
    } catch (ex) {
      const msg = ex instanceof ApiError ? ex.message : "Login nakam hua";
      setErr(msg);
      if (ex instanceof ApiError && ex.status === 403) setUnverified(true);
    } finally { setBusy(false); }
  }

  async function resend() {
    try {
      await api("/api/auth/resend-verification", { method: "POST", body: { email } });
      toast("ok", "Verification email dobara bhej di gayi (agar account maujood hai).");
    } catch (ex) { toast("err", ex instanceof ApiError ? ex.message : "Resend nakam"); }
  }

  return (
    <AuthFrame
      title="Access terminal"
      sub="Authenticate to enter your command center."
      footer={<>New here? <Link href="/signup">Create an account</Link></>}
    >
      <form onSubmit={submit} className="form" noValidate>
        <Field label="Email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        <PasswordField label="Password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
        {err ? <p className="form__err" role="alert">{err}</p> : null}
        {unverified ? <button type="button" className="linkish" onClick={resend}>Resend verification email</button> : null}
        <Button type="submit" loading={busy}>Authenticate</Button>
        <Link href="/forgot-password" className="form__side">Forgot password?</Link>
      </form>
    </AuthFrame>
  );
}
