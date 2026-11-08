"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import AuthFrame from "@/components/AuthFrame";
import { Button, Field } from "@/components/ui";
import { api, ApiError } from "@/lib/api";

export default function Login2FA() {
  const router = useRouter();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [expired, setExpired] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setErr("");
    try {
      await api("/api/auth/login/2fa", { method: "POST", body: { code: code.replace(/\s+/g, "") } });
      router.push("/dashboard");
    } catch (ex) {
      setErr(ex instanceof ApiError ? ex.message : "Verify nakam");
      if (ex instanceof ApiError && ex.status === 401 && /session/i.test(ex.message)) setExpired(true);
    } finally { setBusy(false); }
  }

  return (
    <AuthFrame title="Second factor" sub="Enter the 6-digit code from your authenticator app, or a recovery code." footer={<Link href="/login">Back to login</Link>}>
      <form onSubmit={submit} className="form" noValidate>
        <Field label="Code" inputMode="numeric" autoComplete="one-time-code" autoFocus required value={code} onChange={(e) => setCode(e.target.value)} />
        {err ? <p className="form__err" role="alert">{err}</p> : null}
        {expired ? <Link className="linkish" href="/login">Start again</Link> : null}
        <Button type="submit" loading={busy}>Verify</Button>
      </form>
    </AuthFrame>
  );
}
