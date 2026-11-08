"use client";
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError } from "./api";
import type { Me } from "./types";

interface Ctx { me: Me; refresh: () => Promise<void>; logout: () => Promise<void> }
const SessionCtx = createContext<Ctx | null>(null);

export function useSession(): Ctx {
  const c = useContext(SessionCtx);
  if (!c) throw new Error("useSession SessionProvider ke bahar");
  return c;
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [me, setMe] = useState<Me | null>(null);

  const refresh = useCallback(async () => {
    try {
      setMe(await api<Me>("/api/auth/me"));
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) router.replace("/login");
      else if (e instanceof ApiError && e.status === 403) router.replace("/login");
      else setMe(null);
    }
  }, [router]);

  useEffect(() => { void refresh(); }, [refresh]);

  const logout = useCallback(async () => {
    try { await api("/api/auth/logout", { method: "POST" }); } catch { /* cookie waise bhi saaf */ }
    router.replace("/login");
  }, [router]);

  if (!me) {
    return (
      <div className="auth-wait" role="status" aria-live="polite">
        <div className="auth-wait__ring" />
        <p>verifying session</p>
      </div>
    );
  }
  return <SessionCtx.Provider value={{ me, refresh, logout }}>{children}</SessionCtx.Provider>;
}
