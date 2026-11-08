export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const CSRF_COOKIE = "aliguard_csrf";

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return m ? decodeURIComponent(m[1]) : null;
}

async function ensureCsrf(): Promise<string> {
  let token = readCookie(CSRF_COOKIE);
  if (!token) {
    await fetch("/api/auth/csrf", { credentials: "same-origin" });
    token = readCookie(CSRF_COOKIE);
  }
  return token || "";
}

function extractMessage(data: unknown, status: number): string {
  const d = data as { detail?: unknown; errors?: { msg?: string }[] } | null;
  if (d && typeof d.detail === "string") {
    if (Array.isArray(d.errors) && d.errors.length) {
      const msgs = d.errors.map((e) => e.msg).filter(Boolean);
      if (msgs.length) return msgs.join("; ");
    }
    return d.detail;
  }
  if (d && Array.isArray(d.detail)) {
    return d.detail.map((x: { msg?: string }) => x.msg).filter(Boolean).join("; ") || `Request failed (${status})`;
  }
  return `Request failed (${status})`;
}

interface Opts { method?: "GET" | "POST" | "PATCH" | "DELETE"; body?: unknown }

export async function api<T = unknown>(path: string, opts: Opts = {}, retried = false): Promise<T> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  if (method !== "GET") headers["x-csrf-token"] = await ensureCsrf();
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";

  let res: Response;
  try {
    res = await fetch(path, {
      method, headers, credentials: "same-origin",
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
  } catch {
    throw new ApiError(0, "Server se rabta nahi ho saka. Internet ya backend check karein.");
  }

  let data: unknown = null;
  try { data = await res.json(); } catch { /* khali body */ }

  if (!res.ok) {
    const msg = extractMessage(data, res.status);
    // CSRF cookie purani/invalid ho to ek baar naye token ke sath dobara
    if (res.status === 403 && /csrf/i.test(msg) && !retried) {
      document.cookie = `${CSRF_COOKIE}=; Max-Age=0; path=/`;
      return api<T>(path, opts, true);
    }
    throw new ApiError(res.status, msg);
  }
  return data as T;
}
