export type Verdict = "SAFE" | "SUSPICIOUS" | "PHISHING";

export interface Billing {
  plan: "free" | "pro" | "business" | null; status: string | null; active: boolean; provider: string | null;
  current_period_end: string | null; cancel_at_period_end: boolean; can_manage: boolean;
}
export interface PlanInfo {
  id: "free" | "pro" | "business"; name: string; paid: boolean; tagline: string; price: string;
  interval: string | null; features: string[]; max_gmail_accounts: number; card_required: boolean;
}
export interface PlansData { provider: "stripe" | "mock"; plans: PlanInfo[]; current: Billing }
export interface Me { email: string; is_verified: boolean; totp_enabled: boolean; billing: Billing; gmail_connected: boolean }
export interface Stats { scanned: number; safe: number; suspicious: number; phishing: number; quarantined: number }

export interface ScanSummary {
  id: string; account_id: string; sender: string | null; subject: string | null;
  verdict: Verdict; score: number; action_taken: string | null; created_at: string;
}
export interface PmForm { action: string; has_password: boolean; method: string }
export interface PmSandbox {
  url: string; final_url: string; redirect_chain: string[]; status: number | null; title: string;
  elapsed_ms: number | null; error: string | null; hidden_iframes: number; downloads: string[];
  blocked_targets: number; forms: PmForm[]; findings: string[]; points: number;
}
export interface PmAttachment { name: string; size: number; real_type: string; points: number; findings: string[]; urls: string[] }
export interface PmDomain { domain: string; age_days: number | null; error: string | null }
export interface Postmortem {
  version: number; truncated?: boolean; sandbox?: PmSandbox[]; attachments?: PmAttachment[];
  domains?: PmDomain[]; qr_links?: string[];
}
export interface ScanDetail extends ScanSummary {
  reasons: string[]; layer_scores: Record<string, number | null>; urls: string[]; model_version: string | null;
  postmortem?: Postmortem | null;
}
export interface ScanList { items: ScanSummary[]; total: number; page: number; page_size: number }

export interface GmailAccount { id: string; email: string; status: string; last_run_at: string | null; created_at: string | null }
export interface GmailAccounts { configured: boolean; max_accounts: number; accounts: GmailAccount[] }

export interface CheckResult {
  verdict: Verdict; score: number; confidence: number; reasons: string[];
  layer_scores: Record<string, number | null>;
  signals: { code: string; layer: string; points: number; text: string }[];
  defanged_urls: string[]; degraded: boolean; notes: string[]; model_version: string | null;
}

export interface WhitelistEntry { id: string; kind: "sender" | "domain"; value: string; created_at: string }
export interface SettingsData {
  alerts_enabled: boolean; email_alerts: boolean; telegram_alerts: boolean;
  telegram_linked: boolean; telegram_configured: boolean;
  suspicious_threshold: number; phishing_threshold: number;
  minimum_suspicious_threshold: number; minimum_phishing_threshold: number;
  whitelist: WhitelistEntry[];
}

export type Tone = "idle" | "safe" | "warn" | "danger";
export const verdictTone = (v: Verdict): Tone => (v === "SAFE" ? "safe" : v === "SUSPICIOUS" ? "warn" : "danger");
