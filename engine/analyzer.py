"""Saari layers ko jodna. Design usool:
- analyze() kabhi exception nahi uchalta; layer fail ho to 'degraded' + note.
- ML akeli kabhi PHISHING nahi bana sakti (sirf SUSPICIOUS), corroboration chahiye.
- LLM ka SAFE strong evidence (feed hit, VT >= 5, strong heuristics) ko kabhi kam nahi karta.
- Engine default mein kisi URL ko visit nahi karta. Sandbox (engine/sandbox.py) diya ho to sirf shak wali mails ke
  chand links isolated browser mein khulte hain, aur sirf tab jab koi hard reputation hit na ho."""
from __future__ import annotations

import logging
import time
from collections.abc import Sequence

from engine.attachments import analyze_attachments, sniff
from engine.brands import OFFICIAL
from engine.config import EngineConfig
from engine.domainintel import RdapDomainIntel, evaluate_age
from engine.heuristics import score_heuristics
from engine.llm import LLMProvider
from engine.ml import DEFAULT_MODEL_PATH, ModelLoadError, PhishingModel
from engine.models import AnalysisResult, EmailInput, Signal, Verdict
from engine.parsing import build_content
from engine.postmortem import build_postmortem
from engine.qr import decode_qr_urls
from engine.reputation import ProviderError, ReputationProvider
from engine.sandbox import LinkSandbox, SandboxResult, pick_candidates
from engine.urls import defang, parse_url, registrable_domain

log = logging.getLogger("engine.analyzer")


def blend_base(h_score: float, ml_score: float | None, cfg: EngineConfig) -> float:
    """ML + heuristics ka base score. Alag function isliye ke engine.tune_weights bina dobara
    poora engine chalaye (network/sandbox ke baghair) config grid par wohi formula dohra sake."""
    if ml_score is None:
        return float(h_score)
    base = (1 - cfg.ml_weight) * h_score + cfg.ml_weight * ml_score
    if h_score >= cfg.heuristic_strong:
        base = max(base, float(h_score))  # strong heuristics akeli kafi
    if h_score < cfg.ml_corroboration_heuristic:
        base = min(base, float(cfg.ml_cap_without_corroboration))  # ML akeli PHISHING nahi
    return base


def decide(score: float, cfg: EngineConfig) -> Verdict:
    score = max(0, min(100, round(score)))
    return (Verdict.PHISHING if score >= cfg.phishing_threshold
            else Verdict.SUSPICIOUS if score >= cfg.suspicious_threshold else Verdict.SAFE)


class Engine:
    def __init__(
        self,
        config: EngineConfig | None = None,
        model: PhishingModel | None = None,
        reputation: Sequence[ReputationProvider] = (),
        llm: LLMProvider | None = None,
        sandbox: LinkSandbox | None = None,
        domain_intel: RdapDomainIntel | None = None,
    ) -> None:
        self.cfg = config or EngineConfig()
        self.model, self.reputation, self.llm = model, list(reputation), llm
        self.sandbox = sandbox
        self.domain_intel = domain_intel

    @classmethod
    def default(cls, **kwargs) -> Engine:
        """Bundled model load karta hai; na mile/kharab ho to ML ke baghair chalta hai (warning log)."""
        model = None
        try:
            model = PhishingModel.load(DEFAULT_MODEL_PATH)
        except ModelLoadError as exc:
            log.warning("ML model load nahi hua, heuristics-only mode: %s", exc)
        return cls(model=model, **kwargs)

    # ---------------------------------------------------------------- main
    def analyze(self, email: EmailInput) -> AnalysisResult:
        try:
            return self._analyze(email)
        except Exception:  # noqa: BLE001 - security tool: crash ki jagah degraded jawab
            log.exception("Analysis mein ghair-mutawaqqa error")
            return AnalysisResult(
                verdict=Verdict.SUSPICIOUS, score=self.cfg.suspicious_threshold,
                confidence=0.2, reasons=["Analysis failed internally; manual review advised"],
                layer_scores={"ml": None, "heuristics": None, "reputation": None, "llm": None},
                signals=[], urls=[], defanged_urls=[], degraded=True,
                notes=["internal_error"],
            )

    def _analyze(self, email: EmailInput) -> AnalysisResult:
        cfg = self.cfg
        notes: list[str] = []
        degraded = False
        content = build_content(email, cfg.max_body_chars)

        # Layer 1.5: attachment ke ANDAR ka content + QR codes (links content.urls mein judte hain)
        att_pts, att_signals, att_reports, qr_urls = self._attachments(email, content)

        # Layer 2: heuristics
        h_score, signals, auth = score_heuristics(email, content, cfg)
        signals.extend(att_signals)
        h_score = min(100, h_score + int(att_pts))  # attachment saboot heuristics ki corroboration ginta hai
        if not auth:
            notes.append("no_trusted_auth_results")

        # Layer 1: ML
        ml_score: float | None = None
        if self.model:
            try:
                p = self.model.predict_proba(f"{email.subject}\n{content.text}")
                ml_score = round(p * 100, 1)
                if p >= 0.5:
                    signals.append(Signal("ml_high", "ml", 0,
                                          f"Text pattern model rates this {p:.0%} phishing-like"))
            except Exception:  # noqa: BLE001
                log.exception("ML layer fail")
                degraded = True
                notes.append("ml_failed")
        else:
            notes.append("ml_disabled")

        # Base score (ML + heuristics)
        base = blend_base(h_score, ml_score, cfg)

        # Layer 3: reputation
        rep_score: float | None = None
        hard_hit = False
        if self.reputation and content.urls:
            rep_score, rep_signals, hard_hit, rep_degraded, rep_notes = self._reputation(content.urls)
            signals.extend(rep_signals)
            degraded |= rep_degraded
            notes.extend(rep_notes)
            if hard_hit:
                base = max(base, 95.0)
            elif rep_score:
                base = min(100.0, base + rep_score)

        # Layer 3b: link sandbox (browser mein link kholna). Hard hit ho to zaroorat nahi.
        sbx_score: float | None = None
        sbx_reports: list[dict] = []
        if self.sandbox and content.urls and not hard_hit and base >= cfg.sandbox_min_score:
            sbx_score, sbx_signals, sbx_reports, sbx_notes = self._sandbox(content.urls)
            signals.extend(sbx_signals)
            notes.extend(sbx_notes)
            if sbx_score:
                base = min(100.0, base + sbx_score)

        # Layer 3c: domain age (RDAP)
        dom_reports: list[dict] = []
        dom_score: float | None = None
        if self.domain_intel and content.urls and not hard_hit and base >= cfg.sandbox_min_score:
            dom_score, dom_signals, dom_reports = self._domains(content.urls)
            signals.extend(dom_signals)
            if dom_score:
                base = min(100.0, base + dom_score)

        pre_score = base

        # Layer 4: LLM (sirf borderline par, aur sirf agar URL/suspicion ho)
        llm_score: float | None = None
        if self.llm and cfg.llm_min_score <= pre_score < cfg.phishing_threshold:
            adj, llm_score, llm_signal, llm_failed = self._llm(email, content, pre_score,
                                                               h_score, hard_hit)
            if llm_failed:
                degraded = True
                notes.append("llm_failed")
            if llm_signal:
                signals.append(llm_signal)
            base += adj

        # Trusted sender (DMARC pass ke saath hi) aur koi hard hit na ho
        sender_dom = registrable_domain(email.sender_email.rsplit("@", 1)[-1]) \
            if email.sender_email else ""
        if (sender_dom in cfg.trusted_senders and auth.get("dmarc") == "pass" and not hard_hit):
            base = min(base, 20.0)
            signals.append(Signal("trusted_sender", "heuristics", 0,
                                  "Trusted sender with passing authentication"))

        score = max(0, min(100, round(base)))
        verdict = decide(score, cfg)

        urls = content.urls
        reasons = [s.text for s in sorted(signals, key=lambda s: s.points, reverse=True)
                   if s.layer != "heuristics" or s.points > 0 or s.code == "trusted_sender"]
        if not reasons:
            reasons = ["No suspicious signals found"]
        return AnalysisResult(
            verdict=verdict, score=score,
            confidence=self._confidence(score, degraded, hard_hit),
            reasons=reasons,
            layer_scores={"ml": ml_score, "heuristics": float(h_score),
                          "reputation": rep_score, "sandbox": sbx_score,
                          "attachments": float(att_pts) if att_reports else None, "domain": dom_score,
                          "llm": llm_score},
            signals=signals, urls=urls, defanged_urls=[defang(u) for u in urls],
            degraded=degraded, notes=notes,
            model_version=self.model.version if self.model else None,
            sandbox_reports=sbx_reports,
            postmortem=build_postmortem(sbx_reports, [a.report() for a in att_reports], dom_reports, qr_urls),
        )

    # ---------------------------------------------------------------- layers
    def _reputation(self, urls: list[str]):
        cfg = self.cfg
        # Pehle wo URLs jo heuristics ko shak wale lagte hain
        def rank(u: str) -> int:
            p = parse_url(u)
            return 0 if p and (p.is_ip or p.is_punycode or p.tld_suspicious or p.is_shortener
                               or p.has_userinfo) else 1
        candidates = sorted(urls, key=rank)[: cfg.max_urls_reputation]
        signals: list[Signal] = []
        notes: list[str] = []
        degraded = False
        hard = False
        score = 0.0
        start = time.monotonic()
        for url in candidates:
            if time.monotonic() - start > cfg.reputation_budget_seconds:
                notes.append("reputation_budget_exceeded")
                degraded = True
                break
            for prov in self.reputation:
                try:
                    r = prov.lookup(url)
                except ProviderError as exc:
                    degraded = True
                    notes.append(f"reputation_error:{prov.name}:{exc}")
                    continue
                except Exception:  # noqa: BLE001
                    log.exception("Reputation provider crash")
                    degraded = True
                    notes.append(f"reputation_error:{prov.name}")
                    continue
                if not r:
                    continue
                host = defang(parse_url(url).host) if parse_url(url) else "url"
                if r.listed:
                    hard = True
                    score = max(score, 95)
                    signals.append(Signal("feed_hit", "reputation", 95,
                                          f"URL/domain {host} is listed in threat feed '{r.source}'"))
                elif r.malicious >= cfg.vt_hard_malicious:
                    hard = True
                    score = max(score, 90)
                    signals.append(Signal("vt_malicious", "reputation", 90,
                                          f"VirusTotal: {r.malicious}/{r.total} engines flag {host}"))
                elif r.malicious + r.suspicious > 0:
                    score = max(score, 20)
                    signals.append(Signal("vt_some", "reputation", 20,
                                          f"VirusTotal: {r.malicious + r.suspicious}/{r.total} "
                                          f"engines flag {host}"))
        return (score if candidates else None), signals, hard, degraded, notes

    def _attachments(self, email: EmailInput, content):
        """(points, signals, reports, qr_urls). Nikle hue links content.urls mein judte hain."""
        cfg = self.cfg
        signals: list[Signal] = []
        reports = analyze_attachments(email.attachment_files) if email.attachment_files else []
        pts = 0.0
        for r in reports:
            signals.extend(r.signals)
            pts += r.points
            content.urls.extend(u for u in r.urls if u not in content.urls)
        pts = min(pts, cfg.attachment_max_points)
        images = list(email.image_files) + [(n, d) for n, d in email.attachment_files
                                            if sniff(d) == "image" and (n, d) not in email.image_files]
        qr_urls = decode_qr_urls(images) if images else []
        if qr_urls:
            signals.append(Signal("qr_link", "attachment", 15, "A link is hidden inside a QR code image (QR phishing)"))
            pts += 15
            content.urls.extend(u for u in qr_urls if u not in content.urls)
        del content.urls[cfg.max_urls_analyzed * 2:]
        return pts, signals, reports, qr_urls

    def _domains(self, urls: list[str]):
        """(score, signals, reports). Sirf un domains ke liye jo asli brand ke nahi."""
        cfg = self.cfg
        official = set().union(*OFFICIAL.values())
        seen: list[str] = []
        for u in urls:
            p = parse_url(u)
            if p and not p.is_ip and p.registrable not in official and p.registrable not in seen:
                seen.append(p.registrable)
        signals, reports, best = [], [], 0.0
        for dom in seen[: cfg.max_domains_intel]:
            info = self.domain_intel.lookup(dom)
            reports.append(info.report())
            sig = evaluate_age(dom, info.age_days)
            if sig:
                signals.append(sig)
                best = max(best, sig.points)
        return min(best, cfg.domain_intel_max_points), signals, reports

    def _sandbox(self, urls: list[str]):
        """(score, signals, reports, notes). Time budget ke andar chand URLs kholta hai."""
        cfg = self.cfg
        signals: list[Signal] = []
        reports: list[dict] = []
        notes: list[str] = []
        best = 0.0
        start = time.monotonic()
        for url in pick_candidates(urls, cfg.max_urls_sandbox):
            if time.monotonic() - start > cfg.sandbox_budget_seconds:
                notes.append("sandbox_budget_exceeded")
                break
            res: SandboxResult = self.sandbox.inspect(url)
            reports.append(res.report())
            if res.error:
                notes.append(f"sandbox_error:{res.error}")
            signals.extend(res.signals)
            best = max(best, res.points)
        return min(best, cfg.sandbox_max_points), signals, reports, notes

    def _llm(self, email: EmailInput, content, pre_score: float, h_score: int, hard_hit: bool):
        """(score adjustment, llm_score, signal, failed). LLM sirf asar daal sakta hai, hukm nahi."""
        cfg = self.cfg
        sender_dom = email.sender_email.rsplit("@", 1)[-1] if email.sender_email else "unknown"
        try:
            res = self.llm.classify(email.subject, sender_dom, content.text[: cfg.llm_max_body_chars],
                                    content.urls)
        except ProviderError as exc:
            log.warning("LLM layer skip: %s", exc)
            return 0.0, None, None, True
        except Exception:  # noqa: BLE001
            log.exception("LLM crash")
            return 0.0, None, None, True
        llm_score = {Verdict.SAFE: 0.0, Verdict.SUSPICIOUS: 50.0, Verdict.PHISHING: 100.0}[res.verdict]
        strong = hard_hit or h_score >= cfg.heuristic_strong
        adj = 0.0
        if res.verdict is Verdict.PHISHING:
            adj = 35 * res.confidence
            # LLM akela (corroboration ke baghair) PHISHING tak nahi pohncha sakta
            if pre_score < 50 and pre_score + adj >= cfg.phishing_threshold:
                adj = cfg.phishing_threshold - 1 - pre_score
        elif res.verdict is Verdict.SUSPICIOUS:
            adj = 15 * res.confidence
        elif not strong:
            adj = -15 * res.confidence  # SAFE: sirf halka kam, aur strong evidence par bilkul nahi
        reason = f"LLM review: {res.verdict.value.lower()} ({res.confidence:.0%})"
        if res.reason:
            reason += f" - {res.reason}"
        return adj, llm_score, Signal("llm_verdict", "llm", abs(adj), reason), False

    def _confidence(self, score: int, degraded: bool, hard_hit: bool) -> float:
        t1, t2 = self.cfg.suspicious_threshold, self.cfg.phishing_threshold
        dist = min(abs(score - t1), abs(score - t2))
        if score < t1:
            dist = t1 - score
        elif score >= t2:
            dist = score - t2 + 10
        conf = min(1.0, 0.5 + 0.5 * dist / 35)
        if hard_hit:
            conf = max(conf, 0.95)
        return round(conf * (0.8 if degraded else 1.0), 3)
