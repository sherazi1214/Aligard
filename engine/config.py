"""Engine ki tuning. Thresholds yahin se badalte hain, code mein nahi."""
from dataclasses import dataclass


@dataclass(frozen=True)
class EngineConfig:
    # Final decision thresholds (score 0-100)
    suspicious_threshold: int = 35
    phishing_threshold: int = 70

    # Heuristics itni strong hon to akeli kafi hain (ML ke baghair bhi PHISHING)
    heuristic_strong: int = 60
    ml_weight: float = 0.5
    # ML akeli (heuristics < corroboration) kabhi PHISHING nahi bana sakti, sirf SUSPICIOUS
    ml_corroboration_heuristic: int = 20
    ml_cap_without_corroboration: int = 55

    # Hadd (DoS se bachao)
    max_body_chars: int = 200_000
    max_urls_analyzed: int = 50
    max_urls_reputation: int = 5
    reputation_budget_seconds: float = 20.0

    # Link sandbox (headless browser): sirf tab chalta hai jab Engine(sandbox=...) diya ho
    sandbox_min_score: int = 15  # is se kam score wali (bilkul saaf) mails ke links khole nahi jate
    max_urls_sandbox: int = 2
    sandbox_budget_seconds: float = 30.0
    sandbox_max_points: float = 60.0

    # Domain age (RDAP): sirf Engine(domain_intel=...) diya ho to
    max_domains_intel: int = 3
    domain_intel_max_points: float = 30.0
    attachment_max_points: float = 60.0

    # Reputation
    vt_hard_malicious: int = 5  # itne engines flag karein to hard override

    # LLM: sirf borderline score par chalega
    llm_min_score: int = 15
    llm_max_body_chars: int = 3000

    # Sirf in servers ka Authentication-Results header qabil-e-aitbaar (Gmail: mx.google.com).
    # Attacker khud fake "Authentication-Results" header daal sakta hai.
    trusted_authserv_ids: frozenset = frozenset({"mx.google.com"})
    # Trusted sender domains (registrable). Sirf tab chalte hain jab DMARC pass ho.
    trusted_senders: frozenset = frozenset()
