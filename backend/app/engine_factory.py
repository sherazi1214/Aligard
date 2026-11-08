"""Engine ek hi jagah banta hai. API keys (.env) na hon to wahi bundled ML+heuristics engine, koi paid call nahi.
VirusTotal/OpenAI sirf tab jab key set ho, aur dono daily budget guard ke peeche."""
from __future__ import annotations

import logging
from functools import lru_cache

from backend.app import redis_client
from backend.app.budget import BudgetedLLM, BudgetGuard
from backend.app.config import get_settings
from engine import Engine
from engine.config import EngineConfig
from engine.domainintel import RdapDomainIntel
from engine.llm import OpenAIProvider
from engine.models import AnalysisResult, EmailInput
from engine.reputation import VirusTotalProvider
from engine.sandbox import LinkSandbox, PlaywrightFetcher

log = logging.getLogger("aliguard.engine_factory")


@lru_cache
def get_engine() -> Engine:
    s = get_settings()
    r = redis_client.redis_client
    reputation, llm = [], None
    if s.vt_api_key:
        guard = BudgetGuard(r, "virustotal", s.vt_daily_call_limit, s.vt_user_daily_call_limit)
        reputation.append(VirusTotalProvider(s.vt_api_key, before_request=guard.consume))
    if s.openai_api_key:
        guard = BudgetGuard(r, "openai", s.openai_daily_call_limit, s.openai_user_daily_call_limit)
        llm = BudgetedLLM(OpenAIProvider(s.openai_api_key, model=s.openai_model), guard)
    sandbox = LinkSandbox(PlaywrightFetcher(timeout_ms=s.sandbox_timeout_ms)) if s.sandbox_enabled else None
    log.info("Engine ready (virustotal=%s, llm=%s, sandbox=%s)", bool(reputation), llm is not None,
             sandbox is not None)
    cfg = EngineConfig(max_urls_sandbox=s.sandbox_max_urls)
    intel = RdapDomainIntel() if s.domain_intel_enabled else None
    return Engine.default(config=cfg, reputation=reputation, llm=llm, sandbox=sandbox, domain_intel=intel)


def analyze(email: EmailInput) -> AnalysisResult:
    return get_engine().analyze(email)
