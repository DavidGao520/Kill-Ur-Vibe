"""Guard tests: the shipped methodology prompt teaches a general METHOD, not one
engagement's answer key, and the DNS wordlist carries no engagement-specific tells."""

from __future__ import annotations

from kuv.agent.methodology import METHODOLOGY_SYSTEM_PROMPT
from kuv.recon.dns import SUBDOMAIN_WORDLIST


def test_prompt_brands_generically_not_to_one_client():
    low = METHODOLOGY_SYSTEM_PROMPT.lower()
    assert "ai-built web apps" in low               # generic product framing
    # The prompt must not hardcode a specific target/client URL.
    assert "https://" not in METHODOLOGY_SYSTEM_PROMPT
    assert "http://" not in METHODOLOGY_SYSTEM_PROMPT


def test_prompt_names_the_broadened_taxonomy():
    low = METHODOLOGY_SYSTEM_PROMPT.lower()
    for cls in ("idor", "mass-assignment", "privilege", "forgeable", "graphql", "ssrf"):
        assert cls in low, f"taxonomy class missing from prompt: {cls!r}"


def test_prompt_documents_the_escape_hatch():
    low = METHODOLOGY_SYSTEM_PROMPT.lower()
    assert "operator triage" in low or "novel" in low


def test_wordlist_is_generic():
    for tell in ("ideas", "spark", "datatron", "conga-api", "swag"):
        assert tell not in SUBDOMAIN_WORDLIST, f"engagement-specific subdomain present: {tell!r}"
