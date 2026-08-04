"""Plain-language layer — reports must read for a non-technical founder first.

Alex's rule: a founder skims the report by eye, then forwards it to an engineer or an
AI. So (1) every finding leads with a plain-language statement of the real-world HARM
(what could go wrong, who's hurt) calibrated to severity — not jargon; (2) security
terms keep their precise name but get a one-line plain gloss on FIRST use (so the
engineer/AI still has the exact anchor); (3) internal finding-type tokens never appear
in the human report; (4) each severity gets a plain sentence. All deterministic — the
report never depends on the model to remember to explain a term.
"""

from __future__ import annotations

import re

from kuv.severity import FindingType, Severity

# Internal finding_type -> a plain, human-facing title. Never show the raw token.
TYPE_TITLES: dict[FindingType, str] = {
    FindingType.UNAUTH_WRITE: "Anyone can create or change your data without logging in",
    FindingType.UNAUTH_READ_SENSITIVE: "Private data is readable without logging in",
    FindingType.SERVICE_ROLE_EXPOSED: "A full-access database key is exposed in the app",
    FindingType.OFF_ALLOWLIST_SECRET: "A secret key is exposed in the website's code",
    FindingType.ABUSABLE_PRESIGNED_UPLOAD: "Strangers can upload files into your cloud storage",
    FindingType.WEAK_TRANSPORT_OR_CORS: "The site is missing standard browser security protections",
    FindingType.OAUTH_CONFIG_GAP: "The social-login flow is missing safety checks",
    FindingType.INSECURE_TLS: "The site's HTTPS certificate is invalid or weak",
    FindingType.SUBDOMAIN_TAKEOVER: "An abandoned subdomain could be hijacked by an attacker",
    FindingType.EMAIL_SPOOFING: "Anyone can send email pretending to be your domain",
}

# One plain sentence per severity — what it means for the reader's calendar.
SEVERITY_PLAIN: dict[Severity, str] = {
    Severity.CRITICAL: "Someone could take your data or accounts right now — fix today.",
    Severity.HIGH: "A serious, likely-exploitable hole — fix in the next day or two.",
    Severity.MEDIUM: "Worth fixing soon; it raises risk or helps a bigger attack.",
    Severity.LOW: "Minor on its own — fix when convenient.",
    Severity.INFO: "Informational — no direct risk by itself.",
}

# Security term -> a one-line plain gloss. First use in the report is rendered as
# "TERM (gloss)". Keep the term; add the plain words.
TERM_GLOSSARY: dict[str, str] = {
    "IDOR": "changing an ID in a URL to open someone else's data",
    "BOLA": "the server doesn't check you're allowed to see what you asked for",
    "CORS": "the rule for which other websites' code may read this site's data",
    "CSP": "a browser rule limiting which scripts a page may run",
    "HSTS": "forces browsers to always use HTTPS, blocking downgrade attacks",
    "DMARC": "the email rule that stops others sending mail that looks like it's from you",
    "SPF": "an email rule listing who may send mail for your domain",
    "XSS": "an attacker gets their own JavaScript to run in your users' browsers",
    "CSRF": "a malicious site makes a logged-in user's browser act without their consent",
    "pre-signed PUT": "a temporary link that lets someone upload straight into cloud storage",
    "pre-signed URL": "a temporary link granting direct upload/download to cloud storage",
    "subdomain takeover": "claiming an abandoned DNS record to host content on your domain",
    "CNAME": "a DNS alias pointing one hostname at another",
    "source map": "a file that turns minified JavaScript back into readable source code",
    "clickjacking": "hiding your site in an invisible frame to trick users into clicking",
    "MIME sniffing": "a browser guessing a file's type, which can turn an upload into code",
    "JWT": "a signed token a server issues to prove who a caller is",
    "service_role": "a database key that bypasses all access rules — full data access",
    "websocket": "a persistent two-way connection a page keeps open for live data",
    "PKCE": "an extra check that stops a stolen login code from being reused",
    "OAuth": "the log-in-with-Google/Microsoft handoff",
}

# Match a term not glued to surrounding alphanumerics; longest terms first so
# "pre-signed PUT" wins over "PUT". Case-insensitive.
_TERMS = sorted(TERM_GLOSSARY, key=len, reverse=True)
_PATTERNS = {
    t: re.compile(r"(?<![A-Za-z0-9])" + re.escape(t) + r"(?![A-Za-z0-9])", re.IGNORECASE)
    for t in _TERMS
}


def type_title(finding_type: FindingType, fallback: str = "") -> str:
    return TYPE_TITLES.get(finding_type, fallback or finding_type.value)


def severity_plain(severity: Severity) -> str:
    return SEVERITY_PLAIN.get(severity, "")


class Glosser:
    """Glosses each known term the FIRST time it appears anywhere in the report.
    Stateful across calls (share one instance per report). Never glosses inside
    backtick code spans, and won't double-gloss a term already followed by '('."""

    def __init__(self) -> None:
        self.seen: set[str] = set()

    def gloss(self, text: str) -> str:
        if not text:
            return text
        # Keep backtick code spans verbatim; only gloss prose segments. re.split with one
        # capturing group yields prose at EVEN indices and `code spans` at ODD indices —
        # use the parity, not startswith('`') (a stray backtick would misclassify prose).
        parts = re.split(r"(`[^`]*`)", text)
        for i, part in enumerate(parts):
            if i % 2 == 0:
                parts[i] = self._gloss_prose(part)
        return "".join(parts)

    def _gloss_prose(self, text: str) -> str:
        hits: list[tuple[int, int, str]] = []
        for term in _TERMS:
            if term.lower() in self.seen:
                continue
            m = _PATTERNS[term].search(text)
            if not m:
                continue
            # Skip THIS occurrence if the author already put a parenthetical right after
            # the term — but do NOT mark it seen: a version tag like "OAuth (v2)" must not
            # suppress a legitimate gloss of the term elsewhere in the report.
            tail = text[m.end():m.end() + 2].lstrip()
            if tail.startswith("("):
                continue
            hits.append((m.start(), m.end(), term))

        # Resolve overlaps (e.g. "pre-signed PUT" vs "PUT"): earliest, then longest.
        hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))
        chosen: list[tuple[int, int, str]] = []
        used: list[tuple[int, int]] = []
        for s, e, term in hits:
            if any(not (e <= us or s >= ue) for us, ue in used):
                continue
            chosen.append((s, e, term))
            used.append((s, e))

        # Insert glosses right-to-left so earlier offsets stay valid; never re-scans
        # inserted gloss text (avoids a gloss's words being glossed again).
        for s, e, term in sorted(chosen, key=lambda h: -h[0]):
            text = f"{text[:e]} ({TERM_GLOSSARY[term]}){text[e:]}"
            self.seen.add(term.lower())
        return text
