"""A curated library of deterministic, SAFE exposure checks (nuclei-lite).

Each :class:`CheckSpec` is a small set of candidate paths + a **content matcher**.
Two hard rules keep this high-signal and legitimate to run against a third party's
production:

* **Safe**: every check is a single GET. No writes, no fuzzing, no brute-force.
* **No false positives from SPA catch-alls**: a Next.js/Vite app returns ``200`` +
  its HTML shell for *any* path, so "``GET /.env`` → 200" means nothing. Every
  matcher therefore requires a **positive content signature** (the body actually
  looks like an env file / a git config / a Spring actuator dump) and rejects HTML.

Findings map to the deterministic severity table via ``finding_type`` — the model
never sets severity here, it just records what the matcher deterministically found.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

# --------------------------------------------------------------------------
# results
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Exposure:
    path: str
    finding_type: str
    title: str
    evidence: str
    recommendation: str
    plain_impact: str


@dataclass(frozen=True)
class CheckSpec:
    key: str
    paths: tuple[str, ...]
    finding_type: str
    title: str
    recommendation: str
    plain_impact: str
    matcher: Callable[[int, dict, str], bool]


# --------------------------------------------------------------------------
# matcher helpers
# --------------------------------------------------------------------------

_ENV_LINE = re.compile(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*=")
_SECRETISH_KEY = re.compile(
    r"(?mi)^\s*(?:export\s+)?[A-Z0-9_]*"
    r"(SECRET|KEY|PASSWORD|PASSWD|TOKEN|DATABASE_URL|DB_URL|API|PRIVATE|CREDENTIAL|DSN)"
    r"[A-Z0-9_]*\s*="
)


def _ctype(headers: dict) -> str:
    for k, v in (headers or {}).items():
        if str(k).lower() == "content-type":
            return str(v).lower()
    return ""


def _looks_html(body: str) -> bool:
    head = (body or "")[:600].lstrip().lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<head" in head[:200]


def _m_env(status: int, headers: dict, body: str) -> bool:
    # A served .env: not HTML, and either a secret-ish key or >=2 KEY=VALUE lines.
    if status != 200 or _looks_html(body):
        return False
    if _SECRETISH_KEY.search(body):
        return True
    return len(_ENV_LINE.findall(body)) >= 2


def _m_git_config(status: int, headers: dict, body: str) -> bool:
    low = (body or "").lower()
    return status == 200 and "[core]" in low and "repositoryformatversion" in low


def _m_git_head(status: int, headers: dict, body: str) -> bool:
    b = (body or "").strip()
    return status == 200 and len(b) < 200 and b.lower().startswith("ref:") and "refs/" in b.lower()


def _m_backup(status: int, headers: dict, body: str) -> bool:
    if status != 200 or _looks_html(body):
        return False
    ct = _ctype(headers)
    if any(t in ct for t in ("zip", "gzip", "x-tar", "octet-stream", "sql")):
        return True
    low = (body or "").lower()
    # A served SQL dump served as text/plain: require DDL/DML keywords.
    return ("create table" in low) or ("insert into" in low and "values" in low) or ("drop table" in low)


def _m_actuator(status: int, headers: dict, body: str) -> bool:
    low = (body or "").lower()
    if status != 200 or _looks_html(body):
        return False
    return ('"_links"' in low) or ("activeprofiles" in low) or ("propertysources" in low)


def _m_phpinfo(status: int, headers: dict, body: str) -> bool:
    low = (body or "").lower()
    return status == 200 and ("phpinfo()" in low or ("php version" in low and "configuration" in low))


def _m_apache_status(status: int, headers: dict, body: str) -> bool:
    return status == 200 and "apache server status" in (body or "").lower()


def _m_openapi(status: int, headers: dict, body: str) -> bool:
    low = (body or "").lower()
    if status != 200 or _looks_html(body):
        return False
    return ('"swagger"' in low or '"openapi"' in low) and '"paths"' in low


# --------------------------------------------------------------------------
# the curated check list
# --------------------------------------------------------------------------

CHECKS: tuple[CheckSpec, ...] = (
    CheckSpec(
        "env_file",
        (".env", ".env.local", ".env.production", ".env.development"),
        "exposed_secret_file",
        "Environment file with secrets is publicly served",
        "Remove the file from the web root and rotate every credential it contained; "
        "serve secrets from the runtime environment, never a file under the document root.",
        "Anyone can download your app's secret settings file — which usually holds database "
        "passwords and API keys — just by visiting a URL. Treat every secret in it as leaked.",
        _m_env,
    ),
    CheckSpec(
        "git_config",
        (".git/config",),
        "exposed_secret_file",
        "Exposed .git repository (source code disclosure)",
        "Block access to the .git directory at the web server/CDN; do not deploy the .git "
        "folder to production.",
        "Your source code repository is downloadable from the internet, which can leak your "
        "code, internal URLs, and any secrets committed to git history.",
        _m_git_config,
    ),
    CheckSpec(
        "git_head",
        (".git/HEAD",),
        "exposed_secret_file",
        "Exposed .git repository (source code disclosure)",
        "Block access to the .git directory at the web server/CDN.",
        "Your source code repository is reachable from the internet and can be reconstructed, "
        "leaking code and any secrets in git history.",
        _m_git_head,
    ),
    CheckSpec(
        "backup",
        ("backup.sql", "database.sql", "dump.sql", "db.sql", "backup.zip", "backup.tar.gz"),
        "exposed_secret_file",
        "Database/backup file is publicly downloadable",
        "Remove the backup from the web root; store backups in access-controlled storage.",
        "A full copy of your database or a site backup can be downloaded by anyone — that is "
        "potentially every user record and secret in one file.",
        _m_backup,
    ),
    CheckSpec(
        "spring_actuator",
        ("actuator", "actuator/env", "actuator/health"),
        "exposed_service_interface",
        "Spring Boot Actuator endpoints exposed without auth",
        "Restrict /actuator to authenticated ops access; disable env/heapdump/beans in prod.",
        "An internal operations dashboard is open to the public and can reveal configuration, "
        "environment variables, and internal details useful to an attacker.",
        _m_actuator,
    ),
    CheckSpec(
        "phpinfo",
        ("phpinfo.php", "info.php", "test.php"),
        "exposed_service_interface",
        "phpinfo() page exposed",
        "Delete the phpinfo/test page from production.",
        "A diagnostics page is publicly revealing your server's full configuration and paths, "
        "handing an attacker a map of your environment.",
        _m_phpinfo,
    ),
    CheckSpec(
        "apache_status",
        ("server-status",),
        "exposed_service_interface",
        "Apache mod_status page exposed",
        "Restrict /server-status to localhost/authorized IPs.",
        "A live server-activity page is public, leaking the URLs other users are visiting and "
        "internal request details.",
        _m_apache_status,
    ),
    CheckSpec(
        "openapi",
        ("swagger.json", "openapi.json", "v2/api-docs", "v3/api-docs", "api-docs"),
        "info_disclosure",
        "API schema (OpenAPI/Swagger) publicly reachable",
        "If the API is not meant to be public, require auth on the schema endpoint; otherwise "
        "ensure every documented route enforces its own authorization.",
        "Your full API blueprint is public. It may be intentional, but it hands an attacker the "
        "exact list of endpoints and parameters to probe — worth confirming each is protected.",
        _m_openapi,
    ),
)


def run_templated_checks(
    fetch: Callable[[str], Optional[tuple]],
    checks: tuple[CheckSpec, ...] = CHECKS,
    cap: int = 40,
) -> tuple[list[Exposure], int, bool]:
    """Run each check's paths through ``fetch`` until one matches; return exposures.

    ``fetch(path)`` returns ``(status, headers, body)`` or ``None`` (refused/error).
    At most ``cap`` fetches total (bounds work on a big check list). Returns
    ``(exposures, probed_count, truncated)``.
    """
    out: list[Exposure] = []
    probed = 0
    truncated = False
    for spec in checks:
        hit = False
        for path in spec.paths:
            if probed >= cap:
                truncated = True
                return out, probed, truncated
            res = fetch(path)
            probed += 1
            if res is None:
                continue
            status, headers, body = res
            if spec.matcher(status, headers, body):
                ctype = _ctype(headers) or "-"
                out.append(
                    Exposure(
                        path=path,
                        finding_type=spec.finding_type,
                        title=spec.title,
                        evidence=f"GET /{path} → {status}, {len(body or '')} bytes, content-type: {ctype}",
                        recommendation=spec.recommendation,
                        plain_impact=spec.plain_impact,
                    )
                )
                hit = True
                break
        if hit:
            continue
    return out, probed, truncated
