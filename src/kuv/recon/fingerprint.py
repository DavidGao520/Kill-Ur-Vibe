"""Deterministic tech-stack fingerprinting from a fetched response.

Pure and I/O-free: :func:`fingerprint` matches **structural** signals — framework
asset paths (``/_next/``), header key/values (``server: cloudflare``), cookie names
(``laravel_session``), and SDK script hosts (``js.stripe.com``) — never prose words.
So a marketing page that merely *mentions* "WordPress" in copy is NOT misdetected;
only ``/wp-content/`` / ``wp-json`` (structural) count.

The point is **branching**: KUV's methodology was running one generic probe sequence
against every site, so every report looked the same. Knowing the target is
Supabase-backed vs a WordPress CMS vs a Stripe-integrated Next.js app lets the agent
unlock stack-specific probes instead — different stacks → different findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Cap the body we fold into the match corpus — fingerprint signals live in the
# head/asset refs, not deep in a large document; also bounds work on a huge page.
_BODY_CAP = 300_000


@dataclass(frozen=True)
class Detection:
    """One matched technology and the exact structural signal that proved it."""

    category: str  # framework | cms | server | baas | hosting | payment | auth
    name: str
    evidence: str  # the lowercased structural substring that matched


@dataclass
class Fingerprint:
    detections: list[Detection] = field(default_factory=list)

    def names(self) -> list[str]:
        return [d.name for d in self.detections]

    def has(self, name: str) -> bool:
        low = name.lower()
        return any(d.name.lower() == low for d in self.detections)

    def by_category(self, category: str) -> list[Detection]:
        return [d for d in self.detections if d.category == category]

    def tags(self) -> list[str]:
        """`category:name` tags, sorted — a stable branching key for the methodology."""
        return sorted(f"{d.category}:{d.name}" for d in self.detections)


# (category, name, structural signal substrings). Signals are lowercased and matched
# as substrings against a corpus of "header: value" lines + set-cookies + body + JS
# URLs. Every signal is chosen to be STRUCTURAL (a path, header, cookie, or SDK host)
# so it does not fire on prose. First matching signal per name wins (evidence).
_RULES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    # ---- frontend frameworks ----
    # Order matters only for evidence, not correctness: a site can match several.
    ("framework", "Next.js", ("/_next/", "__next_data__", "x-nextjs", "x-powered-by: next")),
    ("framework", "Nuxt", ("/_nuxt/", "window.__nuxt__", "__nuxt__")),
    ("framework", "SvelteKit", ("__sveltekit", "/_app/immutable/")),
    ("framework", "Remix", ("__remixcontext", "window.__remixmanifest")),
    ("framework", "Angular", ("ng-version=", "/polyfills.", "zone.js")),
    ("framework", "Gatsby", ("/page-data/app-data.json", "___gatsby")),
    # Generic React (Create React App / custom) — the most common vibe-coder frontend.
    # `id="root"` + CRA's `/static/js/main.[hash].js` are structural, not prose.
    ("framework", "React", ('id="root"', "react-dom", "data-reactroot", "/static/js/main.")),
    # Create React App specifically (its fixed build layout).
    ("framework", "Create React App", ("/static/js/main.", "/static/css/main.")),
    # Vite: dev client, or its prod `/assets/index-[hash].js` module bundle.
    ("framework", "Vite", ("/@vite/client", "vite/dist/client", "/assets/index-")),
    ("framework", "Vue", ("__vue__", "data-v-app", "data-server-rendered")),
    # ---- CMS / site builders ----
    ("cms", "WordPress", ("/wp-content/", "/wp-includes/", "wp-json", "x-powered-by: wordpress")),
    ("cms", "Drupal", ("x-generator: drupal", "x-drupal", "/sites/default/files")),
    ("cms", "Shopify", ("x-shopify", "cdn.shopify.com", "x-shopid", "x-sorting-hat")),
    ("cms", "Webflow", ("wf-domain", "assets.website-files.com", "generator: webflow")),
    ("cms", "Wix", ("x-wix-", "static.wixstatic.com", "x-wix-request-id")),
    ("cms", "Ghost", ("content=\"ghost", "x-ghost", "/ghost/api/")),
    # ---- backend / server ----
    ("server", "Express", ("x-powered-by: express", "connect.sid")),
    ("server", "PHP", ("x-powered-by: php", "phpsessid")),
    ("server", "Ruby on Rails", ("x-runtime:", "authenticity_token", "server: puma")),
    ("server", "Django", ("csrfmiddlewaretoken", "csrftoken=", "sessionid=")),
    ("server", "Laravel", ("laravel_session", "x-powered-by: laravel")),
    ("server", "ASP.NET", ("x-aspnet-version", "x-powered-by: asp.net", "__viewstate", "asp.net_sessionid")),
    ("server", "nginx", ("server: nginx",)),
    ("server", "Apache", ("server: apache",)),
    # ---- BaaS / managed backend (the vibe-coder default — high branching value) ----
    ("baas", "Supabase", ("supabase.co", "supabase.io", "supabaseurl", "/rest/v1/", "/auth/v1/")),
    ("baas", "Firebase", ("firebaseio.com", "firebaseapp.com", "identitytoolkit.googleapis")),
    ("baas", "Appwrite", ("appwrite", "/v1/account")),
    ("baas", "PocketBase", ("/api/collections/", "pocketbase")),
    # ---- hosting / CDN ----
    ("hosting", "Cloudflare", ("server: cloudflare", "cf-ray:", "cf-cache-status")),
    ("hosting", "Vercel", ("x-vercel-", "server: vercel")),
    ("hosting", "Netlify", ("x-nf-request-id", "server: netlify")),
    ("hosting", "Fastly", ("x-served-by: cache", "x-fastly")),
    ("hosting", "AWS CloudFront", ("x-amz-cf-id", "via: 1.1 cloudfront")),
    ("hosting", "GitHub Pages", ("server: github.com",)),
    # ---- payments (unlocks webhook_sig_probe) ----
    # NOTE: a bare `pk_live_`/`pk_test_` is NOT a Stripe signal — Clerk publishable keys
    # use the SAME `pk_live_<base64-domain>` format, so keying on it false-detects Stripe on
    # every Clerk site — a Clerk `pk_live_<base64>` key base64-decodes to the site's
    # `clerk.<domain>` frontend host, and such sites ship no js.stripe.com. Rely on the
    # unambiguous Stripe HOSTS instead.
    ("payment", "Stripe", ("js.stripe.com", "stripe.com/v3", "checkout.stripe.com",
                           "api.stripe.com", "m.stripe.network", "hooks.stripe.com")),
    ("payment", "Paddle", ("cdn.paddle.com", "paddlejs")),
    ("payment", "Lemon Squeezy", ("lemonsqueezy",)),
    # ---- auth providers ----
    # Clerk keys are `pk_live_<base64(frontend-domain)>`; a clerk.* frontend domain
    # base64-encodes to a `y2xlcm…` prefix, a reliable literal signal (and the reason a
    # bare pk_live_ must NOT count as Stripe — see the Stripe rule).
    ("auth", "Clerk", ("clerk.com", "clerk.accounts.dev", "__clerk", "clerk-db-jwt",
                       "@clerk/", "pk_live_y2xlcm", "pk_test_y2xlcm")),
    ("auth", "Auth0", ("cdn.auth0.com", ".auth0.com/authorize")),
    ("auth", "NextAuth", ("next-auth.session-token", "/api/auth/callback/")),
)


def _corpus(headers: dict, body: str, cookies, js_urls) -> str:
    parts: list[str] = []
    for k, v in (headers or {}).items():
        parts.append(f"{str(k).lower()}: {str(v).lower()}")
    for c in cookies or ():
        parts.append(str(c).lower())
    for u in js_urls or ():
        parts.append(str(u).lower())
    parts.append((body or "")[:_BODY_CAP].lower())
    return "\n".join(parts)


def fingerprint(
    status: int,
    headers: dict | None = None,
    body: str = "",
    cookies=(),
    js_urls=(),
) -> Fingerprint:
    """Detect technologies from a fetched response via structural signals only.

    ``status`` is accepted for interface symmetry with the other recon analyzers
    (and future status-conditional signals) but no rule keys off it today.
    """
    corpus = _corpus(headers or {}, body, cookies, js_urls)
    dets: list[Detection] = []
    seen: set[str] = set()
    for category, name, signals in _RULES:
        if name in seen:
            continue
        for sig in signals:
            if sig in corpus:
                dets.append(Detection(category, name, sig))
                seen.add(name)
                break
    return Fingerprint(dets)
