"""Tests for deterministic tech-stack fingerprinting (kuv.recon.fingerprint)."""

from __future__ import annotations

from kuv.recon.fingerprint import Detection, fingerprint


def test_detects_nextjs_from_body_asset_path():
    fp = fingerprint(200, {}, body='<script src="/_next/static/chunks/main.js"></script>')
    assert fp.has("Next.js")
    assert "framework" in {d.category for d in fp.detections}


def test_detects_wordpress_from_structural_path_not_prose():
    # Structural signal → detected
    assert fingerprint(200, {}, body='<link href="/wp-content/themes/x/style.css">').has("WordPress")
    # Prose mention only → NOT detected (this is the anti-false-positive guarantee)
    assert not fingerprint(200, {}, body="We are a WordPress hosting company.").has("WordPress")


def test_detects_react_and_cra_from_root_div_and_static_bundle():
    # A Create-React-App SPA shell (a shape that came back empty before).
    body = '<div id="root"></div><script src="/static/js/main.72c47169.js"></script>'
    fp = fingerprint(200, {}, body=body)
    assert fp.has("React")
    assert fp.has("Create React App")
    # prose "we love react" must NOT trigger it
    assert not fingerprint(200, {}, body="We love react and vue frameworks.").has("React")


def test_detects_vite_from_assets_bundle():
    fp = fingerprint(200, {}, body='<script type="module" src="/assets/index-a1b2c3.js"></script>')
    assert fp.has("Vite")


def test_detects_supabase_from_js_url():
    fp = fingerprint(200, {}, body="", js_urls=["https://xyzcompany.supabase.co/rest/v1/"])
    assert fp.has("Supabase")
    assert fp.by_category("baas")


def test_detects_from_headers_cloudflare_and_stripe():
    fp = fingerprint(
        200,
        {"Server": "cloudflare", "CF-Ray": "abc123"},
        body='<script src="https://js.stripe.com/v3/"></script>',
    )
    assert fp.has("Cloudflare")
    assert fp.has("Stripe")


def test_clerk_key_is_not_misdetected_as_stripe():
    # Regression — a Clerk publishable key `pk_live_<base64-domain>` (decoding to a
    # `clerk.<domain>` host) must detect Clerk, NOT Stripe. A bare
    # `pk_live_` is shared between the two providers, so it can't be a Stripe signal.
    fp = fingerprint(
        200, {},
        body='<script>window.__clerk_publishable_key="pk_live_Y2xlcmsuZXhhbXBsZS5jb20k"</script>',
    )
    assert fp.has("Clerk")
    assert not fp.has("Stripe")


def test_real_stripe_still_detected_by_host():
    fp = fingerprint(200, {}, body='<script src="https://js.stripe.com/v3/"></script>')
    assert fp.has("Stripe")


def test_detects_from_set_cookie_names():
    fp = fingerprint(200, {}, body="", cookies=["laravel_session=abc; Path=/; HttpOnly"])
    assert fp.has("Laravel")


def test_clean_html_page_detects_nothing_spurious():
    fp = fingerprint(200, {"Server": ""}, body="<html><body><h1>Hello</h1></body></html>")
    assert fp.detections == []


def test_tags_are_stable_and_sorted():
    fp = fingerprint(
        200,
        {"Server": "Vercel"},
        body='<div id="__next"></div><script src="/_next/x.js"></script>',
    )
    tags = fp.tags()
    assert tags == sorted(tags)
    assert "framework:Next.js" in tags
    assert "hosting:Vercel" in tags


def test_each_name_detected_once_with_first_signal_as_evidence():
    # Two Next.js signals present; it should appear exactly once.
    fp = fingerprint(200, {}, body="/_next/ and __NEXT_DATA__ both present")
    nextjs = [d for d in fp.detections if d.name == "Next.js"]
    assert len(nextjs) == 1
    assert isinstance(nextjs[0], Detection)
