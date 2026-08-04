"""The registrable-domain (eTLD+1) helper is a *security boundary*: it decides how
wide a scan's authorization scope opens. The two ways `host.split('.')[-2:]` is
wrong both authorize scanning hosts the operator never meant to touch, so both are
pinned here.
"""

from __future__ import annotations

from kuv.gate.registrable import registrable_domain


def test_plain_apex_is_itself():
    assert registrable_domain("acme.inc") == "acme.inc"
    assert registrable_domain("bigco.com") == "bigco.com"


def test_subdomain_collapses_to_registrable():
    # The app case: email-auth lives on the apex, not the typed subdomain.
    assert registrable_domain("app.bigco.com") == "bigco.com"
    assert registrable_domain("api.acme.inc") == "acme.inc"
    assert registrable_domain("sub.deep.example.com") == "example.com"


def test_multi_label_public_suffix_is_not_over_scoped():
    # last-2-labels would return 'co.uk' here → '*.co.uk' authorizes the entire UK
    # commercial namespace. The PSL keeps the registrable part.
    assert registrable_domain("app.foo.co.uk") == "foo.co.uk"
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"


def test_private_multitenant_suffix_stays_per_tenant():
    # vercel.app / github.io / pages.dev are PSL *private* suffixes. Without the
    # private section, these collapse to the provider and '*.vercel.app' would
    # authorize scanning every other tenant. Registrable must be the tenant host.
    assert registrable_domain("myapp.vercel.app") == "myapp.vercel.app"
    assert registrable_domain("a.b.myapp.vercel.app") == "myapp.vercel.app"
    assert registrable_domain("project.github.io") == "project.github.io"
    assert registrable_domain("site.pages.dev") == "site.pages.dev"


def test_undeterminable_returns_none_fail_closed():
    # None is the caller's signal to keep an exact-host scope — never widen.
    assert registrable_domain("localhost") is None      # single label
    assert registrable_domain("co.uk") is None          # bare public suffix
    assert registrable_domain("1.2.3.4") is None        # IPv4 literal
    assert registrable_domain("") is None
    assert registrable_domain("::1") is None            # IPv6-ish / no suffix


def test_normalizes_case_and_trailing_dot():
    assert registrable_domain("API.Acme.INC") == "acme.inc"
    assert registrable_domain("app.bigco.com.") == "bigco.com"
