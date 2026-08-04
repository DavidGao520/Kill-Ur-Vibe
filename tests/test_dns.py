"""Tests for DNS recon (subdomain enum, dangling-CNAME, email auth) with a fake resolver."""

from __future__ import annotations

from kuv.recon import email_auth, enumerate_subdomains, is_takeover, takeover_suffix


def _resolver(records):
    def resolve(name, rrtype):
        return list(records.get((name, rrtype), []))
    return resolve


def test_enumerate_finds_live_hosts_and_skips_missing():
    records = {
        ("www.example.com", "A"): ["1.2.3.4"],
        ("app.example.com", "A"): ["5.6.7.8"],
        # everything else in the wordlist resolves to nothing
    }
    hosts = enumerate_subdomains("example.com", _resolver(records))
    names = {h.name for h in hosts}
    assert names == {"www.example.com", "app.example.com"}
    assert all(h.dangling is False for h in hosts)


def test_dangling_cname_flags_takeover():
    records = {
        # gateway has a CNAME to Render but NO A record -> dangling/takeover-able
        ("gateway.example.com", "CNAME"): ["kuv-app.onrender.com."],
    }
    hosts = enumerate_subdomains("example.com", _resolver(records))
    dead = [h for h in hosts if h.name == "gateway.example.com"][0]
    assert dead.dangling is True
    assert dead.takeover_service == "onrender.com"


def test_cname_with_live_a_record_is_not_dangling():
    records = {
        ("app.example.com", "CNAME"): ["app.herokuapp.com."],
        ("app.example.com", "A"): ["9.9.9.9"],   # still resolves -> not dangling
    }
    hosts = enumerate_subdomains("example.com", _resolver(records))
    app = [h for h in hosts if h.name == "app.example.com"][0]
    assert app.dangling is False


def test_takeover_suffix_matches_known_services():
    assert takeover_suffix("myapp.onrender.com.") == "onrender.com"
    assert takeover_suffix("x.herokuapp.com") == "herokuapp.com"
    assert takeover_suffix("cdn.example.com") is None
    assert takeover_suffix(None) is None


def test_is_takeover_from_fingerprint_or_status():
    assert is_takeover("onrender.com", 200, "...x-render-routing: no-server...") is True
    assert is_takeover("github.io", 200, "There isn't a GitHub Pages site here.") is True
    assert is_takeover("onrender.com", 404, "") is True          # dead-app status
    assert is_takeover("onrender.com", 200, "<html>live app</html>") is False


def test_email_auth_dmarc_policy():
    reject = _resolver({("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:x@example.com"],
                        ("example.com", "TXT"): ["v=spf1 include:_spf.google.com ~all"]})
    out = email_auth("example.com", reject)
    assert out["dmarc_present"] and out["dmarc_policy"] == "reject" and out["dmarc_enforced"] is True
    assert out["spf_present"] is True

    nonep = _resolver({("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"]})
    out2 = email_auth("example.com", nonep)
    assert out2["dmarc_policy"] == "none" and out2["dmarc_enforced"] is False
    assert out2["spf_present"] is False
