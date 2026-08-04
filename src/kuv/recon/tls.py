"""TLS validation — cert validity / expiry / hostname / protocol over an injected prober.

Was deferred; added to give the transport-posture assessment real teeth. A verifying
handshake decides validity/hostname/expiry; an unverified handshake still negotiates a
protocol version even when the chain is untrusted, so an expired or self-signed cert is
characterized rather than just erroring out. The prober is injected so the core is
testable; production uses stdlib `ssl` (no third-party dependency)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class TlsResult:
    reachable: bool
    valid_chain: bool               # verifying handshake succeeded
    hostname_match: bool
    expired: bool
    self_signed: bool
    days_to_expiry: int | None
    protocol: str | None            # e.g. "TLSv1.2", "TLSv1.3"
    issuer: str | None              # issuer CN only (no key material)
    gaps: tuple[str, ...]


class TlsProbe(Protocol):
    def __call__(self, host: str, *, port: int, timeout: float) -> TlsResult: ...


_OBSOLETE_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})


def verdict_gaps(
    *,
    reachable: bool,
    valid_chain: bool,
    hostname_match: bool,
    expired: bool,
    self_signed: bool,
    protocol: str | None,
) -> tuple[str, ...]:
    """Deterministic gap list from the raw cert facts (shared by real + fake probes)."""
    if not reachable:
        return ("TLS handshake failed — host unreachable on 443",)
    gaps: list[str] = []
    if expired:
        gaps.append("certificate is expired")
    if self_signed:
        gaps.append("certificate is self-signed / untrusted chain")
    if not hostname_match:
        gaps.append("certificate hostname does not match")
    if not valid_chain and not (expired or self_signed or not hostname_match):
        gaps.append("certificate chain did not verify")
    if protocol in _OBSOLETE_PROTOCOLS:
        gaps.append(f"obsolete TLS protocol negotiated ({protocol})")
    return tuple(gaps)


def _issuer_cn(cert: dict) -> str | None:
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def _days_to_expiry(cert: dict) -> int | None:
    import ssl
    from datetime import datetime, timezone

    not_after = cert.get("notAfter")
    if not not_after:
        return None
    try:
        ts = ssl.cert_time_to_seconds(not_after)
        return int((datetime.fromtimestamp(ts, timezone.utc) - datetime.now(timezone.utc)).days)
    except Exception:  # noqa: BLE001
        return None


def _verifying_context():
    """A verifying TLS context with a REAL trust store, plus whether one was loaded.

    The stdlib default context can be EMPTY on some Python builds (e.g. a python.org
    macOS install where 'Install Certificates.command' was never run) — 0 CA roots make
    EVERY cert fail to verify, a systemic false positive that would flag every site as
    `insecure_tls`. So if the default store is empty we fall back to certifi (which httpx
    already relies on). Returns (ctx, has_trust_store); has_trust_store is False only when
    NO roots could be loaded at all, in which case chain validity is simply not assessable.
    """
    import ssl

    ctx = ssl.create_default_context()
    if ctx.cert_store_stats().get("x509_ca", 0) == 0:
        try:
            import certifi

            ctx.load_verify_locations(certifi.where())
        except Exception:  # noqa: BLE001 — certifi absent; trust store stays empty
            pass
    has_trust = ctx.cert_store_stats().get("x509_ca", 0) > 0
    _lower_minimum_version(ctx)
    return ctx, has_trust


def _lower_minimum_version(ctx) -> None:
    """Allow legacy TLS versions to be negotiated so ss.version() can actually REPORT
    an obsolete protocol (a default context floors at 1.2, hiding 1.0/1.1)."""
    import ssl

    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (ValueError, OSError, AttributeError):  # pragma: no cover — old/locked-down OpenSSL
        pass


def _negotiated_protocol(host: str, port: int, timeout: float) -> str | None:
    """Protocol version from an UNVERIFIED handshake (works even for a bad cert)."""
    import socket
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    _lower_minimum_version(ctx)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.version()
    except Exception:  # noqa: BLE001
        return None


def ssl_tls_probe(host: str, *, port: int = 443, timeout: float = 8.0) -> TlsResult:
    """Production TLS prober (stdlib only)."""
    import socket
    import ssl

    valid_chain = True
    hostname_match = True
    expired = False
    self_signed = False
    issuer: str | None = None
    days_to_expiry: int | None = None
    protocol: str | None = None

    ctx, has_trust = _verifying_context()
    if not has_trust:
        # No CA roots anywhere → chain validity is NOT assessable in this environment.
        # Do NOT false-positive `insecure_tls`; report reachability + protocol only.
        proto = _negotiated_protocol(host, port, timeout)
        return TlsResult(
            reachable=proto is not None, valid_chain=True, hostname_match=True,
            expired=False, self_signed=False, days_to_expiry=None, protocol=proto,
            issuer=None,
            gaps=verdict_gaps(reachable=proto is not None, valid_chain=True,
                              hostname_match=True, expired=False, self_signed=False,
                              protocol=proto),
        )
    try:
        # Verify the cert/hostname while ALLOWING legacy protocols, so an old TLS version
        # is not misreported as a cert-chain failure — protocol is judged separately.
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                protocol = ss.version()
                cert = ss.getpeercert() or {}
                issuer = _issuer_cn(cert)
                days_to_expiry = _days_to_expiry(cert)
    except ssl.SSLCertVerificationError as exc:
        valid_chain = False
        reason = f"{exc}".lower()
        expired = "expired" in reason
        self_signed = "self signed" in reason or "self-signed" in reason
        hostname_match = not any(
            phrase in reason
            for phrase in ("hostname mismatch", "doesn't match", "ip address mismatch", "not valid for")
        )
    except ssl.SSLError:
        valid_chain = False
    except (socket.timeout, OSError):
        return TlsResult(
            reachable=False, valid_chain=False, hostname_match=False, expired=False,
            self_signed=False, days_to_expiry=None, protocol=None, issuer=None,
            gaps=verdict_gaps(reachable=False, valid_chain=False, hostname_match=False,
                              expired=False, self_signed=False, protocol=None),
        )

    if protocol is None:
        protocol = _negotiated_protocol(host, port, timeout)
    return TlsResult(
        reachable=True,
        valid_chain=valid_chain,
        hostname_match=hostname_match,
        expired=expired,
        self_signed=self_signed,
        days_to_expiry=days_to_expiry,
        protocol=protocol,
        issuer=issuer,
        gaps=verdict_gaps(reachable=True, valid_chain=valid_chain, hostname_match=hostname_match,
                          expired=expired, self_signed=self_signed, protocol=protocol),
    )
