"""`playwright_probe` must actually hand Chromium the pinning proxy.

Chromium resolves DNS itself, so the ONLY thing that keeps a rebound in-scope subdomain
away from an internal address is the browser being launched behind the loopback proxy.
A proxy that is built but never passed to `launch()` protects nothing, so this fakes the
Playwright chain and asserts on the launch arguments.
"""

from __future__ import annotations

import asyncio
import sys
import types

from kuv.recon.browser import playwright_probe


class _Page:
    def __init__(self):
        self.goto_urls: list[str] = []

    def on(self, *_a, **_k):
        pass

    async def goto(self, url, **_k):
        self.goto_urls.append(url)

    async def wait_for_timeout(self, _ms):
        pass

    async def title(self):
        return "t"

    async def content(self):
        return "<html></html>"


class _Context:
    def __init__(self, kwargs):
        self.kwargs = kwargs
        self.page = _Page()

    async def add_init_script(self, _s):
        pass

    async def route(self, _pattern, _handler):
        pass

    async def new_page(self):
        return self.page


class _Browser:
    def __init__(self, record):
        self._record = record
        self.context: _Context | None = None

    async def new_context(self, **kwargs):
        self.context = _Context(kwargs)
        return self.context

    async def close(self):
        pass


class _Chromium:
    def __init__(self, record):
        self._record = record

    async def launch(self, **kwargs):
        self._record["launch"] = kwargs
        return _Browser(self._record)


class _PW:
    def __init__(self, record):
        self.chromium = _Chromium(record)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False


def _install_fake_playwright(monkeypatch) -> dict:
    record: dict = {}
    module = types.ModuleType("playwright.async_api")
    module.async_playwright = lambda: _PW(record)
    parent = types.ModuleType("playwright")
    parent.async_api = module
    monkeypatch.setitem(sys.modules, "playwright", parent)
    monkeypatch.setitem(sys.modules, "playwright.async_api", module)
    return record


def _gate(_method, _url):
    return True, "in scope"


def test_probe_launches_chromium_behind_the_proxy_when_one_is_given(monkeypatch):
    record = _install_fake_playwright(monkeypatch)

    asyncio.run(
        playwright_probe(
            "https://example.com/", gate=_gate, timeout=1.0, max_requests=5,
            proxy_url="http://127.0.0.1:54321",
        )
    )

    assert record["launch"]["proxy"] == {"server": "http://127.0.0.1:54321"}


def test_probe_without_a_proxy_launches_unproxied(monkeypatch):
    """Fixtures render loopback targets, which the pin would refuse outright."""
    record = _install_fake_playwright(monkeypatch)

    asyncio.run(
        playwright_probe("http://127.0.0.1:8779/", gate=_gate, timeout=1.0, max_requests=5)
    )

    assert "proxy" not in record["launch"]


def test_proxied_launch_keeps_the_dns_prefetch_hardening(monkeypatch):
    """The proxy is additive — it must not quietly drop the existing launch flags."""
    record = _install_fake_playwright(monkeypatch)

    asyncio.run(
        playwright_probe(
            "https://example.com/", gate=_gate, timeout=1.0, max_requests=5,
            proxy_url="http://127.0.0.1:54321",
        )
    )

    assert "--dns-prefetch-disable" in record["launch"]["args"]
