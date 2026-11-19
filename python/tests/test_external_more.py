# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import http.server
import ipaddress
import socketserver
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from targetzero.external import dangling, dnsinfo, enrich, waf, web
from targetzero.external.scope import Scope


@pytest.fixture
def server() -> Iterator[int]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = f"host={self.headers['Host']} NoSuchBucket".encode()
            self.send_response(200)
            self.send_header("Server", "nginx/1.24.0")
            self.send_header("X-Powered-By", "PHP/8.1.2")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    class Server(http.server.HTTPServer):
        def server_bind(self) -> None:
            # Skip HTTPServer's reverse DNS lookup of the address, which can take seconds.
            socketserver.TCPServer.server_bind(self)
            self.server_name, self.server_port = "localhost", self.server_address[1]

    httpd = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1]
    httpd.shutdown()


def test_web_get_sends_host_to_another_address(server: int) -> None:
    response = web.get("shop.example.com", port=server, use_tls=False, connect_to="127.0.0.1")
    assert response.status == 200
    assert response.headers["server"] == "nginx/1.24.0"
    assert "host=shop.example.com" in response.body


def test_web_get_reports_connection_errors() -> None:
    response = web.get("127.0.0.1", port=1, use_tls=False, timeout=1)
    assert response.status == 0 and response.error.startswith("connect")


def test_provider_for() -> None:
    ranges = {"Cloudflare": [ipaddress.ip_network("104.16.0.0/13")]}
    assert waf.provider_for(dnsinfo.Lookup("a", ips=["104.16.1.1"]), ranges) == "Cloudflare"
    assert (
        waf.provider_for(dnsinfo.Lookup("a", ips=["203.0.113.5"], cnames=["x.edgekey.net"]), ranges)
        == "Akamai"
    )
    assert waf.provider_for(dnsinfo.Lookup("a", ips=["203.0.113.5"]), ranges) == ""


def test_waf_check(monkeypatch: pytest.MonkeyPatch) -> None:
    lookups = {
        "www.example.com": dnsinfo.Lookup("www.example.com", ips=["104.16.1.1"]),
        "app.example.com": dnsinfo.Lookup("app.example.com", ips=["203.0.113.5"]),
        "mail.example.com": dnsinfo.Lookup("mail.example.com", ips=["203.0.113.6"]),
    }
    monkeypatch.setattr(waf.dnsinfo, "lookup", lambda name, res: lookups[name])
    monkeypatch.setattr(waf, "is_web", lambda name: name != "mail.example.com")
    monkeypatch.setattr(waf, "origin_reachable", lambda name, ip: True)
    scope = Scope(domains=("example.com",), networks=(ipaddress.ip_network("203.0.113.0/29"),))
    records, items, _ = waf.check(
        sorted(lookups),
        {"Cloudflare": [ipaddress.ip_network("104.16.0.0/13")]},
        {"www.example.com": "203.0.113.4"},
        scope,
        test_origins=True,
    )
    assert {i["id"] for i in items} == {
        "external:app.example.com/no-waf",
        "external:www.example.com/origin-reachable",
    }
    assert {r["name"]: r["result"] for r in records}["mail.example.com"] == "no web service"


def test_dangling(monkeypatch: pytest.MonkeyPatch, server: int) -> None:
    targets = {
        "old.example.com": "gone.azurewebsites.net",
        "files.example.com": "bucket.s3.amazonaws.com",
        "www.example.com": "",
    }
    monkeypatch.setattr(dangling.dnsinfo, "cname_target", lambda name, res: targets[name])
    monkeypatch.setattr(
        dangling.dnsinfo,
        "lookup",
        lambda name, res: dnsinfo.Lookup(
            name,
            ips=[] if name.startswith("gone") else ["127.0.0.1"],
            nxdomain=name.startswith("gone"),
        ),
    )
    real_get = web.get
    monkeypatch.setattr(
        dangling.web,
        "get",
        lambda name, **kw: real_get(name, port=server, use_tls=False, connect_to="127.0.0.1"),
    )
    assert dangling.check_name("www.example.com", None) is None
    old = dangling.check_name("old.example.com", None)
    assert old is not None and old["result"] == "dangling" and "does not resolve" in old["evidence"]
    files = dangling.check_name("files.example.com", None)
    assert files is not None and files["service"] == "Amazon S3" and files["result"] == "dangling"


def test_enrich_parsing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert enrich.products_from_headers(
        {"server": "Apache/2.4.57 (Ubuntu)", "x-powered-by": "PHP/7.4.33"}
    ) == [("apache", "2.4.57"), ("php", "7.4.33")]
    assert enrich.products_from_cpes(["cpe:/a:nginx:nginx:1.18.0"]) == [("nginx", "1.18.0")]
    cycles = [
        {"cycle": "8.1", "eol": "2025-12-31"},
        {"cycle": "8.3", "eol": "2027-12-31"},
        {"cycle": "7.4", "eol": True},
    ]
    monkeypatch.setattr(enrich, "cached_json", lambda *a, **k: cycles)
    assert enrich.support_status("php", "8.3.1", tmp_path) == ("Y", "2027-12-31")
    assert enrich.support_status("php", "8.1.2", tmp_path) == ("N", "2025-12-31")
    assert enrich.support_status("php", "7.4.33", tmp_path) == ("N", "")
    assert enrich.support_status("unknown-thing", "1.0", tmp_path) == ("?", "")
