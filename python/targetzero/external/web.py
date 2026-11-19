# SPDX-License-Identifier: Apache-2.0
"""A minimal HTTP(S) probe: one GET, no redirects, TLS details kept.

Used by the WAF, enrichment and dangling-DNS checks. It can connect to a given
address while sending a different Host / SNI name, which is how a website's
origin server is tested behind a CDN.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field

from targetzero.external.http import USER_AGENT

MAX_BYTES = 65536


@dataclass
class Tls:
    version: str = ""
    verified: bool = False
    issuer: str = ""
    not_after: str = ""
    error: str = ""


@dataclass
class Response:
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    tls: Tls | None = None
    error: str = ""


def _issuer(cert: dict[str, object]) -> str:
    parts = []
    for rdn in cert.get("issuer", ()):  # type: ignore[attr-defined]
        for key, value in rdn:
            if key in ("organizationName", "commonName"):
                parts.append(str(value))
    return ", ".join(parts)


def _wrap(sock: socket.socket, host: str, verify: bool) -> ssl.SSLSocket:
    context = ssl.create_default_context()
    if not verify:
        # Second attempt only, to read headers of a site whose certificate is invalid.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(sock, server_hostname=host)


def get(
    host: str,
    *,
    port: int = 443,
    use_tls: bool = True,
    connect_to: str | None = None,
    timeout: float = 8.0,
    path: str = "/",
) -> Response:
    """GET http(s)://host/path, optionally connecting to another address (origin tests)."""
    response = Response()
    address = connect_to or host
    tls: Tls | None = Tls() if use_tls else None
    for verify in (True, False) if use_tls else (False,):
        try:
            raw = socket.create_connection((address, port), timeout=timeout)
        except OSError as exc:
            response.error = f"connect: {exc}"
            return response
        try:
            sock: socket.socket = raw
            if tls is not None:
                try:
                    sock = _wrap(raw, host, verify)
                except ssl.SSLCertVerificationError as exc:
                    raw.close()
                    tls.error = exc.verify_message or str(exc)
                    continue
                tls.version = sock.version() or ""
                tls.verified = verify
                cert = sock.getpeercert() if verify else None
                if cert:
                    tls.issuer = _issuer(cert)  # type: ignore[arg-type]
                    tls.not_after = str(cert.get("notAfter", ""))
            request = (
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
                "Accept: */*\r\nConnection: close\r\n\r\n"
            )
            sock.sendall(request.encode())
            data = b""
            while len(data) < MAX_BYTES:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data += chunk
        except (OSError, ssl.SSLError) as exc:
            response.error = f"{type(exc).__name__}: {exc}"
            return response
        finally:
            raw.close()
        _parse(data, response)
        response.tls = tls
        return response
    response.tls = tls
    response.error = response.error or "TLS handshake failed"
    return response


def _parse(data: bytes, response: Response) -> None:
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split(" ", 2)
        response.status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep:
            response.headers[key.strip().lower()] = value.strip()
    response.body = body.decode("utf-8", errors="replace")
