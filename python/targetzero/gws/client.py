# SPDX-License-Identifier: Apache-2.0
"""Authenticated Admin SDK clients.

Two ways to sign in, picked from the credentials file:

- Service account with domain-wide delegation ("type": "service_account"):
  impersonates gws.admin_subject. Suited to scheduled runs.
- OAuth desktop client ("installed" in the file): opens a browser once and
  signs in as the admin running the script. Suited to small tenants.

Only read-only scopes are requested by the inventory commands.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from targetzero.common.config import Config, ConfigError

READ_SCOPES = (
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
    "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.reports.usage.readonly",
)


class Gws:
    """Thin wrapper so tests can replace the API with a fake."""

    def __init__(self, directory: Any, reports: Any, customer: str) -> None:
        self.directory = directory
        self.reports = reports
        self.customer = customer

    def pages(self, method: Any, key: str, **params: Any) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        token = None
        while True:
            # Some list calls (domains) do not accept pageToken at all.
            extra: dict[str, str] = {"pageToken": token} if token else {}
            response = method(**params, **extra).execute()
            items += response.get(key, [])
            token = response.get("nextPageToken")
            if not token:
                return items


def connect(config: Config, scopes: tuple[str, ...] = READ_SCOPES) -> Gws:
    try:
        from google.oauth2 import service_account
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build
    except ImportError as exc:
        raise ConfigError(
            "Google Workspace support is not installed: pip install 'targetzero[gws]'"
        ) from exc

    settings = config.data.get("gws", {})
    file = settings.get("credentials_file", "")
    if not file:
        raise ConfigError("gws.credentials_file is not set in targetzero.yaml")
    path = Path(file).expanduser()
    if not path.is_absolute():
        path = config.path.parent / path
    info = json.loads(path.read_text(encoding="utf-8"))
    credentials: Any
    if info.get("type") == "service_account":
        subject = settings.get("admin_subject", "")
        if not subject:
            raise ConfigError("gws.admin_subject is required with a service account")
        credentials = service_account.Credentials.from_service_account_info(  # type: ignore[no-untyped-call]
            info, scopes=list(scopes), subject=subject
        )
    elif "installed" in info:
        flow = InstalledAppFlow.from_client_config(info, scopes=list(scopes))
        credentials = flow.run_local_server(port=0, open_browser=True)
    else:
        raise ConfigError(f"{path} is neither a service account key nor an OAuth desktop client")
    directory = build("admin", "directory_v1", credentials=credentials, cache_discovery=False)
    reports = build("admin", "reports_v1", credentials=credentials, cache_discovery=False)
    return Gws(directory, reports, settings.get("customer_id", "my_customer"))
