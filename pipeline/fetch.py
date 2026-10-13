"""Read the sensor's log blobs from Azure Storage with an Entra ID token.

In GitHub Actions the token comes from `az` after azure/login exchanged the
workflow's OIDC token for the reader identity, so the repo holds no secret.
Locally, `az login` with your own account works the same way.
"""
from __future__ import annotations

import subprocess
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

API_VERSION = "2023-11-03"


def access_token() -> str:
    result = subprocess.run(
        ["az", "account", "get-access-token", "--resource", "https://storage.azure.com/",
         "--query", "accessToken", "-o", "tsv"],
        check=True, capture_output=True, text=True)
    return result.stdout.strip()


class BlobContainer:
    def __init__(self, account: str, container: str, token: str) -> None:
        self.base = f"https://{account}.blob.core.windows.net/{container}"
        self.headers = {"Authorization": f"Bearer {token}", "x-ms-version": API_VERSION}

    def _get(self, url: str) -> bytes:
        req = urllib.request.Request(url, headers=self.headers)
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.read()

    def list(self, prefix: str) -> list[dict]:
        """All blobs under prefix as {name, etag, size}, following pagination."""
        blobs, marker = [], ""
        while True:
            query = {"restype": "container", "comp": "list", "prefix": prefix}
            if marker:
                query["marker"] = marker
            root = ET.fromstring(self._get(f"{self.base}?{urllib.parse.urlencode(query)}"))
            for blob in root.iter("Blob"):
                props = blob.find("Properties")
                blobs.append({
                    "name": blob.findtext("Name", ""),
                    "etag": props.findtext("Etag", "") if props is not None else "",
                    "size": int(props.findtext("Content-Length", "0")) if props is not None else 0,
                })
            marker = root.findtext("NextMarker") or ""
            if not marker:
                return blobs

    def download(self, name: str) -> bytes:
        return self._get(f"{self.base}/{urllib.parse.quote(name)}")
