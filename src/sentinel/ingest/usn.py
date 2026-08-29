"""Fetch Ubuntu Security Notices.

USNs are the authoritative answer to the question the graph actually needs: for this
release, which package version fixed this CVE. That is what turns "a package named
openssl is installed" into "the installed openssl predates the fix for CVE-x", which
are different claims with very different operational meaning.

Free, unauthenticated, and paginated.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from sentinel.config import settings

NOTICES_URL = "https://ubuntu.com/security/notices.json"
# The API caps page size at 20 and returns 422 above it.
PAGE = 20
TIMEOUT = httpx.Timeout(60.0, connect=15.0)
RETRYABLE = {429, 500, 502, 503, 504}


@dataclass
class UsnFetch:
    release: str
    notices: int
    path: Path
    missed_offsets: list[int]


def _get_page(client: httpx.Client, release: str, offset: int) -> dict | None:
    """One page, retried with backoff. Returns None if the page never succeeds.

    The service is free and occasionally returns 502/504 under load. Retrying is worth
    it; failing the whole run after 45 successful pages is not.
    """
    delay = 1.0
    for attempt in range(5):
        try:
            r = client.get(
                NOTICES_URL, params={"limit": PAGE, "offset": offset, "release": release}
            )
            if r.status_code in RETRYABLE:
                raise httpx.HTTPStatusError("retryable", request=r.request, response=r)
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPStatusError, httpx.TransportError):
            if attempt == 4:
                return None
            time.sleep(delay)
            delay *= 2
    return None


def fetch(release: str = "noble", out_dir: Path | None = None) -> UsnFetch:
    out_dir = out_dir or settings.raw_dir
    collected: list[dict] = []
    missed: list[int] = []
    offset = 0
    total = None

    with httpx.Client(timeout=TIMEOUT, follow_redirects=True,
                      headers={"User-Agent": "sentinel/0.1"}) as c:
        while True:
            payload = _get_page(c, release, offset)
            if payload is None:
                # Record the gap and keep going: a partial catalogue with a known
                # hole is far more useful than no catalogue, as long as the hole is
                # reported rather than hidden.
                missed.append(offset)
                offset += PAGE
                if total is not None and offset >= total:
                    break
                continue
            if total is None:
                total = int(payload.get("total_results", 0))
            batch = payload.get("notices", [])
            if not batch:
                break
            collected.extend(batch)
            offset += PAGE
            time.sleep(0.2)
            if offset >= (total or 0):
                break

    # Keep only what the matcher needs. The full notices carry long prose descriptions
    # that would triple the file for no downstream use.
    slim = [
        {
            "id": n.get("id"),
            "published": n.get("published"),
            "cves": n.get("cves_ids") or [],
            "packages": [
                {
                    "name": p.get("name"),
                    "version": p.get("version"),
                    "is_source": bool(p.get("is_source")),
                }
                for p in (n.get("release_packages") or {}).get(release, [])
                if p.get("name") and p.get("version")
            ],
        }
        for n in collected
    ]

    path = out_dir / f"usn_{release}.json"
    path.write_text(json.dumps(slim), encoding="utf-8")
    return UsnFetch(release, len(slim), path, missed)


if __name__ == "__main__":
    res = fetch()
    pkgs = sum(len(n["packages"]) for n in json.loads(res.path.read_text(encoding="utf-8")))
    print(f"{res.release}: {res.notices:,} notices, {pkgs:,} package fixes -> {res.path.name}")
    if res.missed_offsets:
        print(f"  WARNING: {len(res.missed_offsets)} page(s) unretrievable at offsets "
              f"{res.missed_offsets} - catalogue is incomplete")
