"""Fetch Ubuntu Security Notices.

USNs are the authoritative answer to the question the graph actually needs: for this
release, which package version fixed this CVE. That is what turns "a package named
openssl is installed" into "the installed openssl predates the fix for CVE-x", which
are different claims with very different operational meaning.

Free, unauthenticated, and paginated.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import httpx

from sentinel.config import settings

NOTICES_URL = "https://ubuntu.com/security/notices.json"
PAGE = 100
TIMEOUT = httpx.Timeout(60.0, connect=15.0)


@dataclass(frozen=True)
class UsnFetch:
    release: str
    notices: int
    path: Path


def fetch(release: str = "noble", out_dir: Path | None = None) -> UsnFetch:
    out_dir = out_dir or settings.raw_dir
    collected: list[dict] = []
    offset = 0

    with httpx.Client(timeout=TIMEOUT, follow_redirects=True,
                      headers={"User-Agent": "sentinel/0.1"}) as c:
        while True:
            r = c.get(NOTICES_URL, params={"limit": PAGE, "offset": offset, "release": release})
            r.raise_for_status()
            payload = r.json()
            batch = payload.get("notices", [])
            if not batch:
                break
            collected.extend(batch)
            offset += PAGE
            if offset >= int(payload.get("total_results", 0)):
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
    return UsnFetch(release, len(slim), path)


if __name__ == "__main__":
    res = fetch()
    pkgs = sum(len(n["packages"]) for n in json.loads(res.path.read_text(encoding="utf-8")))
    print(f"{res.release}: {res.notices:,} notices, {pkgs:,} package fixes -> {res.path.name}")
