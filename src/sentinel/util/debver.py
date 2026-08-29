"""Debian/Ubuntu package version comparison.

Implemented directly rather than pulled from python-debian, because this is the single
function the whole vulnerability-matching claim rests on: "is the installed version older
than the version that fixed this CVE". Get it wrong and every exposure number is wrong,
in a way no amount of graph modelling would reveal.

Follows Debian Policy §5.6.12. A version is:

    [epoch:]upstream_version[-debian_revision]

Comparison walks each part alternating between non-digit and digit runs. Within a
non-digit run, characters sort by a modified ordering where '~' sorts *before* the end
of string - which is what makes 1.0~rc1 correctly older than 1.0, the case that matters
most in practice because it is how pre-releases and backports are numbered.
"""
from __future__ import annotations

import re

_VERSION_RE = re.compile(
    r"^(?:(?P<epoch>\d+):)?(?P<upstream>[^:-]*(?:-[^:-]*)*?)(?:-(?P<revision>[^:-]+))?$"
)


def _order(char: str) -> int:
    """Sort weight for a single non-digit character.

    '~' sorts before everything, including the end of a string. Letters sort before
    all other characters. Everything else sorts by ASCII, offset past the letters.
    """
    if char == "~":
        return -1
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _compare_part(a: str, b: str) -> int:
    """Compare one version part (upstream or revision) using the dpkg algorithm."""
    ia = ib = 0
    while ia < len(a) or ib < len(b):
        # Non-digit run.
        first_diff = 0
        while (ia < len(a) and not a[ia].isdigit()) or (ib < len(b) and not b[ib].isdigit()):
            ca = _order(a[ia]) if ia < len(a) and not a[ia].isdigit() else 0
            cb = _order(b[ib]) if ib < len(b) and not b[ib].isdigit() else 0
            if ca != cb:
                first_diff = ca - cb
                break
            if ia < len(a) and not a[ia].isdigit():
                ia += 1
            if ib < len(b) and not b[ib].isdigit():
                ib += 1
        if first_diff:
            return 1 if first_diff > 0 else -1

        # Digit run. Leading zeros are insignificant, so compare numerically.
        sa = ia
        while ia < len(a) and a[ia].isdigit():
            ia += 1
        sb = ib
        while ib < len(b) and b[ib].isdigit():
            ib += 1
        na = int(a[sa:ia] or "0")
        nb = int(b[sb:ib] or "0")
        if na != nb:
            return 1 if na > nb else -1

    return 0


def parse(version: str) -> tuple[int, str, str]:
    """Split a version into (epoch, upstream, revision)."""
    v = version.strip()
    # A trailing hyphen means an empty revision, which Debian treats as invalid rather
    # than as "no revision". Rejecting it keeps a malformed version out of the matcher
    # instead of letting it compare as something plausible.
    if v.endswith("-") or v.endswith(":"):
        raise ValueError(f"invalid Debian version (empty component): {version!r}")
    m = _VERSION_RE.match(v)
    if not m or not (m.group("upstream") or ""):
        raise ValueError(f"unparseable Debian version: {version!r}")
    return (
        int(m.group("epoch") or 0),
        m.group("upstream") or "",
        m.group("revision") or "",
    )


def compare(a: str, b: str) -> int:
    """Return -1 if a < b, 0 if equal, 1 if a > b."""
    ea, ua, ra = parse(a)
    eb, ub, rb = parse(b)
    if ea != eb:
        return 1 if ea > eb else -1
    if (c := _compare_part(ua, ub)) != 0:
        return c
    return _compare_part(ra, rb)


def is_older(installed: str, fixed: str) -> bool:
    """True when the installed version predates the version that fixed an issue."""
    return compare(installed, fixed) < 0
