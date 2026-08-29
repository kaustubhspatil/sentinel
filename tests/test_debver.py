"""Tests for Debian version comparison.

Cases are taken from Debian Policy §5.6.12 and from dpkg's own test suite, plus real
Ubuntu security-update versions, because the failure mode this guards against is silent:
a wrong comparison produces a plausible-looking exposure count that is simply false.
"""
from __future__ import annotations

import pytest

from sentinel.util.debver import compare, is_older, parse


@pytest.mark.parametrize(
    "lower,higher",
    [
        # Ordinary numeric ordering
        ("1.0", "1.1"),
        ("1.9", "1.10"),
        ("2.2", "10.0"),
        # Leading zeros are insignificant
        ("1.007", "1.8"),
        # Revisions
        ("1.0-1", "1.0-2"),
        ("1.0-1", "1.0-10"),
        # Epochs dominate everything
        ("2.0", "1:1.0"),
        ("1:1.0", "2:0.1"),
        # '~' sorts before end-of-string: pre-releases and backports
        ("1.0~rc1", "1.0"),
        ("1.0~beta", "1.0~rc1"),
        ("1.0-1~bpo12+1", "1.0-1"),
        # Letters sort before other characters
        ("1.0a", "1.0b"),
        ("1.0a", "1.0+"),
        # Real Ubuntu security updates
        ("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5"),
        ("1:9.6p1-3ubuntu13.5", "1:9.6p1-3ubuntu13.11"),
        ("2.43-1ubuntu2.3", "2.43-1ubuntu2.4"),
    ],
)
def test_ordering(lower: str, higher: str) -> None:
    assert compare(lower, higher) == -1
    assert compare(higher, lower) == 1
    assert is_older(lower, higher)
    assert not is_older(higher, lower)


@pytest.mark.parametrize(
    "version",
    ["1.0", "1.0-1", "1:1.0-1", "1.0~rc1", "3.0.13-0ubuntu3.4"],
)
def test_equality(version: str) -> None:
    assert compare(version, version) == 0
    assert not is_older(version, version)


def test_absent_epoch_equals_zero() -> None:
    assert compare("0:1.0", "1.0") == 0


def test_trailing_hyphen_is_invalid() -> None:
    """An empty revision is malformed, not equivalent to having no revision.

    Folding it into the upstream version would make "1.0-" compare as *older* than
    "1.0", which is the kind of quiet wrongness this module exists to avoid.
    """
    with pytest.raises(ValueError):
        parse("1.0-")


@pytest.mark.parametrize(
    "version,expected",
    [
        ("1.0", (0, "1.0", "")),
        ("1:2.3-4", (1, "2.3", "4")),
        ("2.43-1ubuntu2.4", (0, "2.43", "1ubuntu2.4")),
        # Upstream versions may themselves contain hyphens; the last one wins.
        ("1.0-beta-3", (0, "1.0-beta", "3")),
    ],
)
def test_parse(version: str, expected: tuple[int, str, str]) -> None:
    assert parse(version) == expected


def test_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        parse("1:2:3")


def test_not_older_when_patched() -> None:
    """The case the vulnerability matcher actually asks about."""
    assert not is_older("3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3.4")
    assert is_older("3.0.13-0ubuntu3.3", "3.0.13-0ubuntu3.4")
