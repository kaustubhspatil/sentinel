"""Neo4j connection handling."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from neo4j import Driver, GraphDatabase

from sentinel.config import settings


def driver() -> Driver:
    if not settings.neo4j_password:
        raise RuntimeError(
            "NEO4J_PASSWORD is not set. On the backbone it lives in "
            "/srv/sentinel/deploy/.env; locally, tunnel to the host and export it."
        )
    return GraphDatabase.driver(
        settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
    )


@contextmanager
def session() -> Iterator:
    d = driver()
    try:
        with d.session() as s:
            yield s
    finally:
        d.close()
