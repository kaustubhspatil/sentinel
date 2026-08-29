"""Embeddings in pgvector.

Vectors live in Postgres rather than a dedicated vector database because Postgres is
already running here, the corpus is a few thousand documents, and a separate service would
be infrastructure bought for a problem this size does not have. At a hundred million
chunks that answer changes; at two thousand it does not.

Embedding calls are batched and cached by content hash, so re-running the ablation costs
nothing. That matters more than it sounds: an ablation you cannot afford to re-run is an
ablation you run once, believe, and never check.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

import httpx
import psycopg
from pgvector.psycopg import register_vector

from sentinel.config import settings
from sentinel.rag.corpus import Document

MODEL = "text-embedding-3-small"
DIMS = 1536
BATCH = 64
TIMEOUT = httpx.Timeout(120.0, connect=15.0)

DDL = f"""
CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE IF NOT EXISTS doc_embeddings (
    doc_id      TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    title       TEXT,
    content     TEXT NOT NULL,
    content_sha TEXT NOT NULL,
    embedding   vector({DIMS}) NOT NULL
);
CREATE INDEX IF NOT EXISTS doc_embeddings_kind ON doc_embeddings (kind);
"""


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def connect() -> psycopg.Connection:
    conn = psycopg.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        user=settings.postgres_user,
        password=settings.postgres_password or "",
        dbname=settings.postgres_db,
        autocommit=True,
    )
    conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
    register_vector(conn)
    return conn


def embed_texts(texts: list[str]) -> list[list[float]]:
    """Embed a batch through Azure OpenAI."""
    endpoint = (settings.azure_openai_endpoint or "").rstrip("/")
    url = f"{endpoint}/openai/deployments/{MODEL}/embeddings"
    # A freshly created deployment returns 404 for several minutes while it propagates
    # across the Global tier, and rate limits appear as 429. Both are transient and the
    # identical request succeeds shortly after, so retry rather than abandoning a
    # half-finished index.
    delay = 2.0
    for attempt in range(5):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(
                url,
                params={"api-version": "2024-10-21"},
                headers={"api-key": settings.azure_openai_api_key},
                json={"input": texts},
            )
        if r.status_code in (404, 429, 500, 502, 503, 504) and attempt < 4:
            time.sleep(delay)
            delay *= 2
            continue
        r.raise_for_status()
        data = r.json()["data"]
        break
    else:  # pragma: no cover - only on five consecutive failures
        r.raise_for_status()
        data = r.json()["data"]
    # The API may return results out of order; index is authoritative.
    return [item["embedding"] for item in sorted(data, key=lambda d: d["index"])]


@dataclass
class EmbedStats:
    documents: int = 0
    embedded: int = 0
    cached: int = 0

    def __str__(self) -> str:
        return f"documents={self.documents:,} embedded={self.embedded:,} cached={self.cached:,}"


def index_documents(docs: list[Document]) -> EmbedStats:
    stats = EmbedStats(documents=len(docs))
    conn = connect()
    conn.execute(DDL)

    existing = {
        row[0]: row[1]
        for row in conn.execute("SELECT doc_id, content_sha FROM doc_embeddings").fetchall()
    }

    pending: list[Document] = []
    for d in docs:
        if existing.get(d.doc_id) == _sha(d.content):
            stats.cached += 1
        else:
            pending.append(d)

    for i in range(0, len(pending), BATCH):
        chunk = pending[i : i + BATCH]
        vectors = embed_texts([d.content[:8000] for d in chunk])
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO doc_embeddings (doc_id, kind, title, content, content_sha, embedding)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (doc_id) DO UPDATE SET
                    kind = EXCLUDED.kind, title = EXCLUDED.title,
                    content = EXCLUDED.content, content_sha = EXCLUDED.content_sha,
                    embedding = EXCLUDED.embedding
                """,
                [
                    (d.doc_id, d.kind, d.title, d.content, _sha(d.content), v)
                    for d, v in zip(chunk, vectors, strict=True)
                ],
            )
        stats.embedded += len(chunk)
    conn.close()
    return stats


class VectorStore:
    """Cosine search over the stored embeddings, with a per-process query cache."""

    def __init__(self) -> None:
        self.conn = connect()
        self._query_cache: dict[str, list[float]] = {}

    def _embed_query(self, query: str) -> list[float]:
        key = _sha(query)
        if key not in self._query_cache:
            self._query_cache[key] = embed_texts([query[:8000]])[0]
        return self._query_cache[key]

    def search(self, query: str, k: int = 10) -> list[tuple[str, float]]:
        vector = self._embed_query(query)
        rows = self.conn.execute(
            """
            SELECT doc_id, 1 - (embedding <=> %s::vector) AS similarity
            FROM doc_embeddings
            ORDER BY embedding <=> %s::vector
            LIMIT %s
            """,
            (vector, vector, k),
        ).fetchall()
        return [(r[0], float(r[1])) for r in rows]

    def count(self) -> int:
        return self.conn.execute("SELECT count(*) FROM doc_embeddings").fetchone()[0]


if __name__ == "__main__":
    from sentinel.rag.corpus import load_documents

    print(index_documents(load_documents()))
