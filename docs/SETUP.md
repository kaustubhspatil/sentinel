# Setup

Sentinel runs against a small fleet of Linux hosts plus one always-on backbone. Nothing here
is specific to a cloud vendor — the components below are what matter; where they run is a
cost decision.

## 1. Local

```bash
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"      # Windows
# source .venv/bin/activate && pip install -e ".[dev]"   # Linux/macOS
```

Verify with the credential-free path:

```bash
python -m sentinel.ingest.feeds
```

This fetches the CISA KEV catalogue, the current EPSS scores and the MITRE ATT&CK
Enterprise STIX bundle into `data/raw/`. No accounts required.

## 2. Secrets

`sentinel.config` loads environment values from **outside the repository**, in this order:

1. the process environment
2. `$SENTINEL_ENV_FILE`
3. `~/.secrets/msp.env`

Nothing sensitive is ever read from inside the working tree. Copy `.env.example` to
`~/.secrets/msp.env` and fill it in.

## 3. Backbone

One host, 2 vCPU / 8 GB, running the stateful services:

| Service | Role |
|---|---|
| Neo4j | knowledge graph |
| ClickHouse | metrics, logs, agent tool-call traces |
| Redpanda | event mesh (Kafka API) — provisioned, not yet carrying traffic |
| Temporal | durable execution for multi-step remediation |
| PostgreSQL + pgvector | document store and embeddings |
| Caddy | TLS termination |

Run it on preemptible/spot capacity if cost matters — configure the termination action to
**stop, not delete**, so the disk survives and recovery is a restart rather than a rebuild.

## 4. Fleet nodes

Any small Linux hosts. Each runs `node_exporter` and `osquery`, shipping metrics and logs to
the observability stack and package inventory to the graph loader. Geographic and provider
spread is desirable — it makes the estate model non-trivial.

## 5. Batch ingestion

The public feeds refresh on a schedule via GitHub Actions rather than on the backbone, which
keeps the daily EPSS series accumulating even when the backbone is down.

## Operations

- [`incident_log.md`](incident_log.md) — real failures and what changed as a result.
