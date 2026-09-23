#!/usr/bin/env bash
# redpanda/clickhouse/neo4j/postgres need to own their data dirs, run before compose up
set -euo pipefail
ROOT=${1:-/srv/sentinel}

sudo mkdir -p "$ROOT"/{neo4j/data,neo4j/logs,clickhouse,redpanda,postgres,temporal,caddy}

# redpanda, clickhouse
sudo chown -R 101:101 "$ROOT/redpanda" "$ROOT/clickhouse"
# neo4j
sudo chown -R 7474:7474 "$ROOT/neo4j"
# postgres
sudo chown -R 999:999 "$ROOT/postgres"

echo "volume ownership prepared under $ROOT"
