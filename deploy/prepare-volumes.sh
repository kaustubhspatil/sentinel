#!/usr/bin/env bash
# Bind-mounted volumes are created by the Docker daemon as root, or inherited from the
# host user, but Redpanda and ClickHouse both run as uid 101 inside their images and
# will not start if they cannot write their data directory. Compose has no ordering hook
# for this, so it runs before `docker compose up`.
set -euo pipefail
ROOT=${1:-/srv/sentinel}

sudo mkdir -p "$ROOT"/{neo4j/data,neo4j/logs,clickhouse,redpanda,postgres,temporal,caddy}

# uid 101: redpanda, clickhouse
sudo chown -R 101:101 "$ROOT/redpanda" "$ROOT/clickhouse"
# uid 7474: neo4j
sudo chown -R 7474:7474 "$ROOT/neo4j"
# uid 999: postgres
sudo chown -R 999:999 "$ROOT/postgres"

echo "volume ownership prepared under $ROOT"
