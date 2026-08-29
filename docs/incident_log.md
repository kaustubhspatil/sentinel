# Incident log

Every real failure, what it looked like, what was diagnosed, what changed. Written by hand.
This is the primary source for the "most complex technical challenge" interview answer -
its value comes from being real, so do not backfill it.

| Date | Signal | Diagnosis | Change | Time to resolve |
|---|---|---|---|---|
| | | | | |
| 2026-08-29 | `redpanda` container in a restart loop immediately after first `compose up`; ClickHouse never reached healthy | `Failure during startup: system_error (error system:13, open: Permission denied)` writing `pid.lock`. Both images run as uid 101, but the bind-mounted host directories were owned by the login user (1001:1002). Neo4j and Postgres were unaffected because their images chown their own data directory on start. | Added `deploy/prepare-volumes.sh` to set per-service ownership before `compose up`, rather than fixing it by hand - the failure would otherwise recur on every fresh host. | ~10 min |
