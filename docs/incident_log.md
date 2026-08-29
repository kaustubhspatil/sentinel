# Incident log

Every real failure, what it looked like, what was diagnosed, what changed. Written by hand.
This is the primary source for the "most complex technical challenge" interview answer -
its value comes from being real, so do not backfill it.

| Date | Signal | Diagnosis | Change | Time to resolve |
|---|---|---|---|---|
| | | | | |
| 2026-08-29 | `redpanda` container in a restart loop immediately after first `compose up`; ClickHouse never reached healthy | `Failure during startup: system_error (error system:13, open: Permission denied)` writing `pid.lock`. Both images run as uid 101, but the bind-mounted host directories were owned by the login user (1001:1002). Neo4j and Postgres were unaffected because their images chown their own data directory on start. | Added `deploy/prepare-volumes.sh` to set per-service ownership before `compose up`, rather than fixing it by hand - the failure would otherwise recur on every fresh host. | ~10 min |
| 2026-08-29 | Fleet agents reported healthy and metrics flowed, but osquery results - the package inventory the CVE graph joins on - shipped nothing | osquery writes its result log `0600 root:root`, and Grafana Alloy runs as its own user. Alloy tailed a file it could not open and reported no error, so every dashboard looked correct while the most important stream was silent. Two effects masked it: node metrics were arriving normally, and osquery's scheduled queries are differential, so an empty log was expected for the first interval anyway. | Set osquery's `logger_mode` to 0644 in the config rather than chmod'ing after the fact, so newly rotated logs stay readable. Verification now checks that the agent user can actually read the file, not just that the service is active. | ~20 min |
