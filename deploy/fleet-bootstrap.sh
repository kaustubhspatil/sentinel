#!/usr/bin/env bash
# Turn a bare Linux host into a managed endpoint.
#
# Installs the two signals an RMM actually needs:
#   node_exporter - resource telemetry (the "is it healthy" question)
#   osquery       - inventory and behaviour: installed packages, logins, listening
#                   ports, processes (the "what is it and who touched it" question)
# and Grafana Alloy to ship both off-box, so a preempted or destroyed node does not
# take its own history with it.
#
# Package inventory matters beyond monitoring: it is the join key from a host to the
# CVE graph. Without osquery's deb_packages the vulnerability side of the ontology has
# nothing to attach to.
#
# Usage: TENANT=acme GRAFANA_* ... bash fleet-bootstrap.sh
set -euo pipefail

: "${TENANT:?TENANT must be set (the customer this host belongs to)}"
: "${GRAFANA_PROM_URL:?}" "${GRAFANA_PROM_USER:?}"
: "${GRAFANA_LOKI_URL:?}" "${GRAFANA_LOKI_USER:?}" "${GRAFANA_API_TOKEN:?}"

HOST=$(hostname)
log(){ echo "[fleet $(date -u +%H:%M:%S)] $*"; }
export DEBIAN_FRONTEND=noninteractive

log "base packages + node_exporter"
sudo -E apt-get update -qq
sudo -E apt-get install -y -qq ca-certificates curl gnupg prometheus-node-exporter \
  unattended-upgrades fail2ban

log "osquery"
if ! command -v osqueryd >/dev/null 2>&1; then
  curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/osquery.gpg
  echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main" \
    | sudo tee /etc/apt/sources.list.d/osquery.list >/dev/null
  sudo -E apt-get update -qq
  sudo -E apt-get install -y -qq osquery
fi

# Scheduled queries are differential by default: the first execution stores a baseline
# and logs nothing, so results only appear on the second run. deb_packages is marked
# snapshot so every execution emits the full inventory - it is the join key to the CVE
# graph and must not arrive as a diff. Its interval is 900s during build-out for a
# workable feedback loop; 3600s is the sane production value.
# (Comment kept out of the JSON below: osquery's config is parsed as strict JSON.)
log "osquery schedule"
sudo mkdir -p /etc/osquery /var/log/osquery
sudo tee /etc/osquery/osquery.conf >/dev/null <<OSQ
{
  "options": {
    "logger_path": "/var/log/osquery",
    "logger_mode": "0644",
    "schedule_splay_percent": 10,
    "utc": "true",
    "host_identifier": "hostname"
  },
  "schedule": {
    "os_version":        { "query": "SELECT name, version, build, platform FROM os_version;", "interval": 3600 },
    "deb_packages":      { "query": "SELECT name, version, arch FROM deb_packages;", "interval": 900, "snapshot": true },
    "listening_ports":   { "query": "SELECT DISTINCT pid, port, protocol, address FROM listening_ports WHERE port != 0;", "interval": 600 },
    "logged_in_users":   { "query": "SELECT user, tty, host, time FROM logged_in_users;", "interval": 300 },
    "last_logins":       { "query": "SELECT username, tty, host, time, type FROM last WHERE time > 0;", "interval": 600 },
    "process_snapshot":  { "query": "SELECT pid, name, path, cmdline, uid FROM processes;", "interval": 900 },
    "kernel_info":       { "query": "SELECT version, arguments FROM kernel_info;", "interval": 86400 }
  }
}
OSQ
sudo systemctl enable --now osqueryd
sudo systemctl restart osqueryd

log "grafana alloy"
if ! command -v alloy >/dev/null 2>&1; then
  sudo mkdir -p /etc/apt/keyrings
  curl -fsSL https://apt.grafana.com/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/grafana.gpg
  echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" \
    | sudo tee /etc/apt/sources.list.d/grafana.list >/dev/null
  sudo -E apt-get update -qq
  sudo -E apt-get install -y -qq alloy
fi

log "alloy config"
sudo tee /etc/alloy/config.alloy >/dev/null <<ALLOY
// Metrics: scrape the local node_exporter and forward to Grafana Cloud.
prometheus.scrape "node" {
  targets = [{
    __address__ = "localhost:9100",
    instance    = "${HOST}",
  }]
  forward_to      = [prometheus.remote_write.cloud.receiver]
  scrape_interval = "30s"
}

prometheus.remote_write "cloud" {
  external_labels = {
    tenant = "${TENANT}",
    fleet  = "sentinel",
  }
  endpoint {
    url = "${GRAFANA_PROM_URL}"
    basic_auth {
      username = "${GRAFANA_PROM_USER}"
      password = "${GRAFANA_API_TOKEN}"
    }
  }
}

// Logs: the systemd journal, plus osquery's scheduled query results. The osquery
// stream is the one that matters later - it carries package inventory and login
// activity, which is what the graph and the behavioural baselines are built from.
loki.source.journal "journal" {
  forward_to = [loki.write.cloud.receiver]
  labels     = {
    job    = "systemd-journal",
    host   = "${HOST}",
    tenant = "${TENANT}",
  }
}

// osquery splits its output: differential query results go to osqueryd.results.log,
// while snapshot queries - deb_packages, the inventory the CVE graph joins on - go to
// osqueryd.snapshots.log. Tailing only the first silently drops the inventory.
local.file_match "osquery" {
  path_targets = [
    {
      __path__ = "/var/log/osquery/osqueryd.results.log",
      job      = "osquery",
      stream   = "results",
      host     = "${HOST}",
      tenant   = "${TENANT}",
    },
    {
      __path__ = "/var/log/osquery/osqueryd.snapshots.log",
      job      = "osquery",
      stream   = "snapshots",
      host     = "${HOST}",
      tenant   = "${TENANT}",
    },
  ]
}

loki.source.file "osquery" {
  targets    = local.file_match.osquery.targets
  forward_to = [loki.write.cloud.receiver]
}

loki.write "cloud" {
  endpoint {
    url = "${GRAFANA_LOKI_URL}"
    basic_auth {
      username = "${GRAFANA_LOKI_USER}"
      password = "${GRAFANA_API_TOKEN}"
    }
  }
}
ALLOY

# Alloy runs as its own user, and osquery writes its result log 0600 root:root by
# default - so the log ships nothing and fails silently. logger_mode above fixes new
# files; this handles a log that already exists from a previous run.
# logger_mode only applies when osquery creates the file, so existing logs keep their
# original 0640 root:root and stay unreadable to Alloy. Fix both cases.
sudo chmod 0644 /var/log/osquery/*.log 2>/dev/null || true

sudo systemctl enable --now alloy
sudo systemctl restart alloy

log "status"
systemctl is-active prometheus-node-exporter osqueryd alloy
log "DONE ${HOST} tenant=${TENANT}"
