#!/usr/bin/env bash
#
# Audit and optionally tune Oracle HTTP Server 12c/14c for WebLogic routing
# in environments that commonly load Oracle WebGate.
#
# Default mode is read-only audit. Use the "apply" subcommand only after
# reviewing the generated report in a lower environment.

set -u

VERSION="1.0.0"
COMMAND="audit"
DOMAIN_HOME="${DOMAIN_HOME:-}"
ORACLE_HOME="${ORACLE_HOME:-}"
OHS_INSTANCE="${COMPONENT_NAME:-}"
CONFIG_DIR=""
REPORT_DIR=""
BACKUP_DIR=""
PROFILE="webgate-balanced"
VALIDATE=1
VERBOSE=0

MAX_REQUEST_WORKERS_OVERRIDE=""
THREADS_PER_CHILD_OVERRIDE=""
LISTEN_BACKLOG_OVERRIDE=""
KEEPALIVE_TIMEOUT_OVERRIDE=""
TIMEOUT_OVERRIDE=""
WLS_CLUSTER_OVERRIDE=""
WL_IO_TIMEOUT_OVERRIDE=""
WL_TEMP_DIR_OVERRIDE=""
STATIC_BACKENDS=0
OS_TUNING=1
APPLY_OS_TUNING=0
OS_USER=""
SYSCTL_FILE="/etc/sysctl.d/98-ohs-wls-webgate.conf"
LIMITS_FILE="/etc/security/limits.d/98-ohs-wls-webgate.conf"
SYSTEMD_SERVICE=""
SYSTEMD_OVERRIDE_DIR=""
SYSCTL_LOAD=1
SYSTEMD_RELOAD=1

APPLY=0
REPORT_FILE=""
HTTPD_CONF=""
NODEMGR_PROPS=""
PLUGIN_CONF=""
WEBGATE_DETECTED=0
MOD_WL_DETECTED=0
CONFIG_FS_TYPE="unknown"
CONFIG_FILES=()
BACKED_UP_FILES=""
MISSING_HTTPD_LINES=()
MISSING_PLUGIN_LINES=()
FINDINGS=()
APPLIED_CHANGES=()

usage() {
  cat <<'EOF'
Usage:
  tune-ohs-wls-webgate.sh [audit|plan|apply] [options]

Modes:
  audit   Inspect the OHS instance and write a tuning report. This is the default.
  plan    Same as audit, with explicit recommended directive snippets.
  apply   Back up config files, apply conservative tuning edits, and validate syntax.

Common options:
  --domain-home PATH          WebLogic/OHS domain home. Uses DOMAIN_HOME if set.
  --config-dir PATH           OHS staging config dir containing httpd.conf.
  --instance NAME             OHS component name, for example ohs1.
  --oracle-home PATH          Oracle home. Uses ORACLE_HOME if set.
  --profile NAME              webgate-balanced, throughput, latency, or conservative.
  --report-dir PATH           Directory for report output.
  --backup-dir PATH           Directory for config backups in apply mode.
  --static-backends           Treat WebLogicCluster as non-clustered backends; keep DynamicServerList OFF.
  --no-os-tuning              Skip Linux OS tuning checks and snippets.
  --apply-os-tuning           In apply mode, also write sysctl, limits, and optional systemd files.
  --os-user USER              OS account that runs OHS children or Node Manager. Auto-detected by default.
  --sysctl-file PATH          Target sysctl drop-in. Default: /etc/sysctl.d/98-ohs-wls-webgate.conf.
  --limits-file PATH          Target limits drop-in. Default: /etc/security/limits.d/98-ohs-wls-webgate.conf.
  --systemd-service NAME      Optional service to receive a LimitNOFILE/LimitNPROC override.
  --systemd-override-dir PATH Override directory for --systemd-service, useful for testing.
  --no-sysctl-load            Write sysctl file but do not load it with sysctl -p.
  --no-systemd-reload         Write systemd override but do not run systemctl daemon-reload.
  --no-validate               Skip httpd -t validation in apply mode.
  --verbose                   Print additional discovery details.

Override options:
  --max-request-workers N     Override calculated MaxRequestWorkers.
  --threads-per-child N       Override calculated ThreadsPerChild.
  --listen-backlog N          Override calculated ListenBacklog.
  --keepalive-timeout N       Override OHS client KeepAliveTimeout.
  --timeout N                 Override OHS Timeout.
  --wls-cluster HOSTS         Set WebLogicCluster, for example host1:8001,host2:8001.
  --wl-io-timeout N           Override WLIOTimeoutSecs.
  --wl-temp-dir PATH          Set WLTempDir for WebLogic proxy POST temp files.

Examples:
  ./tune-ohs-wls-webgate.sh audit --domain-home /u01/oracle/config/domains/prod_domain --instance ohs1

  ./tune-ohs-wls-webgate.sh plan --config-dir /u01/oracle/config/domains/prod_domain/config/fmwconfig/components/OHS/ohs1

  ./tune-ohs-wls-webgate.sh apply \
    --domain-home /u01/oracle/config/domains/prod_domain \
    --instance ohs1 \
    --profile webgate-balanced \
    --wls-cluster wls1.example.com:8001,wls2.example.com:8001 \
    --apply-os-tuning \
    --os-user oracle

Notes:
  - The script targets Linux OHS 12c/14c Apache 2.4 based layouts.
  - It edits the OHS staging configuration directory, not the runtime instances directory.
  - For WebLogic-managed OHS domains, stop the Administration Server before manual config edits
    or use Fusion Middleware Control/WLST processes required by your change policy.
EOF
}

info() {
  printf '%s\n' "$*"
  if [[ -n "$REPORT_FILE" ]]; then
    printf '%s\n' "$*" >> "$REPORT_FILE"
  fi
}

debug() {
  if [[ "$VERBOSE" -eq 1 ]]; then
    info "DEBUG: $*"
  fi
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

is_number() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

max() {
  local a="$1"
  local b="$2"
  if (( a > b )); then
    printf '%s' "$a"
  else
    printf '%s' "$b"
  fi
}

min() {
  local a="$1"
  local b="$2"
  if (( a < b )); then
    printf '%s' "$a"
  else
    printf '%s' "$b"
  fi
}

upper() {
  printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]'
}

ceil_div() {
  local a="$1"
  local b="$2"
  printf '%s' $(( (a + b - 1) / b ))
}

add_finding() {
  FINDINGS+=("$1")
}

add_applied() {
  APPLIED_CHANGES+=("$1")
}

require_value() {
  local option="$1"
  local value="${2:-}"
  if [[ -z "$value" ]]; then
    die "$option requires a value"
  fi
}

parse_args() {
  if [[ $# -gt 0 ]]; then
    case "$1" in
      audit|plan|apply)
        COMMAND="$1"
        shift
        ;;
      -h|--help|help)
        usage
        exit 0
        ;;
    esac
  fi

  case "$COMMAND" in
    audit|plan) APPLY=0 ;;
    apply) APPLY=1 ;;
    *) die "Unknown mode: $COMMAND" ;;
  esac

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --domain-home)
        require_value "$1" "${2:-}"
        DOMAIN_HOME="$2"
        shift 2
        ;;
      --config-dir)
        require_value "$1" "${2:-}"
        CONFIG_DIR="$2"
        shift 2
        ;;
      --instance|--ohs-instance)
        require_value "$1" "${2:-}"
        OHS_INSTANCE="$2"
        shift 2
        ;;
      --oracle-home)
        require_value "$1" "${2:-}"
        ORACLE_HOME="$2"
        shift 2
        ;;
      --profile)
        require_value "$1" "${2:-}"
        PROFILE="$2"
        shift 2
        ;;
      --report-dir)
        require_value "$1" "${2:-}"
        REPORT_DIR="$2"
        shift 2
        ;;
      --backup-dir)
        require_value "$1" "${2:-}"
        BACKUP_DIR="$2"
        shift 2
        ;;
      --max-request-workers)
        require_value "$1" "${2:-}"
        MAX_REQUEST_WORKERS_OVERRIDE="$2"
        shift 2
        ;;
      --threads-per-child)
        require_value "$1" "${2:-}"
        THREADS_PER_CHILD_OVERRIDE="$2"
        shift 2
        ;;
      --listen-backlog)
        require_value "$1" "${2:-}"
        LISTEN_BACKLOG_OVERRIDE="$2"
        shift 2
        ;;
      --keepalive-timeout)
        require_value "$1" "${2:-}"
        KEEPALIVE_TIMEOUT_OVERRIDE="$2"
        shift 2
        ;;
      --timeout)
        require_value "$1" "${2:-}"
        TIMEOUT_OVERRIDE="$2"
        shift 2
        ;;
      --wls-cluster)
        require_value "$1" "${2:-}"
        WLS_CLUSTER_OVERRIDE="$2"
        shift 2
        ;;
      --wl-io-timeout)
        require_value "$1" "${2:-}"
        WL_IO_TIMEOUT_OVERRIDE="$2"
        shift 2
        ;;
      --wl-temp-dir)
        require_value "$1" "${2:-}"
        WL_TEMP_DIR_OVERRIDE="$2"
        shift 2
        ;;
      --static-backends)
        STATIC_BACKENDS=1
        shift
        ;;
      --no-os-tuning)
        OS_TUNING=0
        shift
        ;;
      --apply-os-tuning)
        APPLY_OS_TUNING=1
        shift
        ;;
      --os-user)
        require_value "$1" "${2:-}"
        OS_USER="$2"
        shift 2
        ;;
      --sysctl-file)
        require_value "$1" "${2:-}"
        SYSCTL_FILE="$2"
        shift 2
        ;;
      --limits-file)
        require_value "$1" "${2:-}"
        LIMITS_FILE="$2"
        shift 2
        ;;
      --systemd-service)
        require_value "$1" "${2:-}"
        SYSTEMD_SERVICE="$2"
        shift 2
        ;;
      --systemd-override-dir)
        require_value "$1" "${2:-}"
        SYSTEMD_OVERRIDE_DIR="$2"
        shift 2
        ;;
      --no-sysctl-load)
        SYSCTL_LOAD=0
        shift
        ;;
      --no-systemd-reload)
        SYSTEMD_RELOAD=0
        shift
        ;;
      --no-validate)
        VALIDATE=0
        shift
        ;;
      --verbose)
        VERBOSE=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown option: $1"
        ;;
    esac
  done

  case "$PROFILE" in
    webgate-balanced|throughput|latency|conservative) ;;
    *) die "Unknown profile: $PROFILE" ;;
  esac

  for opt in \
    "$MAX_REQUEST_WORKERS_OVERRIDE" \
    "$THREADS_PER_CHILD_OVERRIDE" \
    "$LISTEN_BACKLOG_OVERRIDE" \
    "$KEEPALIVE_TIMEOUT_OVERRIDE" \
    "$TIMEOUT_OVERRIDE" \
    "$WL_IO_TIMEOUT_OVERRIDE"; do
    if [[ -n "$opt" ]] && ! is_number "$opt"; then
      die "Numeric override expected, got: $opt"
    fi
  done

  if [[ "$APPLY_OS_TUNING" -eq 1 && "$COMMAND" != "apply" ]]; then
    die "--apply-os-tuning can only be used with apply mode"
  fi
  if [[ "$APPLY_OS_TUNING" -eq 1 && "$OS_TUNING" -eq 0 ]]; then
    die "--apply-os-tuning cannot be combined with --no-os-tuning"
  fi
}

discover_from_processes() {
  local proc_confs
  proc_confs="$(ps -eo args 2>/dev/null | awk '
    /[o]hs\/bin\/httpd|[h]ttpd/ {
      for (i = 1; i <= NF; i++) {
        if ($i == "-f" && (i + 1) <= NF) {
          print $(i + 1)
        }
      }
    }' | sort -u)"

  if [[ -z "$CONFIG_DIR" && -n "$proc_confs" ]]; then
    local first_conf
    first_conf="$(printf '%s\n' "$proc_confs" | head -n 1)"
    if [[ -f "$first_conf" ]]; then
      CONFIG_DIR="$(cd "$(dirname "$first_conf")" && pwd -P)"
      debug "Discovered CONFIG_DIR from running process: $CONFIG_DIR"
    fi
  fi
}

discover_config_dir() {
  if [[ -n "$CONFIG_DIR" ]]; then
    [[ -f "$CONFIG_DIR/httpd.conf" ]] || die "--config-dir does not contain httpd.conf: $CONFIG_DIR"
    CONFIG_DIR="$(cd "$CONFIG_DIR" && pwd -P)"
    return
  fi

  discover_from_processes
  if [[ -n "$CONFIG_DIR" ]]; then
    return
  fi

  local ohs_root=""
  if [[ -n "$DOMAIN_HOME" ]]; then
    ohs_root="$DOMAIN_HOME/config/fmwconfig/components/OHS"
  elif [[ -n "${ORACLE_INSTANCE:-}" ]]; then
    ohs_root="${ORACLE_INSTANCE}/config/fmwconfig/components/OHS"
  fi

  if [[ -n "$ohs_root" && -d "$ohs_root" ]]; then
    if [[ -n "$OHS_INSTANCE" && -f "$ohs_root/$OHS_INSTANCE/httpd.conf" ]]; then
      CONFIG_DIR="$(cd "$ohs_root/$OHS_INSTANCE" && pwd -P)"
      return
    fi

    local candidates
    candidates="$(find "$ohs_root" -maxdepth 2 -type f -name httpd.conf 2>/dev/null \
      | grep -v '/instances/' \
      | sort)"
    local count
    count="$(printf '%s\n' "$candidates" | sed '/^$/d' | wc -l | tr -d ' ')"
    if [[ "$count" = "1" ]]; then
      CONFIG_DIR="$(cd "$(dirname "$candidates")" && pwd -P)"
      return
    elif [[ "$count" -gt 1 ]]; then
      die "Multiple OHS instances found. Re-run with --instance NAME or --config-dir PATH.
Candidates:
$candidates"
    fi
  fi

  die "Could not discover OHS config. Provide --domain-home with --instance, or --config-dir."
}

initialize_paths() {
  HTTPD_CONF="$CONFIG_DIR/httpd.conf"
  [[ -f "$HTTPD_CONF" ]] || die "Missing httpd.conf: $HTTPD_CONF"

  if [[ -z "$REPORT_DIR" ]]; then
    REPORT_DIR="${PWD}/ohs-wls-webgate-tuning-$(date +%Y%m%d-%H%M%S)"
  fi
  mkdir -p "$REPORT_DIR" || die "Could not create report directory: $REPORT_DIR"
  REPORT_FILE="$REPORT_DIR/ohs-wls-webgate-tuning-report.txt"
  : > "$REPORT_FILE" || die "Could not write report file: $REPORT_FILE"

  if [[ -z "$BACKUP_DIR" ]]; then
    BACKUP_DIR="$REPORT_DIR/backups"
  fi

  NODEMGR_PROPS="$CONFIG_DIR/ohs.plugins.nodemanager.properties"
}

collect_config_files() {
  local list
  list="$(find "$CONFIG_DIR" -maxdepth 4 -type f \
    \( -name '*.conf' -o -name 'webgate.conf' -o -name 'ObAccessClient.xml' \) \
    2>/dev/null | sort)"
  CONFIG_FILES=()
  while IFS= read -r f; do
    [[ -n "$f" ]] && CONFIG_FILES+=("$f")
  done <<< "$list"

  if [[ "${#CONFIG_FILES[@]}" -eq 0 ]]; then
    CONFIG_FILES=("$HTTPD_CONF")
  fi
}

detect_filesystem_type() {
  if command -v stat >/dev/null 2>&1; then
    CONFIG_FS_TYPE="$(stat -f -c %T "$CONFIG_DIR" 2>/dev/null || printf 'unknown')"
  fi
}

active_grep() {
  local pattern="$1"
  local file
  for file in "${CONFIG_FILES[@]}"; do
    awk '
      /^[[:space:]]*#/ { next }
      { print }
    ' "$file" 2>/dev/null | grep -Eiq "$pattern" && return 0
  done
  return 1
}

find_directive_occurrences() {
  local directive="$1"
  local file
  for file in "${CONFIG_FILES[@]}"; do
    awk -v d="$directive" -v file="$file" '
      BEGIN { dlow = tolower(d) }
      /^[[:space:]]*#/ { next }
      {
        key = tolower($1)
        if (key == dlow) {
          val = $0
          sub(/^[[:space:]]*[^[:space:]]+[[:space:]]*/, "", val)
          printf "%s\t%d\t%s\n", file, NR, val
        }
      }
    ' "$file" 2>/dev/null
  done
}

last_directive_value() {
  local directive="$1"
  find_directive_occurrences "$directive" | tail -n 1 | cut -f3-
}

last_directive_file() {
  local directive="$1"
  find_directive_occurrences "$directive" | tail -n 1 | cut -f1
}

directive_count() {
  local directive="$1"
  find_directive_occurrences "$directive" | wc -l | tr -d ' '
}

detect_plugin_conf() {
  local file
  PLUGIN_CONF=""

  for file in "${CONFIG_FILES[@]}"; do
    if awk '
      /^[[:space:]]*#/ { next }
      /WebLogicCluster|WebLogicHost|WebLogicPort|DynamicServerList|KeepAliveEnabled|WLIOTimeoutSecs|WLSRequest|weblogic-handler/ { found=1 }
      END { exit(found ? 0 : 1) }
    ' "$file" 2>/dev/null; then
      PLUGIN_CONF="$file"
      break
    fi
  done

  if [[ -z "$PLUGIN_CONF" ]]; then
    for file in "${CONFIG_FILES[@]}"; do
      if awk '
        /^[[:space:]]*#/ { next }
        /weblogic_module|mod_wl_ohs/ { found=1 }
        END { exit(found ? 0 : 1) }
      ' "$file" 2>/dev/null; then
        PLUGIN_CONF="$file"
        break
      fi
    done
  fi

  if [[ -z "$PLUGIN_CONF" ]]; then
    if [[ -d "$CONFIG_DIR/moduleconf" ]]; then
      PLUGIN_CONF="$CONFIG_DIR/moduleconf/mod_wl_ohs.conf"
    else
      PLUGIN_CONF="$HTTPD_CONF"
    fi
  fi
}

detect_modules() {
  if active_grep 'LoadModule[[:space:]]+.*webgate|mod_webgate|webgate\.conf|ObAccessClient\.xml'; then
    WEBGATE_DETECTED=1
  fi

  if active_grep 'LoadModule[[:space:]]+.*weblogic|mod_wl_ohs|weblogic_module|WebLogicCluster|WebLogicHost|WLSRequest|weblogic-handler'; then
    MOD_WL_DETECTED=1
  fi
}

get_mpm() {
  local mpm=""
  if [[ -f "$NODEMGR_PROPS" ]]; then
    mpm="$(awk -F= '
      /^[[:space:]]*#/ { next }
      tolower($1) ~ /^[[:space:]]*mpm[[:space:]]*$/ {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2)
        print $2
      }' "$NODEMGR_PROPS" | tail -n 1)"
  fi

  if [[ -z "$mpm" ]]; then
    if active_grep 'mpm_event_module|event\.load|mpm[[:space:]]*=[[:space:]]*event'; then
      mpm="event"
    elif active_grep 'mpm_worker_module|worker\.load|mpm[[:space:]]*=[[:space:]]*worker'; then
      mpm="worker"
    elif active_grep 'mpm_prefork_module|prefork\.load|mpm[[:space:]]*=[[:space:]]*prefork'; then
      mpm="prefork"
    else
      mpm="unknown"
    fi
  fi

  printf '%s' "$mpm"
}

cpu_count() {
  local n
  n="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || printf '2')"
  is_number "$n" || n=2
  printf '%s' "$n"
}

fd_limit() {
  local n
  n="$(ulimit -n 2>/dev/null || printf '0')"
  is_number "$n" || n=0
  printf '%s' "$n"
}

sysctl_value() {
  local key="$1"
  sysctl -n "$key" 2>/dev/null || printf ''
}

detect_os_user() {
  if [[ -n "$OS_USER" ]]; then
    return
  fi

  local configured_user
  configured_user="$(last_directive_value "User" | awk '{print $1}' | tail -n 1)"
  case "$configured_user" in
    ""|\#*|\$*|*\}*) ;;
    *)
      OS_USER="$configured_user"
      return
      ;;
  esac

  local owner
  owner="$(stat -c %U "$HTTPD_CONF" 2>/dev/null || printf '')"
  if [[ -n "$owner" && "$owner" != "UNKNOWN" && "$owner" != "root" ]]; then
    OS_USER="$owner"
    return
  fi

  OS_USER="$(id -un 2>/dev/null || printf 'oracle')"
}

systemd_service_name() {
  local service="$SYSTEMD_SERVICE"
  [[ -z "$service" ]] && return
  case "$service" in
    *.service) printf '%s' "$service" ;;
    *) printf '%s.service' "$service" ;;
  esac
}

systemd_override_file() {
  local service
  service="$(systemd_service_name)"
  [[ -z "$service" ]] && return
  if [[ -n "$SYSTEMD_OVERRIDE_DIR" ]]; then
    printf '%s/override.conf' "$SYSTEMD_OVERRIDE_DIR"
  else
    printf '/etc/systemd/system/%s.d/override.conf' "$service"
  fi
}

build_os_targets() {
  local target_backlog="$1"
  local target_fd="$2"
  local target_max="$3"
  local current value

  local target_somaxconn
  target_somaxconn="$(max "$target_backlog" 1024)"
  current="$(sysctl_value net.core.somaxconn)"
  if is_number "$current"; then
    target_somaxconn="$(max "$target_somaxconn" "$current")"
  fi

  local target_syn_backlog
  target_syn_backlog=$(( target_backlog * 2 ))
  target_syn_backlog="$(max "$target_syn_backlog" 2048)"
  current="$(sysctl_value net.ipv4.tcp_max_syn_backlog)"
  if is_number "$current"; then
    target_syn_backlog="$(max "$target_syn_backlog" "$current")"
  fi

  local target_port_range="10240 65000"
  current="$(sysctl_value net.ipv4.ip_local_port_range)"
  local port_low port_high port_width
  port_low="$(printf '%s\n' "$current" | awk 'NF >= 2 { print $1 }')"
  port_high="$(printf '%s\n' "$current" | awk 'NF >= 2 { print $2 }')"
  if is_number "$port_low" && is_number "$port_high"; then
    port_width=$(( port_high - port_low + 1 ))
    if (( port_width >= 20000 )); then
      target_port_range="$port_low $port_high"
    fi
  fi

  local target_fin_timeout=30
  current="$(sysctl_value net.ipv4.tcp_fin_timeout)"
  if is_number "$current" && (( current < target_fin_timeout )); then
    target_fin_timeout="$current"
  fi

  local target_file_max
  target_file_max=$(( target_fd * 8 ))
  target_file_max="$(max "$target_file_max" 1048576)"
  current="$(sysctl_value fs.file-max)"
  if is_number "$current"; then
    target_file_max="$(max "$target_file_max" "$current")"
  fi

  local soft_nofile hard_nofile nproc_limit
  soft_nofile="$target_fd"
  hard_nofile="$(max $(( target_fd * 2 )) 65536)"
  nproc_limit="$(max $(( target_max * 2 )) 16384)"

  printf '%s|%s|%s|%s|%s|%s|%s|%s' \
    "$target_somaxconn" "$target_syn_backlog" "$target_port_range" \
    "$target_fin_timeout" "$target_file_max" "$soft_nofile" \
    "$hard_nofile" "$nproc_limit"
}

calc_targets() {
  local cpu="$1"
  local fd="$2"
  local base_max threads backlog keepalive timeout wlio

  case "$PROFILE" in
    conservative)
      base_max=$(( cpu * 75 ))
      base_max="$(max "$base_max" 400)"
      base_max="$(min "$base_max" 700)"
      threads=50
      backlog=512
      keepalive=5
      timeout=120
      wlio=120
      ;;
    latency)
      base_max=$(( cpu * 100 ))
      base_max="$(max "$base_max" 500)"
      base_max="$(min "$base_max" 1000)"
      threads=50
      backlog=1024
      keepalive=2
      timeout=75
      wlio=120
      ;;
    throughput)
      base_max=$(( cpu * 200 ))
      base_max="$(max "$base_max" 800)"
      base_max="$(min "$base_max" 2200)"
      threads=64
      backlog=2048
      keepalive=3
      timeout=120
      wlio=180
      ;;
    webgate-balanced)
      base_max=$(( cpu * 125 ))
      base_max="$(max "$base_max" 600)"
      base_max="$(min "$base_max" 1400)"
      threads=50
      backlog=1024
      keepalive=3
      timeout=120
      wlio=180
      ;;
  esac

  if [[ -n "$MAX_REQUEST_WORKERS_OVERRIDE" ]]; then
    base_max="$MAX_REQUEST_WORKERS_OVERRIDE"
  fi
  if [[ -n "$THREADS_PER_CHILD_OVERRIDE" ]]; then
    threads="$THREADS_PER_CHILD_OVERRIDE"
  fi
  if [[ -n "$LISTEN_BACKLOG_OVERRIDE" ]]; then
    backlog="$LISTEN_BACKLOG_OVERRIDE"
  fi
  if [[ -n "$KEEPALIVE_TIMEOUT_OVERRIDE" ]]; then
    keepalive="$KEEPALIVE_TIMEOUT_OVERRIDE"
  fi
  if [[ -n "$TIMEOUT_OVERRIDE" ]]; then
    timeout="$TIMEOUT_OVERRIDE"
  fi
  if [[ -n "$WL_IO_TIMEOUT_OVERRIDE" ]]; then
    wlio="$WL_IO_TIMEOUT_OVERRIDE"
  fi

  local fd_cap=0
  if (( fd > 0 )); then
    fd_cap=$(( (fd - 512) / 3 ))
    if (( fd_cap > 0 && base_max > fd_cap )); then
      add_finding "[WARN] Open-file limit ($fd) is low for requested MaxRequestWorkers ($base_max). Capping recommendation at $fd_cap; raise the OHS process nofile limit for higher concurrency."
      base_max="$fd_cap"
    fi
  fi

  if (( base_max < 200 )); then
    base_max=200
  fi
  if (( threads < 1 )); then
    threads=50
  fi

  local server_limit
  server_limit="$(ceil_div "$base_max" "$threads")"
  local start_servers
  start_servers="$(ceil_div "$cpu" 2)"
  start_servers="$(max "$start_servers" 3)"
  start_servers="$(min "$start_servers" "$server_limit")"
  local min_spare=$(( base_max / 4 ))
  min_spare="$(max "$min_spare" "$threads")"
  min_spare="$(min "$min_spare" 300)"
  local max_spare=$(( base_max / 2 ))
  max_spare="$(max "$max_spare" $(( min_spare + threads )) )"
  max_spare="$(min "$max_spare" 800)"
  local fd_recommended=$(( base_max * 3 + 1024 ))

  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
    "$base_max" "$threads" "$server_limit" "$start_servers" "$min_spare" \
    "$max_spare" "$backlog" "$keepalive" "$timeout" "$wlio" "$fd_recommended"
}

print_directive_row() {
  local directive="$1"
  local value
  local location
  value="$(last_directive_value "$directive")"
  location="$(last_directive_file "$directive")"
  if [[ -n "$value" ]]; then
    info "  $directive = $value (${location#$CONFIG_DIR/})"
  else
    info "  $directive = <not set>"
  fi
}

print_current_state() {
  local mpm="$1"
  info "Oracle HTTP Server WebLogic/WebGate tuning report"
  info "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  info "Script version: $VERSION"
  info "Mode: $COMMAND"
  info "Profile: $PROFILE"
  info ""
  info "Discovered environment"
  info "  Config directory: $CONFIG_DIR"
  info "  httpd.conf: $HTTPD_CONF"
  info "  Domain home: ${DOMAIN_HOME:-<not supplied>}"
  info "  Oracle home: ${ORACLE_HOME:-<not supplied>}"
  info "  OHS instance: ${OHS_INSTANCE:-<not supplied>}"
  info "  Config filesystem: $CONFIG_FS_TYPE"
  info "  MPM: $mpm"
  info "  WebGate detected: $([[ "$WEBGATE_DETECTED" -eq 1 ]] && printf YES || printf NO)"
  info "  mod_wl_ohs detected: $([[ "$MOD_WL_DETECTED" -eq 1 ]] && printf YES || printf NO)"
  info "  WebLogic plug-in config target: $PLUGIN_CONF"
  info ""
  info "Current OHS performance directives"
  print_directive_row "MaxRequestWorkers"
  print_directive_row "ServerLimit"
  print_directive_row "ThreadsPerChild"
  print_directive_row "StartServers"
  print_directive_row "MinSpareThreads"
  print_directive_row "MaxSpareThreads"
  print_directive_row "ListenBacklog"
  print_directive_row "KeepAlive"
  print_directive_row "KeepAliveTimeout"
  print_directive_row "Timeout"
  print_directive_row "MaxConnectionsPerChild"
  print_directive_row "Mutex"
  info ""
  info "Current WebLogic proxy plug-in directives"
  print_directive_row "WebLogicCluster"
  print_directive_row "WebLogicHost"
  print_directive_row "WebLogicPort"
  print_directive_row "DynamicServerList"
  print_directive_row "KeepAliveEnabled"
  print_directive_row "KeepAliveSecs"
  print_directive_row "ConnectTimeoutSecs"
  print_directive_row "ConnectRetrySecs"
  print_directive_row "WLSocketTimeoutSecs"
  print_directive_row "WLIOTimeoutSecs"
  print_directive_row "DebugConfigInfo"
  print_directive_row "WLTempDir"
  print_directive_row "WLSRequest"
  info ""
}

evaluate_current_state() {
  local mpm="$1"
  local target_max="$2"
  local target_backlog="$3"
  local target_fd="$4"

  if [[ "$WEBGATE_DETECTED" -eq 0 ]]; then
    add_finding "[INFO] WebGate was not detected in the selected OHS config. The tool still audits WebLogic routing, but WebGate-specific guidance may not apply."
  fi
  if [[ "$MOD_WL_DETECTED" -eq 0 ]]; then
    add_finding "[WARN] mod_wl_ohs/WebLogic proxy directives were not detected. Existing WebLogic routing may be in another include tree, or this instance is not routing to WebLogic."
  fi
  if [[ "$mpm" = "prefork" ]]; then
    add_finding "[WARN] Prefork MPM detected. WebLogic proxy connection pooling should be disabled for prefork; event or worker MPM is preferred for Linux OHS routing workloads."
  elif [[ "$mpm" = "unknown" ]]; then
    add_finding "[WARN] Could not determine MPM. On Linux OHS 12c/14c, event MPM is normally preferred for concurrent routing workloads."
  fi

  local current_max
  current_max="$(last_directive_value "MaxRequestWorkers")"
  if is_number "$current_max" && (( current_max < target_max )); then
    add_finding "[WARN] MaxRequestWorkers ($current_max) is below the calculated target ($target_max). This can cap concurrent OHS/WebGate/WebLogic-routed requests."
  fi

  local current_keepalive
  current_keepalive="$(last_directive_value "KeepAliveTimeout")"
  if is_number "$current_keepalive" && (( current_keepalive > 5 )); then
    add_finding "[WARN] KeepAliveTimeout ($current_keepalive) is high for a front-end OHS tier. Long idle client keep-alives can hold OHS workers during bursts."
  fi

  local debug_config
  debug_config="$(last_directive_value "DebugConfigInfo")"
  if [[ "$(upper "$debug_config")" = "ON" ]]; then
    add_finding "[WARN] DebugConfigInfo is ON. Turn it OFF in production because it exposes proxy plug-in configuration details."
  fi

  local dyn
  dyn="$(last_directive_value "DynamicServerList")"
  local cluster
  cluster="$(last_directive_value "WebLogicCluster")"
  local dyn_upper
  dyn_upper="$(upper "$dyn")"
  if [[ -n "$cluster" && "$STATIC_BACKENDS" -eq 0 && "$dyn_upper" = "OFF" ]]; then
    add_finding "[WARN] WebLogicCluster is configured but DynamicServerList is OFF. For real WebLogic clusters, ON usually improves failover and avoids stale cluster membership."
  fi
  if [[ -n "$cluster" && "$STATIC_BACKENDS" -eq 1 && "$dyn_upper" != "OFF" ]]; then
    add_finding "[WARN] --static-backends was selected. Set DynamicServerList OFF when WebLogicCluster lists multiple non-clustered managed servers."
  fi

  local sethandler_count
  sethandler_count="$(grep -Eih '^[[:space:]]*SetHandler[[:space:]]+weblogic-handler' "${CONFIG_FILES[@]}" 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$sethandler_count" -gt 0 ]]; then
    add_finding "[INFO] Found $sethandler_count SetHandler weblogic-handler mapping(s). For slow/NFS DocumentRoot cases, Oracle documents WLSRequest ON as a lower-overhead alternative, but this must be changed per Location mapping."
  fi

  if [[ "$CONFIG_FS_TYPE" =~ nfs|nfs4|cifs|smb|fuse ]]; then
    add_finding "[WARN] OHS config appears to be on $CONFIG_FS_TYPE. On Linux shared filesystems, use a non-file Mutex such as 'Mutex sysvsem default' and keep WebLogic proxy temp files on local storage."
  fi

  local fd
  fd="$(fd_limit)"
  if (( fd > 0 && fd < target_fd )); then
    add_finding "[WARN] Current open-file limit ($fd) is below the calculated recommendation ($target_fd). Raise the limit for the OHS runtime user before increasing MaxRequestWorkers."
  fi

  local somaxconn
  somaxconn="$(sysctl_value net.core.somaxconn)"
  if is_number "$somaxconn" && (( somaxconn < target_backlog )); then
    add_finding "[WARN] net.core.somaxconn ($somaxconn) is below ListenBacklog target ($target_backlog). Increase somaxconn for bursty login traffic."
  fi

  local fin_timeout
  fin_timeout="$(sysctl_value net.ipv4.tcp_fin_timeout)"
  if is_number "$fin_timeout" && (( fin_timeout > 30 )); then
    add_finding "[INFO] net.ipv4.tcp_fin_timeout is $fin_timeout. If CONNECTION_REFUSED appears under load, lowering this according to Linux standards can help recycle sockets sooner."
  fi

  local ip_range
  ip_range="$(sysctl_value net.ipv4.ip_local_port_range)"
  if [[ "$ip_range" =~ ^[0-9]+[[:space:]]+[0-9]+$ ]]; then
    local low high width
    low="$(printf '%s' "$ip_range" | awk '{print $1}')"
    high="$(printf '%s' "$ip_range" | awk '{print $2}')"
    width=$(( high - low + 1 ))
    if (( width < 20000 )); then
      add_finding "[INFO] Ephemeral port range width is $width. A wider net.ipv4.ip_local_port_range helps high-throughput OHS-to-WebLogic connection churn."
    fi
  fi
}

evaluate_os_state() {
  [[ "$OS_TUNING" -eq 1 ]] || return

  local target_somaxconn="$1"
  local target_syn_backlog="$2"
  local target_port_range="$3"
  local target_fin_timeout="$4"
  local target_file_max="$5"
  local soft_nofile="$6"

  detect_os_user

  local current
  current="$(sysctl_value net.core.somaxconn)"
  if is_number "$current" && (( current < target_somaxconn )); then
    add_finding "[WARN] net.core.somaxconn ($current) is below the OS target ($target_somaxconn). OHS ListenBacklog can be capped by the kernel."
  fi

  current="$(sysctl_value net.ipv4.tcp_max_syn_backlog)"
  if is_number "$current" && (( current < target_syn_backlog )); then
    add_finding "[WARN] net.ipv4.tcp_max_syn_backlog ($current) is below the OS target ($target_syn_backlog). SYN bursts during login peaks may queue poorly."
  fi

  current="$(sysctl_value net.ipv4.ip_local_port_range)"
  local low high width
  low="$(printf '%s\n' "$current" | awk 'NF >= 2 { print $1 }')"
  high="$(printf '%s\n' "$current" | awk 'NF >= 2 { print $2 }')"
  if is_number "$low" && is_number "$high"; then
    width=$(( high - low + 1 ))
    if (( width < 20000 )); then
      add_finding "[WARN] net.ipv4.ip_local_port_range width ($width) is narrow for high OHS-to-WebLogic connection churn. Target range: $target_port_range."
    fi
  fi

  current="$(sysctl_value net.ipv4.tcp_fin_timeout)"
  if is_number "$current" && is_number "$target_fin_timeout" && (( current > target_fin_timeout )); then
    add_finding "[INFO] net.ipv4.tcp_fin_timeout ($current) is higher than the OS target ($target_fin_timeout). Lowering can help release closed sockets sooner under load."
  fi

  current="$(sysctl_value fs.file-max)"
  if is_number "$current" && (( current < target_file_max )); then
    add_finding "[WARN] fs.file-max ($current) is below the OS target ($target_file_max). The host-wide file table can limit OHS and backend connections."
  fi

  local runtime_fd
  runtime_fd="$(fd_limit)"
  if is_number "$runtime_fd" && (( runtime_fd < soft_nofile )); then
    add_finding "[WARN] Current shell nofile limit ($runtime_fd) is below the target OHS soft nofile limit ($soft_nofile). Ensure the OHS launch path receives the new limit."
  fi

  if [[ "$APPLY" -eq 1 && "$APPLY_OS_TUNING" -eq 0 ]]; then
    add_finding "[INFO] OS tuning apply is not enabled. Use --apply-os-tuning to write sysctl and limits drop-ins after reviewing this report."
  fi
}

print_recommendations() {
  local target_max="$1"
  local target_threads="$2"
  local target_server_limit="$3"
  local target_start="$4"
  local target_min_spare="$5"
  local target_max_spare="$6"
  local target_backlog="$7"
  local target_keepalive="$8"
  local target_timeout="$9"
  local target_wlio="${10}"
  local target_fd="${11}"

  local dyn_value="ON"
  if [[ "$STATIC_BACKENDS" -eq 1 ]]; then
    dyn_value="OFF"
  fi

  info "Calculated target directives"
  info "  ServerLimit $target_server_limit"
  info "  StartServers $target_start"
  info "  ThreadsPerChild $target_threads"
  info "  MaxRequestWorkers $target_max"
  info "  MinSpareThreads $target_min_spare"
  info "  MaxSpareThreads $target_max_spare"
  info "  ListenBacklog $target_backlog"
  info "  KeepAlive On"
  info "  KeepAliveTimeout $target_keepalive"
  info "  Timeout $target_timeout"
  info "  DynamicServerList $dyn_value"
  info "  KeepAliveEnabled ON"
  info "  KeepAliveSecs 20"
  info "  ConnectTimeoutSecs 10"
  info "  ConnectRetrySecs 2"
  info "  WLSocketTimeoutSecs 2"
  info "  WLIOTimeoutSecs $target_wlio"
  info "  DebugConfigInfo OFF"
  if [[ -n "$WLS_CLUSTER_OVERRIDE" ]]; then
    info "  WebLogicCluster $WLS_CLUSTER_OVERRIDE"
  fi
  if [[ -n "$WL_TEMP_DIR_OVERRIDE" ]]; then
    info "  WLTempDir $WL_TEMP_DIR_OVERRIDE"
  elif [[ "$CONFIG_FS_TYPE" =~ nfs|nfs4|cifs|smb|fuse ]]; then
    info "  WLTempDir /tmp/ohs-wl-proxy"
  fi
  info ""
  info "Runtime prerequisites"
  info "  Recommended OHS runtime nofile limit: $target_fd"
  info "  Recommended net.core.somaxconn: at least $target_backlog"
  info "  Validate WebLogic Server AcceptBackLog is sized for OHS concurrency."
  info "  Keep WebGate/OHS/mod_wl debug logging disabled during steady-state load tests."
  info ""

  if [[ "$COMMAND" = "plan" || "$COMMAND" = "apply" ]]; then
    info "Reviewable snippets"
    info "  OHS core snippet:"
    info "    ServerLimit $target_server_limit"
    info "    StartServers $target_start"
    info "    ThreadsPerChild $target_threads"
    info "    MaxRequestWorkers $target_max"
    info "    MinSpareThreads $target_min_spare"
    info "    MaxSpareThreads $target_max_spare"
    info "    ListenBacklog $target_backlog"
    info "    KeepAlive On"
    info "    KeepAliveTimeout $target_keepalive"
    info "    Timeout $target_timeout"
    info "  mod_wl_ohs snippet:"
    info "    <IfModule weblogic_module>"
    if [[ -n "$WLS_CLUSTER_OVERRIDE" ]]; then
      info "      WebLogicCluster $WLS_CLUSTER_OVERRIDE"
    fi
    info "      DynamicServerList $dyn_value"
    info "      KeepAliveEnabled ON"
    info "      KeepAliveSecs 20"
    info "      ConnectTimeoutSecs 10"
    info "      ConnectRetrySecs 2"
    info "      WLSocketTimeoutSecs 2"
    info "      WLIOTimeoutSecs $target_wlio"
    info "      DebugConfigInfo OFF"
    if [[ -n "$WL_TEMP_DIR_OVERRIDE" ]]; then
      info "      WLTempDir $WL_TEMP_DIR_OVERRIDE"
    elif [[ "$CONFIG_FS_TYPE" =~ nfs|nfs4|cifs|smb|fuse ]]; then
      info "      WLTempDir /tmp/ohs-wl-proxy"
    fi
    info "    </IfModule>"
    info ""
  fi
}

print_os_recommendations() {
  [[ "$OS_TUNING" -eq 1 ]] || {
    info "Linux OS tuning"
    info "  Skipped by --no-os-tuning."
    info ""
    return
  }

  local target_somaxconn="$1"
  local target_syn_backlog="$2"
  local target_port_range="$3"
  local target_fin_timeout="$4"
  local target_file_max="$5"
  local soft_nofile="$6"
  local hard_nofile="$7"
  local nproc_limit="$8"
  local override_file
  override_file="$(systemd_override_file)"

  detect_os_user

  info "Linux OS tuning"
  info "  OHS OS user: $OS_USER"
  info "  sysctl target file: $SYSCTL_FILE"
  info "  limits target file: $LIMITS_FILE"
  if [[ -n "$SYSTEMD_SERVICE" ]]; then
    info "  systemd service: $(systemd_service_name)"
    info "  systemd override file: $override_file"
  else
    info "  systemd service: <not supplied>"
  fi
  info ""
  info "Current Linux OS values"
  info "  net.core.somaxconn = $(sysctl_value net.core.somaxconn)"
  info "  net.ipv4.tcp_max_syn_backlog = $(sysctl_value net.ipv4.tcp_max_syn_backlog)"
  info "  net.ipv4.ip_local_port_range = $(sysctl_value net.ipv4.ip_local_port_range)"
  info "  net.ipv4.tcp_fin_timeout = $(sysctl_value net.ipv4.tcp_fin_timeout)"
  info "  fs.file-max = $(sysctl_value fs.file-max)"
  info "  current shell nofile = $(fd_limit)"
  info ""
  info "Recommended sysctl drop-in"
  info "  $SYSCTL_FILE:"
  info "    net.core.somaxconn = $target_somaxconn"
  info "    net.ipv4.tcp_max_syn_backlog = $target_syn_backlog"
  info "    net.ipv4.ip_local_port_range = $target_port_range"
  info "    net.ipv4.tcp_fin_timeout = $target_fin_timeout"
  info "    fs.file-max = $target_file_max"
  info ""
  info "Recommended process limits drop-in"
  info "  $LIMITS_FILE:"
  info "    $OS_USER soft nofile $soft_nofile"
  info "    $OS_USER hard nofile $hard_nofile"
  info "    $OS_USER soft nproc $nproc_limit"
  info "    $OS_USER hard nproc $nproc_limit"
  if [[ -n "$SYSTEMD_SERVICE" ]]; then
    info ""
    info "Recommended systemd override"
    info "  $override_file:"
    info "    [Service]"
    info "    LimitNOFILE=$hard_nofile"
    info "    LimitNPROC=$nproc_limit"
  fi
  if [[ "$APPLY" -eq 1 && "$APPLY_OS_TUNING" -eq 0 ]]; then
    info ""
    info "  OS files were not modified. Add --apply-os-tuning to write and load these settings."
  fi
  info ""
}

backup_once() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  case " $BACKED_UP_FILES " in
    *" $file "*) return 0 ;;
  esac
  mkdir -p "$BACKUP_DIR" || die "Could not create backup directory: $BACKUP_DIR"
  cp -p "$file" "$BACKUP_DIR/$(basename "$file").bak" || die "Could not back up $file"
  BACKED_UP_FILES="$BACKED_UP_FILES $file"
}

replace_last_directive_in_file() {
  local file="$1"
  local directive="$2"
  local value="$3"
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/ohs-tune.XXXXXX")" || die "mktemp failed"
  awk -v d="$directive" -v replacement="$directive $value" '
    BEGIN { dlow = tolower(d) }
    {
      lines[NR] = $0
      stripped = $0
      sub(/^[[:space:]]+/, "", stripped)
      if (stripped !~ /^#/ && tolower($1) == dlow) {
        last = NR
      }
    }
    END {
      for (i = 1; i <= NR; i++) {
        if (i == last) {
          indent = lines[i]
          sub(/[^[:space:]].*$/, "", indent)
          print indent replacement
        } else {
          print lines[i]
        }
      }
    }
  ' "$file" > "$tmp" || die "Failed to prepare update for $file"
  cat "$tmp" > "$file" || die "Failed to write $file"
  rm -f "$tmp"
}

upsert_httpd_directive() {
  local directive="$1"
  local value="$2"
  local file
  file="$(last_directive_file "$directive")"
  if [[ -n "$file" && -f "$file" ]]; then
    backup_once "$file"
    replace_last_directive_in_file "$file" "$directive" "$value"
    add_applied "Updated $directive in $file"
  else
    MISSING_HTTPD_LINES+=("$directive $value")
  fi
}

upsert_plugin_directive() {
  local directive="$1"
  local value="$2"
  local file
  file="$(last_directive_file "$directive")"
  if [[ -n "$file" && -f "$file" ]]; then
    backup_once "$file"
    replace_last_directive_in_file "$file" "$directive" "$value"
    add_applied "Updated $directive in $file"
  else
    MISSING_PLUGIN_LINES+=("$directive $value")
  fi
}

remove_managed_block() {
  local file="$1"
  local begin="$2"
  local end="$3"
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/ohs-tune.XXXXXX")" || die "mktemp failed"
  awk -v begin="$begin" -v end="$end" '
    $0 == begin { skip = 1; next }
    $0 == end { skip = 0; next }
    skip != 1 { print }
  ' "$file" > "$tmp" || die "Failed to rewrite managed block in $file"
  cat "$tmp" > "$file" || die "Failed to write $file"
  rm -f "$tmp"
}

append_httpd_managed_block() {
  if [[ "${#MISSING_HTTPD_LINES[@]}" -eq 0 ]]; then
    return
  fi
  local begin="# BEGIN OHS-WLS-WEBGATE-TUNER core"
  local end="# END OHS-WLS-WEBGATE-TUNER core"
  backup_once "$HTTPD_CONF"
  remove_managed_block "$HTTPD_CONF" "$begin" "$end"
  {
    printf '\n%s\n' "$begin"
    printf '# Added by tune-ohs-wls-webgate.sh. Review after patching or domain reconfiguration.\n'
    local line
    for line in "${MISSING_HTTPD_LINES[@]}"; do
      printf '%s\n' "$line"
    done
    printf '%s\n' "$end"
  } >> "$HTTPD_CONF"
  add_applied "Appended managed OHS core block to $HTTPD_CONF"
}

append_plugin_managed_block() {
  if [[ "${#MISSING_PLUGIN_LINES[@]}" -eq 0 ]]; then
    return
  fi
  local target="$PLUGIN_CONF"
  if [[ ! -f "$target" ]]; then
    mkdir -p "$(dirname "$target")" || die "Could not create $(dirname "$target")"
    : > "$target" || die "Could not create $target"
  fi
  local begin="# BEGIN OHS-WLS-WEBGATE-TUNER mod_wl_ohs"
  local end="# END OHS-WLS-WEBGATE-TUNER mod_wl_ohs"
  backup_once "$target"
  remove_managed_block "$target" "$begin" "$end"
  {
    printf '\n%s\n' "$begin"
    printf '# Added by tune-ohs-wls-webgate.sh. Place route-specific overrides inside Location blocks when required.\n'
    printf '<IfModule weblogic_module>\n'
    local line
    for line in "${MISSING_PLUGIN_LINES[@]}"; do
      printf '  %s\n' "$line"
    done
    printf '</IfModule>\n'
    printf '%s\n' "$end"
  } >> "$target"
  add_applied "Appended managed mod_wl_ohs block to $target"
}

apply_tuning() {
  local target_max="$1"
  local target_threads="$2"
  local target_server_limit="$3"
  local target_start="$4"
  local target_min_spare="$5"
  local target_max_spare="$6"
  local target_backlog="$7"
  local target_keepalive="$8"
  local target_timeout="$9"
  local target_wlio="${10}"

  if [[ ! -w "$HTTPD_CONF" ]]; then
    die "httpd.conf is not writable: $HTTPD_CONF"
  fi
  if [[ -f "$PLUGIN_CONF" && ! -w "$PLUGIN_CONF" ]]; then
    die "Plug-in config is not writable: $PLUGIN_CONF"
  fi

  upsert_httpd_directive "ServerLimit" "$target_server_limit"
  upsert_httpd_directive "StartServers" "$target_start"
  upsert_httpd_directive "ThreadsPerChild" "$target_threads"
  upsert_httpd_directive "MaxRequestWorkers" "$target_max"
  upsert_httpd_directive "MinSpareThreads" "$target_min_spare"
  upsert_httpd_directive "MaxSpareThreads" "$target_max_spare"
  upsert_httpd_directive "ListenBacklog" "$target_backlog"
  upsert_httpd_directive "KeepAlive" "On"
  upsert_httpd_directive "KeepAliveTimeout" "$target_keepalive"
  upsert_httpd_directive "Timeout" "$target_timeout"
  append_httpd_managed_block

  local dyn_value="ON"
  if [[ "$STATIC_BACKENDS" -eq 1 ]]; then
    dyn_value="OFF"
  fi

  if [[ -n "$WLS_CLUSTER_OVERRIDE" ]]; then
    upsert_plugin_directive "WebLogicCluster" "$WLS_CLUSTER_OVERRIDE"
  fi
  upsert_plugin_directive "DynamicServerList" "$dyn_value"
  upsert_plugin_directive "KeepAliveEnabled" "ON"
  upsert_plugin_directive "KeepAliveSecs" "20"
  upsert_plugin_directive "ConnectTimeoutSecs" "10"
  upsert_plugin_directive "ConnectRetrySecs" "2"
  upsert_plugin_directive "WLSocketTimeoutSecs" "2"
  upsert_plugin_directive "WLIOTimeoutSecs" "$target_wlio"
  upsert_plugin_directive "DebugConfigInfo" "OFF"

  if [[ -n "$WL_TEMP_DIR_OVERRIDE" ]]; then
    mkdir -p "$WL_TEMP_DIR_OVERRIDE" 2>/dev/null || true
    upsert_plugin_directive "WLTempDir" "$WL_TEMP_DIR_OVERRIDE"
  elif [[ "$CONFIG_FS_TYPE" =~ nfs|nfs4|cifs|smb|fuse ]]; then
    mkdir -p "/tmp/ohs-wl-proxy" 2>/dev/null || true
    upsert_plugin_directive "WLTempDir" "/tmp/ohs-wl-proxy"
  fi
  append_plugin_managed_block

  collect_config_files
}

write_os_tuning_file() {
  local file="$1"
  shift
  local dir
  dir="$(dirname "$file")"
  mkdir -p "$dir" || die "Could not create $dir"
  if [[ -e "$file" && ! -f "$file" ]]; then
    die "Refusing to overwrite non-regular file: $file"
  fi
  if [[ -f "$file" ]]; then
    [[ -w "$file" ]] || die "File is not writable: $file"
    backup_once "$file"
  else
    [[ -w "$dir" ]] || die "Directory is not writable: $dir"
  fi

  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/ohs-os-tune.XXXXXX")" || die "mktemp failed"
  {
    local line
    for line in "$@"; do
      printf '%s\n' "$line"
    done
  } > "$tmp" || die "Could not prepare $file"
  cat "$tmp" > "$file" || die "Could not write $file"
  chmod 0644 "$file" 2>/dev/null || true
  rm -f "$tmp"
}

apply_os_tuning() {
  [[ "$OS_TUNING" -eq 1 && "$APPLY_OS_TUNING" -eq 1 ]] || return

  local target_somaxconn="$1"
  local target_syn_backlog="$2"
  local target_port_range="$3"
  local target_fin_timeout="$4"
  local target_file_max="$5"
  local soft_nofile="$6"
  local hard_nofile="$7"
  local nproc_limit="$8"
  local uid
  uid="$(id -u 2>/dev/null || printf '1')"
  local override_file
  override_file="$(systemd_override_file)"

  if [[ "$uid" != "0" ]]; then
    if [[ "$SYSCTL_LOAD" -eq 1 || "$SYSCTL_FILE" = /etc/* || "$LIMITS_FILE" = /etc/* || "$override_file" = /etc/* || ( -n "$SYSTEMD_SERVICE" && "$SYSTEMD_RELOAD" -eq 1 ) ]]; then
      die "--apply-os-tuning needs root for /etc writes, sysctl loading, or systemd override creation. Run as root, or use custom --sysctl-file/--limits-file with --no-sysctl-load."
    fi
  fi

  detect_os_user
  info ""
  info "OS tuning apply"

  write_os_tuning_file "$SYSCTL_FILE" \
    "# Generated by tune-ohs-wls-webgate.sh for OHS/WebLogic/WebGate routing." \
    "# Review after OS patching, kernel upgrades, or capacity changes." \
    "net.core.somaxconn = $target_somaxconn" \
    "net.ipv4.tcp_max_syn_backlog = $target_syn_backlog" \
    "net.ipv4.ip_local_port_range = $target_port_range" \
    "net.ipv4.tcp_fin_timeout = $target_fin_timeout" \
    "fs.file-max = $target_file_max"
  add_applied "Wrote OS sysctl drop-in $SYSCTL_FILE"
  info "  Wrote $SYSCTL_FILE"

  if [[ "$SYSCTL_LOAD" -eq 1 ]]; then
    local sysctl_log="$REPORT_DIR/sysctl-load.log"
    if command -v sysctl >/dev/null 2>&1; then
      if sysctl -p "$SYSCTL_FILE" > "$sysctl_log" 2>&1; then
        add_applied "Loaded sysctl settings from $SYSCTL_FILE"
        info "  Loaded sysctl settings from $SYSCTL_FILE"
      else
        info "  WARN: sysctl -p $SYSCTL_FILE failed. See $sysctl_log"
        add_finding "[WARN] sysctl load failed for $SYSCTL_FILE. Review $sysctl_log and apply supported keys manually."
      fi
    else
      info "  WARN: sysctl command not found; settings were written but not loaded."
      add_finding "[WARN] sysctl command not found; settings were written but not loaded."
    fi
  else
    info "  Skipped live sysctl load by --no-sysctl-load"
  fi

  write_os_tuning_file "$LIMITS_FILE" \
    "# Generated by tune-ohs-wls-webgate.sh for OHS/WebLogic/WebGate routing." \
    "# These limits apply to new login/PAM sessions; systemd services need LimitNOFILE too." \
    "$OS_USER soft nofile $soft_nofile" \
    "$OS_USER hard nofile $hard_nofile" \
    "$OS_USER soft nproc $nproc_limit" \
    "$OS_USER hard nproc $nproc_limit"
  add_applied "Wrote OS limits drop-in $LIMITS_FILE"
  info "  Wrote $LIMITS_FILE"

  if [[ -n "$override_file" ]]; then
    write_os_tuning_file "$override_file" \
      "# Generated by tune-ohs-wls-webgate.sh for OHS/WebLogic/WebGate routing." \
      "[Service]" \
      "LimitNOFILE=$hard_nofile" \
      "LimitNPROC=$nproc_limit"
    add_applied "Wrote systemd override $override_file"
    info "  Wrote $override_file"

    if [[ "$SYSTEMD_RELOAD" -eq 1 ]]; then
      local systemd_log="$REPORT_DIR/systemd-daemon-reload.log"
      if command -v systemctl >/dev/null 2>&1; then
        if systemctl daemon-reload > "$systemd_log" 2>&1; then
          add_applied "Ran systemctl daemon-reload"
          info "  Ran systemctl daemon-reload"
        else
          info "  WARN: systemctl daemon-reload failed. See $systemd_log"
          add_finding "[WARN] systemctl daemon-reload failed. Review $systemd_log and run daemon-reload manually."
        fi
      else
        info "  WARN: systemctl not found; override was written but daemon-reload was not run."
        add_finding "[WARN] systemctl not found; override was written but daemon-reload was not run."
      fi
    else
      info "  Skipped systemd daemon-reload by --no-systemd-reload"
    fi
  fi
}

validate_config() {
  [[ "$VALIDATE" -eq 1 ]] || {
    info "Validation skipped by --no-validate."
    return
  }

  local httpd_bin=""
  if [[ -n "$ORACLE_HOME" && -x "$ORACLE_HOME/ohs/bin/httpd" ]]; then
    httpd_bin="$ORACLE_HOME/ohs/bin/httpd"
  elif command -v httpd >/dev/null 2>&1; then
    httpd_bin="$(command -v httpd)"
  elif command -v apachectl >/dev/null 2>&1; then
    httpd_bin="$(command -v apachectl)"
  fi

  if [[ -z "$httpd_bin" ]]; then
    add_finding "[WARN] Could not find httpd/apachectl for syntax validation. Run ORACLE_HOME/ohs/bin/httpd -t -f $HTTPD_CONF manually."
    return
  fi

  info ""
  info "Validation"
  local validation_log="$REPORT_DIR/httpd-validation.log"
  if "$httpd_bin" -t -f "$HTTPD_CONF" > "$validation_log" 2>&1; then
    info "  PASS: $httpd_bin -t -f $HTTPD_CONF"
  else
    info "  FAIL: $httpd_bin -t -f $HTTPD_CONF"
    info "  See: $validation_log"
    add_finding "[ERROR] OHS syntax validation failed after apply. Review validation log and restore backups from $BACKUP_DIR if needed."
  fi
}

print_findings() {
  info "Findings"
  if [[ "${#FINDINGS[@]}" -eq 0 ]]; then
    info "  No major warnings found by static inspection."
  else
    local f
    for f in "${FINDINGS[@]}"; do
      info "  $f"
    done
  fi
  info ""
}

print_apply_summary() {
  [[ "$APPLY" -eq 1 ]] || return
  info "Applied changes"
  if [[ "${#APPLIED_CHANGES[@]}" -eq 0 ]]; then
    info "  No config changes were applied."
  else
    local c
    for c in "${APPLIED_CHANGES[@]}"; do
      info "  $c"
    done
    info "  Backups: $BACKUP_DIR"
  fi
  info ""
}

print_next_steps() {
  info "Next steps"
  info "  1. Review the report and changed files before promoting to production."
  info "  2. In WebLogic-managed OHS domains, use your normal Fusion Middleware Control/WLST lifecycle so staging changes propagate correctly."
  info "  3. Restart OHS during a maintenance window and run a representative login/protected-resource load test."
  info "  4. Watch OHS metrics: busy/idle processes, request throughput, request processing time, active connections, 4xx/5xx, and mod_wl_ohs timing."
  info "  5. Watch WebLogic: execute thread saturation, AcceptBackLog, stuck threads, JDBC latency, and 503/CONNECTION_REFUSED events."
  info "  6. If OS limits or systemd overrides changed, restart the OHS/Node Manager launch service so new limits are inherited."
  info ""
  info "Report written to: $REPORT_FILE"
}

main() {
  parse_args "$@"
  discover_config_dir
  initialize_paths
  collect_config_files
  detect_filesystem_type
  detect_plugin_conf
  detect_modules

  local mpm
  mpm="$(get_mpm)"
  local cpu fd targets
  cpu="$(cpu_count)"
  fd="$(fd_limit)"
  targets="$(calc_targets "$cpu" "$fd")"
  IFS='|' read -r target_max target_threads target_server_limit target_start target_min_spare \
    target_max_spare target_backlog target_keepalive target_timeout target_wlio target_fd <<< "$targets"

  local os_targets target_somaxconn target_syn_backlog target_port_range target_fin_timeout \
    target_file_max soft_nofile hard_nofile nproc_limit
  if [[ "$OS_TUNING" -eq 1 ]]; then
    detect_os_user
    os_targets="$(build_os_targets "$target_backlog" "$target_fd" "$target_max")"
    IFS='|' read -r target_somaxconn target_syn_backlog target_port_range target_fin_timeout \
      target_file_max soft_nofile hard_nofile nproc_limit <<< "$os_targets"
    evaluate_os_state "$target_somaxconn" "$target_syn_backlog" "$target_port_range" \
      "$target_fin_timeout" "$target_file_max" "$soft_nofile"
  fi

  evaluate_current_state "$mpm" "$target_max" "$target_backlog" "$target_fd"
  print_current_state "$mpm"
  print_findings
  print_recommendations "$target_max" "$target_threads" "$target_server_limit" "$target_start" \
    "$target_min_spare" "$target_max_spare" "$target_backlog" "$target_keepalive" \
    "$target_timeout" "$target_wlio" "$target_fd"
  if [[ "$OS_TUNING" -eq 1 ]]; then
    print_os_recommendations "$target_somaxconn" "$target_syn_backlog" "$target_port_range" \
      "$target_fin_timeout" "$target_file_max" "$soft_nofile" "$hard_nofile" "$nproc_limit"
  else
    print_os_recommendations "" "" "" "" "" "" "" ""
  fi

  if [[ "$APPLY" -eq 1 ]]; then
    apply_tuning "$target_max" "$target_threads" "$target_server_limit" "$target_start" \
      "$target_min_spare" "$target_max_spare" "$target_backlog" "$target_keepalive" \
      "$target_timeout" "$target_wlio"
    apply_os_tuning "$target_somaxconn" "$target_syn_backlog" "$target_port_range" \
      "$target_fin_timeout" "$target_file_max" "$soft_nofile" "$hard_nofile" "$nproc_limit"
    validate_config
    print_apply_summary
  fi

  print_next_steps
}

main "$@"
