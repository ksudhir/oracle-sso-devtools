#!/usr/bin/env bash
#
# Audit and optionally prepare/apply Oracle Access Manager WebLogic managed
# server tuning for Linux domains.
#
# Default mode is read-only audit. Apply mode writes a WLST script and can run
# it only when --run-wlst is explicitly supplied.

set -u

VERSION="1.0.0"
COMMAND="audit"
APPLY=0

DOMAIN_HOME="${DOMAIN_HOME:-}"
ORACLE_HOME="${ORACLE_HOME:-}"
SERVER_NAMES=""
PROFILE="oam-balanced"
REPORT_DIR=""
BACKUP_DIR=""
RUN_WLST=0
TUNE_JDBC=0
DATASOURCE_NAMES=""
JDK_MODE="auto"
ENABLE_WEBLOGIC_PLUGIN=1
NO_OS_TUNING=0
APPLY_OS_TUNING=0
OS_USER=""
SYSCTL_FILE="/etc/sysctl.d/98-oam-wls-managed-server.conf"
LIMITS_FILE="/etc/security/limits.d/98-oam-wls-managed-server.conf"
SYSTEMD_SERVICE=""
SYSTEMD_OVERRIDE_DIR=""
SYSCTL_LOAD=1
SYSTEMD_RELOAD=1
VERBOSE=0

HEAP_MB_OVERRIDE=""
METASPACE_MB_OVERRIDE=""
ACCEPT_BACKLOG_OVERRIDE=""
MAX_OPEN_SOCK_OVERRIDE=""
STUCK_THREAD_MAX_TIME_OVERRIDE=""
JDBC_INITIAL_OVERRIDE=""
JDBC_MIN_OVERRIDE=""
JDBC_MAX_OVERRIDE=""
JDBC_STATEMENT_CACHE_OVERRIDE=""

CONFIG_XML=""
REPORT_FILE=""
WLST_SCRIPT=""
CONFIG_BACKUP_DIR=""
TARGET_SERVERS=()
TARGET_DATASOURCES=()
FINDINGS=()
APPLIED_CHANGES=()

usage() {
  cat <<'EOF'
Usage:
  tune-oam-wls-managed-server.sh [audit|plan|apply] [options]

Modes:
  audit   Inspect OAM managed server/domain tuning and write a report. Default.
  plan    Same as audit, plus writes a reviewable WLST apply script.
  apply   Back up config, write WLST apply script, optionally run it with --run-wlst.

Common options:
  --domain-home PATH          WebLogic domain home. Uses DOMAIN_HOME when set.
  --oracle-home PATH          Oracle home. Uses ORACLE_HOME when set.
  --server NAME[,NAME]        Managed server(s). Auto-detects names containing "oam".
  --profile NAME              oam-balanced, conservative, latency, or throughput.
  --report-dir PATH           Directory for reports and generated WLST.
  --backup-dir PATH           Backup directory for apply mode.
  --run-wlst                  In apply mode, run the generated offline WLST script.
  --jdk auto|8|11|17          JVM argument style for GC logging. Default: auto.
  --disable-plugin-enabled    Do not set WeblogicPluginEnabled=true.
  --verbose                   Print extra discovery details.

JVM/WebLogic overrides:
  --heap-mb N                 Set -Xms/-Xmx in MB.
  --metaspace-mb N            Set MaxMetaspaceSize in MB.
  --accept-backlog N          Set ServerMBean AcceptBacklog.
  --max-open-sock-count N     Set ServerMBean MaxOpenSockCount.
  --stuck-thread-max-time N   Set ServerMBean StuckThreadMaxTime seconds.

JDBC options:
  --tune-jdbc                 Include selected JDBC data sources in generated WLST.
  --datasource-names A,B      Data sources to tune. Defaults to OAM/OPSS/MDS/Audit-like names.
  --jdbc-initial N            JDBC InitialCapacity.
  --jdbc-min N                JDBC MinCapacity.
  --jdbc-max N                JDBC MaxCapacity.
  --jdbc-statement-cache N    JDBC StatementCacheSize.

Linux OS options:
  --no-os-tuning              Skip OS checks and snippets.
  --apply-os-tuning           In apply mode, write sysctl, limits, and optional systemd files.
  --os-user USER              OS account that runs Node Manager/OAM. Auto-detected by owner.
  --sysctl-file PATH          Default: /etc/sysctl.d/98-oam-wls-managed-server.conf.
  --limits-file PATH          Default: /etc/security/limits.d/98-oam-wls-managed-server.conf.
  --systemd-service NAME      Optional service for LimitNOFILE/LimitNPROC override.
  --systemd-override-dir PATH Override directory for --systemd-service, useful for testing.
  --no-sysctl-load            Write sysctl file but do not load it with sysctl -p.
  --no-systemd-reload         Write systemd override but do not run systemctl daemon-reload.

Examples:
  ./tune-oam-wls-managed-server.sh audit \
    --domain-home /u01/oracle/config/domains/IAMGovernanceDomain

  ./tune-oam-wls-managed-server.sh plan \
    --domain-home /u01/oracle/config/domains/IAMGovernanceDomain \
    --server oam_server1 \
    --profile oam-balanced \
    --tune-jdbc

  ./tune-oam-wls-managed-server.sh apply \
    --domain-home /u01/oracle/config/domains/IAMGovernanceDomain \
    --oracle-home /u01/oracle/middleware \
    --server oam_server1,oam_server2 \
    --tune-jdbc \
    --run-wlst

Notes:
  - The script targets OAM 12c/14c WebLogic managed servers on Linux.
  - Apply mode uses offline WLST readDomain/updateDomain. Stop the Admin Server
    and affected managed servers, or follow your normal change-control process.
  - JVM argument tuning assumes servers are started by Node Manager using
    ServerStartMBean arguments. If your site uses custom shell scripts, copy the
    generated JVM arguments into those scripts instead.
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

require_value() {
  local option="$1"
  local value="${2:-}"
  if [[ -z "$value" ]]; then
    die "$option requires a value"
  fi
}

add_finding() {
  FINDINGS+=("$1")
}

add_applied() {
  APPLIED_CHANGES+=("$1")
}

split_csv_into_array() {
  local csv="$1"
  local array_name="$2"
  local old_ifs="$IFS"
  IFS=','
  local item
  for item in $csv; do
    item="$(printf '%s' "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    if [[ -n "$item" ]]; then
      eval "$array_name+=(\"\$item\")"
    fi
  done
  IFS="$old_ifs"
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
      --oracle-home)
        require_value "$1" "${2:-}"
        ORACLE_HOME="$2"
        shift 2
        ;;
      --server|--servers)
        require_value "$1" "${2:-}"
        SERVER_NAMES="$2"
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
      --run-wlst)
        RUN_WLST=1
        shift
        ;;
      --jdk)
        require_value "$1" "${2:-}"
        JDK_MODE="$2"
        shift 2
        ;;
      --disable-plugin-enabled)
        ENABLE_WEBLOGIC_PLUGIN=0
        shift
        ;;
      --heap-mb)
        require_value "$1" "${2:-}"
        HEAP_MB_OVERRIDE="$2"
        shift 2
        ;;
      --metaspace-mb)
        require_value "$1" "${2:-}"
        METASPACE_MB_OVERRIDE="$2"
        shift 2
        ;;
      --accept-backlog)
        require_value "$1" "${2:-}"
        ACCEPT_BACKLOG_OVERRIDE="$2"
        shift 2
        ;;
      --max-open-sock-count)
        require_value "$1" "${2:-}"
        MAX_OPEN_SOCK_OVERRIDE="$2"
        shift 2
        ;;
      --stuck-thread-max-time)
        require_value "$1" "${2:-}"
        STUCK_THREAD_MAX_TIME_OVERRIDE="$2"
        shift 2
        ;;
      --tune-jdbc)
        TUNE_JDBC=1
        shift
        ;;
      --datasource-names)
        require_value "$1" "${2:-}"
        DATASOURCE_NAMES="$2"
        shift 2
        ;;
      --jdbc-initial)
        require_value "$1" "${2:-}"
        JDBC_INITIAL_OVERRIDE="$2"
        shift 2
        ;;
      --jdbc-min)
        require_value "$1" "${2:-}"
        JDBC_MIN_OVERRIDE="$2"
        shift 2
        ;;
      --jdbc-max)
        require_value "$1" "${2:-}"
        JDBC_MAX_OVERRIDE="$2"
        shift 2
        ;;
      --jdbc-statement-cache)
        require_value "$1" "${2:-}"
        JDBC_STATEMENT_CACHE_OVERRIDE="$2"
        shift 2
        ;;
      --no-os-tuning)
        NO_OS_TUNING=1
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
    oam-balanced|conservative|latency|throughput) ;;
    *) die "Unknown profile: $PROFILE" ;;
  esac

  case "$JDK_MODE" in
    auto|8|11|17) ;;
    *) die "Unknown --jdk value: $JDK_MODE" ;;
  esac

  local opt
  for opt in "$HEAP_MB_OVERRIDE" "$METASPACE_MB_OVERRIDE" "$ACCEPT_BACKLOG_OVERRIDE" \
    "$MAX_OPEN_SOCK_OVERRIDE" "$STUCK_THREAD_MAX_TIME_OVERRIDE" "$JDBC_INITIAL_OVERRIDE" \
    "$JDBC_MIN_OVERRIDE" "$JDBC_MAX_OVERRIDE" "$JDBC_STATEMENT_CACHE_OVERRIDE"; do
    if [[ -n "$opt" ]] && ! is_number "$opt"; then
      die "Numeric override expected, got: $opt"
    fi
  done

  if [[ "$RUN_WLST" -eq 1 && "$COMMAND" != "apply" ]]; then
    die "--run-wlst can only be used with apply mode"
  fi
  if [[ "$APPLY_OS_TUNING" -eq 1 && "$COMMAND" != "apply" ]]; then
    die "--apply-os-tuning can only be used with apply mode"
  fi
  if [[ "$APPLY_OS_TUNING" -eq 1 && "$NO_OS_TUNING" -eq 1 ]]; then
    die "--apply-os-tuning cannot be combined with --no-os-tuning"
  fi
}

discover_domain() {
  if [[ -z "$DOMAIN_HOME" && -f "./config/config.xml" ]]; then
    DOMAIN_HOME="$(pwd -P)"
  fi

  [[ -n "$DOMAIN_HOME" ]] || die "Provide --domain-home or set DOMAIN_HOME"
  [[ -d "$DOMAIN_HOME" ]] || die "DOMAIN_HOME does not exist: $DOMAIN_HOME"
  DOMAIN_HOME="$(cd "$DOMAIN_HOME" && pwd -P)"
  CONFIG_XML="$DOMAIN_HOME/config/config.xml"
  [[ -f "$CONFIG_XML" ]] || die "Missing WebLogic config.xml: $CONFIG_XML"

  if [[ -z "$REPORT_DIR" ]]; then
    REPORT_DIR="${PWD}/oam-wls-managed-server-tuning-$(date +%Y%m%d-%H%M%S)"
  fi
  mkdir -p "$REPORT_DIR" || die "Could not create report directory: $REPORT_DIR"
  REPORT_FILE="$REPORT_DIR/oam-wls-managed-server-tuning-report.txt"
  : > "$REPORT_FILE" || die "Could not write report file: $REPORT_FILE"
  WLST_SCRIPT="$REPORT_DIR/apply-oam-wls-managed-server-tuning.py"

  if [[ -z "$BACKUP_DIR" ]]; then
    BACKUP_DIR="$REPORT_DIR/backups"
  fi
  CONFIG_BACKUP_DIR="$BACKUP_DIR/domain-config"
}

xml_first_tag_value() {
  local file="$1"
  local tag="$2"
  sed -n "s:.*<$tag>\(.*\)</$tag>.*:\1:p" "$file" 2>/dev/null | head -n 1
}

server_tag_value() {
  local server="$1"
  local tag="$2"
  awk -v target="$server" -v tag="$tag" '
    /<server>/ { in_server=1; block=""; name="" }
    in_server {
      block = block $0 "\n"
      if ($0 ~ "<name>") {
        n=$0
        sub(/^.*<name>/, "", n)
        sub(/<\/name>.*$/, "", n)
        if (name == "") name=n
      }
    }
    /<\/server>/ {
      if (in_server && name == target) {
        n=split(block, lines, "\n")
        for (i=1; i<=n; i++) {
          if (lines[i] ~ "<" tag ">") {
            v=lines[i]
            sub("^.*<" tag ">", "", v)
            sub("</" tag ">.*$", "", v)
            print v
            exit
          }
        }
      }
      in_server=0
    }
  ' "$CONFIG_XML"
}

server_start_arguments() {
  local server="$1"
  awk -v target="$server" '
    /<server>/ { in_server=1; in_start=0; block=""; name="" }
    in_server {
      if ($0 ~ "<name>") {
        n=$0
        sub(/^.*<name>/, "", n)
        sub(/<\/name>.*$/, "", n)
        if (name == "") name=n
      }
      if ($0 ~ "<server-start>") in_start=1
      if (in_start && $0 ~ "<arguments>") {
        v=$0
        sub(/^.*<arguments>/, "", v)
        sub(/<\/arguments>.*$/, "", v)
        arg=v
      }
      if ($0 ~ "</server-start>") in_start=0
    }
    /<\/server>/ {
      if (name == target && arg != "") print arg
      in_server=0
      arg=""
    }
  ' "$CONFIG_XML"
}

discover_servers() {
  TARGET_SERVERS=()
  if [[ -n "$SERVER_NAMES" ]]; then
    split_csv_into_array "$SERVER_NAMES" TARGET_SERVERS
  else
    local discovered
    discovered="$(awk '
      /<server>/ { in_server=1; name="" }
      in_server && /<name>/ {
        n=$0
        sub(/^.*<name>/, "", n)
        sub(/<\/name>.*$/, "", n)
        if (name == "") name=n
      }
      /<\/server>/ {
        lname=tolower(name)
        if (lname ~ /oam/ && lname !~ /admin/) print name
        in_server=0
      }
    ' "$CONFIG_XML")"
    local s
    while IFS= read -r s; do
      [[ -n "$s" ]] && TARGET_SERVERS+=("$s")
    done <<< "$discovered"
  fi

  if [[ "${#TARGET_SERVERS[@]}" -eq 0 ]]; then
    die "No OAM managed server discovered. Re-run with --server oam_server1"
  fi

  local server
  for server in "${TARGET_SERVERS[@]}"; do
    if [[ -z "$(server_tag_value "$server" "name")" ]]; then
      die "Server not found in config.xml: $server"
    fi
  done
}

discover_datasources() {
  TARGET_DATASOURCES=()
  if [[ -n "$DATASOURCE_NAMES" ]]; then
    split_csv_into_array "$DATASOURCE_NAMES" TARGET_DATASOURCES
    return
  fi

  local file name lname
  if [[ -d "$DOMAIN_HOME/config/jdbc" ]]; then
    for file in "$DOMAIN_HOME"/config/jdbc/*.xml; do
      [[ -f "$file" ]] || continue
      name="$(xml_first_tag_value "$file" "name")"
      lname="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"
      case "$lname" in
        *oam*|*opss*|*mds*|*iad*|*audit*)
          TARGET_DATASOURCES+=("$name")
          ;;
      esac
    done
  fi
}

cpu_count() {
  local n
  n="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || printf '2')"
  is_number "$n" || n=2
  printf '%s' "$n"
}

mem_mb() {
  local n
  n="$(awk '/MemTotal:/ { printf "%d", $2 / 1024 }' /proc/meminfo 2>/dev/null)"
  is_number "$n" || n=0
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

detect_jdk_major() {
  if [[ "$JDK_MODE" != "auto" ]]; then
    printf '%s' "$JDK_MODE"
    return
  fi

  local java_bin=""
  if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]]; then
    java_bin="${JAVA_HOME}/bin/java"
  elif command -v java >/dev/null 2>&1; then
    java_bin="$(command -v java)"
  fi

  if [[ -z "$java_bin" ]]; then
    printf '8'
    return
  fi

  local version major
  version="$("$java_bin" -version 2>&1 | awk -F\" '/version/ { print $2; exit }')"
  if [[ "$version" = 1.* ]]; then
    major="$(printf '%s' "$version" | awk -F. '{ print $2 }')"
  else
    major="$(printf '%s' "$version" | awk -F. '{ print $1 }')"
  fi
  is_number "$major" || major=8
  if (( major >= 17 )); then
    printf '17'
  elif (( major >= 11 )); then
    printf '11'
  else
    printf '8'
  fi
}

calc_targets() {
  local cpu="$1"
  local memory_mb="$2"
  local heap metaspace backlog maxsock stuck jdbc_initial jdbc_min jdbc_max stmt_cache

  case "$PROFILE" in
    conservative)
      heap=4096
      metaspace=512
      backlog=512
      maxsock=4096
      stuck=600
      jdbc_initial=5
      jdbc_min=10
      jdbc_max=50
      stmt_cache=30
      ;;
    latency)
      heap=6144
      metaspace=768
      backlog=1024
      maxsock=8192
      stuck=600
      jdbc_initial=10
      jdbc_min=20
      jdbc_max=80
      stmt_cache=50
      ;;
    throughput)
      heap=12288
      metaspace=1024
      backlog=2048
      maxsock=16384
      stuck=900
      jdbc_initial=20
      jdbc_min=30
      jdbc_max=150
      stmt_cache=75
      ;;
    oam-balanced)
      heap=8192
      metaspace=768
      backlog=1024
      maxsock=8192
      stuck=600
      jdbc_initial=10
      jdbc_min=20
      jdbc_max=100
      stmt_cache=50
      ;;
  esac

  if (( cpu <= 2 )); then
    heap="$(min "$heap" 4096)"
    jdbc_max="$(min "$jdbc_max" 50)"
  fi
  if (( memory_mb > 0 )); then
    local cap
    cap=$(( memory_mb * 60 / 100 ))
    cap="$(max "$cap" 2048)"
    heap="$(min "$heap" "$cap")"
  fi

  [[ -n "$HEAP_MB_OVERRIDE" ]] && heap="$HEAP_MB_OVERRIDE"
  [[ -n "$METASPACE_MB_OVERRIDE" ]] && metaspace="$METASPACE_MB_OVERRIDE"
  [[ -n "$ACCEPT_BACKLOG_OVERRIDE" ]] && backlog="$ACCEPT_BACKLOG_OVERRIDE"
  [[ -n "$MAX_OPEN_SOCK_OVERRIDE" ]] && maxsock="$MAX_OPEN_SOCK_OVERRIDE"
  [[ -n "$STUCK_THREAD_MAX_TIME_OVERRIDE" ]] && stuck="$STUCK_THREAD_MAX_TIME_OVERRIDE"
  [[ -n "$JDBC_INITIAL_OVERRIDE" ]] && jdbc_initial="$JDBC_INITIAL_OVERRIDE"
  [[ -n "$JDBC_MIN_OVERRIDE" ]] && jdbc_min="$JDBC_MIN_OVERRIDE"
  [[ -n "$JDBC_MAX_OVERRIDE" ]] && jdbc_max="$JDBC_MAX_OVERRIDE"
  [[ -n "$JDBC_STATEMENT_CACHE_OVERRIDE" ]] && stmt_cache="$JDBC_STATEMENT_CACHE_OVERRIDE"

  local fd_target
  fd_target=$(( maxsock + jdbc_max * 4 + 4096 ))
  fd_target="$(max "$fd_target" 16384)"

  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
    "$heap" "$metaspace" "$backlog" "$maxsock" "$stuck" \
    "$jdbc_initial" "$jdbc_min" "$jdbc_max" "$stmt_cache" "$fd_target"
}

build_jvm_args() {
  local server="$1"
  local heap="$2"
  local metaspace="$3"
  local jdk_major="$4"
  local log_dir="${DOMAIN_HOME}/servers/${server}/logs"
  local common="-Xms${heap}m -Xmx${heap}m -XX:MaxMetaspaceSize=${metaspace}m -XX:+UseG1GC -XX:MaxGCPauseMillis=200 -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=${log_dir} -Djava.awt.headless=true"

  if [[ "$jdk_major" = "8" ]]; then
    printf '%s %s' "$common" "-XX:+UseStringDeduplication -Xloggc:${log_dir}/gc-${server}.log -XX:+PrintGCDetails -XX:+PrintGCDateStamps -XX:+UseGCLogFileRotation -XX:NumberOfGCLogFiles=10 -XX:GCLogFileSize=50M"
  else
    printf '%s %s' "$common" "-XX:+UseStringDeduplication -Xlog:gc*,safepoint:file=${log_dir}/gc-${server}.log:time,uptime,level,tags:filecount=10,filesize=50M"
  fi
}

detect_os_user() {
  if [[ -n "$OS_USER" ]]; then
    return
  fi

  local owner
  owner="$(stat -c %U "$CONFIG_XML" 2>/dev/null || printf '')"
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
  local backlog="$1"
  local fd_target="$2"
  local maxsock="$3"
  local somaxconn syn_backlog file_max port_range fin_timeout swappiness nproc_limit

  somaxconn="$(max "$backlog" 1024)"
  local current
  current="$(sysctl_value net.core.somaxconn)"
  if is_number "$current"; then
    somaxconn="$(max "$somaxconn" "$current")"
  fi

  syn_backlog=$(( backlog * 2 ))
  syn_backlog="$(max "$syn_backlog" 2048)"
  current="$(sysctl_value net.ipv4.tcp_max_syn_backlog)"
  if is_number "$current"; then
    syn_backlog="$(max "$syn_backlog" "$current")"
  fi

  port_range="10240 65000"
  current="$(sysctl_value net.ipv4.ip_local_port_range)"
  local low high width
  low="$(printf '%s\n' "$current" | awk 'NF >= 2 { print $1 }')"
  high="$(printf '%s\n' "$current" | awk 'NF >= 2 { print $2 }')"
  if is_number "$low" && is_number "$high"; then
    width=$(( high - low + 1 ))
    if (( width >= 20000 )); then
      port_range="$low $high"
    fi
  fi

  fin_timeout=30
  current="$(sysctl_value net.ipv4.tcp_fin_timeout)"
  if is_number "$current" && (( current < fin_timeout )); then
    fin_timeout="$current"
  fi

  file_max=$(( fd_target * 8 ))
  file_max="$(max "$file_max" 1048576)"
  current="$(sysctl_value fs.file-max)"
  if is_number "$current"; then
    file_max="$(max "$file_max" "$current")"
  fi

  swappiness=10
  nproc_limit=$(( maxsock / 2 + 8192 ))
  nproc_limit="$(max "$nproc_limit" 16384)"

  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s' \
    "$somaxconn" "$syn_backlog" "$port_range" "$fin_timeout" \
    "$file_max" "$swappiness" "$fd_target" "$(( fd_target * 2 ))" "$nproc_limit"
}

print_current_state() {
  local jdk_major="$1"
  info "OAM WebLogic managed-server tuning report"
  info "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  info "Script version: $VERSION"
  info "Mode: $COMMAND"
  info "Profile: $PROFILE"
  info ""
  info "Discovered environment"
  info "  Domain home: $DOMAIN_HOME"
  info "  config.xml: $CONFIG_XML"
  info "  Oracle home: ${ORACLE_HOME:-<not supplied>}"
  info "  Target server(s): ${TARGET_SERVERS[*]}"
  info "  Target data source(s): $([[ "${#TARGET_DATASOURCES[@]}" -gt 0 ]] && printf '%s' "${TARGET_DATASOURCES[*]}" || printf '<none discovered>')"
  info "  JDK argument mode: $jdk_major"
  info ""

  local server
  for server in "${TARGET_SERVERS[@]}"; do
    info "Current WebLogic server settings: $server"
    info "  ListenPort = $(server_tag_value "$server" "listen-port")"
    info "  AcceptBacklog = $(server_tag_value "$server" "accept-backlog")"
    info "  MaxOpenSockCount = $(server_tag_value "$server" "max-open-sock-count")"
    info "  WeblogicPluginEnabled = $(server_tag_value "$server" "weblogic-plugin-enabled")"
    info "  StuckThreadMaxTime = $(server_tag_value "$server" "stuck-thread-max-time")"
    info "  ServerStart Arguments = $(server_start_arguments "$server")"
    info ""
  done

  if [[ "${#TARGET_DATASOURCES[@]}" -gt 0 ]]; then
    info "Current JDBC data source settings"
    local ds file
    for ds in "${TARGET_DATASOURCES[@]}"; do
      file="$(find "$DOMAIN_HOME/config/jdbc" -type f -name '*.xml' -exec grep -l "<name>$ds</name>" {} \; 2>/dev/null | head -n 1)"
      if [[ -n "$file" ]]; then
        info "  $ds (${file#$DOMAIN_HOME/})"
        info "    InitialCapacity = $(xml_first_tag_value "$file" "initial-capacity")"
        info "    MinCapacity = $(xml_first_tag_value "$file" "min-capacity")"
        info "    MaxCapacity = $(xml_first_tag_value "$file" "max-capacity")"
        info "    StatementCacheSize = $(xml_first_tag_value "$file" "statement-cache-size")"
        info "    TestConnectionsOnReserve = $(xml_first_tag_value "$file" "test-connections-on-reserve")"
        info "    SecondsToTrustAnIdlePoolConnection = $(xml_first_tag_value "$file" "seconds-to-trust-an-idle-pool-connection")"
      fi
    done
    info ""
  fi
}

evaluate_state() {
  local backlog="$1"
  local maxsock="$2"
  local heap="$3"
  local fd_target="$4"
  local server current args

  for server in "${TARGET_SERVERS[@]}"; do
    current="$(server_tag_value "$server" "accept-backlog")"
    if is_number "$current" && (( current < backlog )); then
      add_finding "[WARN] $server AcceptBacklog ($current) is below target ($backlog). Backend connection bursts from OHS can queue at WebLogic."
    fi

    current="$(server_tag_value "$server" "max-open-sock-count")"
    if is_number "$current" && (( current > 0 && current < maxsock )); then
      add_finding "[WARN] $server MaxOpenSockCount ($current) is below target ($maxsock). WebLogic can stop accepting new sockets at this threshold."
    fi

    current="$(server_tag_value "$server" "weblogic-plugin-enabled")"
    if [[ "$ENABLE_WEBLOGIC_PLUGIN" -eq 1 && "$(upper "$current")" != "TRUE" ]]; then
      add_finding "[WARN] $server WeblogicPluginEnabled is not true. Enable it when OAM is fronted by OHS/mod_wl_ohs."
    fi

    args="$(server_start_arguments "$server")"
    if [[ "$args" != *"-Xmx"* ]]; then
      add_finding "[WARN] $server ServerStart arguments do not show -Xmx. Node Manager starts may be using defaults or external scripts."
    elif ! printf '%s' "$args" | grep -Eq -- "-Xmx${heap}m|-Xmx$(( heap / 1024 ))g|-Xmx${heap}M"; then
      add_finding "[INFO] $server heap args differ from the profile target (${heap}m). Review load-test memory and GC data before changing."
    fi
  done

  local fd
  fd="$(fd_limit)"
  if is_number "$fd" && (( fd < fd_target )); then
    add_finding "[WARN] Current shell nofile limit ($fd) is below target ($fd_target). Ensure Node Manager/OAM inherits the higher limit."
  fi

  if [[ "$TUNE_JDBC" -eq 0 && "${#TARGET_DATASOURCES[@]}" -gt 0 ]]; then
    add_finding "[INFO] JDBC tuning is not enabled. Use --tune-jdbc after confirming database session capacity with the DBA."
  fi

  if [[ "$NO_OS_TUNING" -eq 0 && "$APPLY" -eq 1 && "$APPLY_OS_TUNING" -eq 0 ]]; then
    add_finding "[INFO] OS tuning apply is not enabled. Use --apply-os-tuning to write sysctl and process-limit drop-ins."
  fi
}

evaluate_os_state() {
  [[ "$NO_OS_TUNING" -eq 0 ]] || return
  local somaxconn="$1"
  local syn_backlog="$2"
  local port_range="$3"
  local fin_timeout="$4"
  local file_max="$5"
  local swappiness="$6"
  local soft_nofile="$7"

  detect_os_user
  local current
  current="$(sysctl_value net.core.somaxconn)"
  if is_number "$current" && (( current < somaxconn )); then
    add_finding "[WARN] net.core.somaxconn ($current) is below target ($somaxconn)."
  fi
  current="$(sysctl_value net.ipv4.tcp_max_syn_backlog)"
  if is_number "$current" && (( current < syn_backlog )); then
    add_finding "[WARN] net.ipv4.tcp_max_syn_backlog ($current) is below target ($syn_backlog)."
  fi
  current="$(sysctl_value fs.file-max)"
  if is_number "$current" && (( current < file_max )); then
    add_finding "[WARN] fs.file-max ($current) is below target ($file_max)."
  fi
  current="$(sysctl_value vm.swappiness)"
  if is_number "$current" && (( current > swappiness )); then
    add_finding "[INFO] vm.swappiness ($current) is above target ($swappiness). Avoiding JVM heap swap is important for OAM latency."
  fi

  local thp=""
  if [[ -r /sys/kernel/mm/transparent_hugepage/enabled ]]; then
    thp="$(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null)"
    if printf '%s' "$thp" | grep -q '\[always\]'; then
      add_finding "[INFO] Transparent Huge Pages appear to be set to always. Disable THP for latency-sensitive Java middleware unless your OS/JDK validation says otherwise."
    fi
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

print_recommendations() {
  local heap="$1"
  local metaspace="$2"
  local backlog="$3"
  local maxsock="$4"
  local stuck="$5"
  local jdbc_initial="$6"
  local jdbc_min="$7"
  local jdbc_max="$8"
  local stmt_cache="$9"
  local fd_target="${10}"
  local jdk_major="${11}"

  info "Calculated WebLogic/OAM targets"
  info "  Heap: -Xms${heap}m -Xmx${heap}m"
  info "  MaxMetaspaceSize: ${metaspace}m"
  info "  AcceptBacklog: $backlog"
  info "  MaxOpenSockCount: $maxsock"
  info "  StuckThreadMaxTime: $stuck"
  info "  WeblogicPluginEnabled: $([[ "$ENABLE_WEBLOGIC_PLUGIN" -eq 1 ]] && printf true || printf '<unchanged>')"
  info "  Recommended runtime nofile: $fd_target"
  info ""

  local server
  for server in "${TARGET_SERVERS[@]}"; do
    info "  JVM arguments for $server:"
    info "    $(build_jvm_args "$server" "$heap" "$metaspace" "$jdk_major")"
  done
  info ""

  info "Calculated JDBC targets"
  if [[ "${#TARGET_DATASOURCES[@]}" -eq 0 ]]; then
    info "  No OAM-like JDBC data sources were discovered."
  else
    info "  InitialCapacity: $jdbc_initial"
    info "  MinCapacity: $jdbc_min"
    info "  MaxCapacity: $jdbc_max"
    info "  StatementCacheSize: $stmt_cache"
    info "  SecondsToTrustAnIdlePoolConnection: 10"
    info "  TestConnectionsOnReserve: false"
    if [[ "$TUNE_JDBC" -eq 0 ]]; then
      info "  WLST will not change JDBC pools unless --tune-jdbc is supplied."
    fi
  fi
  info ""
}

print_os_recommendations() {
  if [[ "$NO_OS_TUNING" -eq 1 ]]; then
    info "Linux OS tuning"
    info "  Skipped by --no-os-tuning."
    info ""
    return
  fi

  local somaxconn="$1"
  local syn_backlog="$2"
  local port_range="$3"
  local fin_timeout="$4"
  local file_max="$5"
  local swappiness="$6"
  local soft_nofile="$7"
  local hard_nofile="$8"
  local nproc_limit="$9"
  local override_file
  override_file="$(systemd_override_file)"
  detect_os_user

  info "Linux OS tuning"
  info "  OAM OS user: $OS_USER"
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
  info "  vm.swappiness = $(sysctl_value vm.swappiness)"
  if [[ -r /sys/kernel/mm/transparent_hugepage/enabled ]]; then
    info "  transparent_hugepage/enabled = $(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null)"
  fi
  info "  current shell nofile = $(fd_limit)"
  info ""
  info "Recommended sysctl drop-in"
  info "  $SYSCTL_FILE:"
  info "    net.core.somaxconn = $somaxconn"
  info "    net.ipv4.tcp_max_syn_backlog = $syn_backlog"
  info "    net.ipv4.ip_local_port_range = $port_range"
  info "    net.ipv4.tcp_fin_timeout = $fin_timeout"
  info "    fs.file-max = $file_max"
  info "    vm.swappiness = $swappiness"
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

python_list() {
  local item
  printf '['
  local first=1
  for item in "$@"; do
    if [[ "$first" -eq 0 ]]; then
      printf ', '
    fi
    first=0
    printf '"%s"' "$(printf '%s' "$item" | sed 's/\\/\\\\/g;s/"/\\"/g')"
  done
  printf ']'
}

write_wlst_script() {
  local heap="$1"
  local metaspace="$2"
  local backlog="$3"
  local maxsock="$4"
  local stuck="$5"
  local jdbc_initial="$6"
  local jdbc_min="$7"
  local jdbc_max="$8"
  local stmt_cache="$9"
  local jdk_major="${10}"

  local servers_py datasources_py
  servers_py="$(python_list "${TARGET_SERVERS[@]}")"
  datasources_py="$(python_list "${TARGET_DATASOURCES[@]}")"

  cat > "$WLST_SCRIPT" <<EOF
# Generated by tune-oam-wls-managed-server.sh $VERSION.
# Offline WLST script for OAM managed server tuning.

domain_home = r'''$DOMAIN_HOME'''
servers = $servers_py
datasources = $datasources_py
tune_jdbc = $([[ "$TUNE_JDBC" -eq 1 ]] && printf 'True' || printf 'False')
enable_plugin = $([[ "$ENABLE_WEBLOGIC_PLUGIN" -eq 1 ]] && printf 'True' || printf 'False')

heap_mb = $heap
metaspace_mb = $metaspace
accept_backlog = $backlog
max_open_sock_count = $maxsock
stuck_thread_max_time = $stuck
jdbc_initial = $jdbc_initial
jdbc_min = $jdbc_min
jdbc_max = $jdbc_max
jdbc_statement_cache = $stmt_cache
jdk_major = '$jdk_major'

def log(msg):
    print('[oam-wls-tuner] ' + str(msg))

def server_jvm_args(server):
    log_dir = domain_home + '/servers/' + server + '/logs'
    common = '-Xms%dm -Xmx%dm -XX:MaxMetaspaceSize=%dm -XX:+UseG1GC -XX:MaxGCPauseMillis=200 -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=%s -Djava.awt.headless=true' % (heap_mb, heap_mb, metaspace_mb, log_dir)
    if jdk_major == '8':
        return common + ' -XX:+UseStringDeduplication -Xloggc:%s/gc-%s.log -XX:+PrintGCDetails -XX:+PrintGCDateStamps -XX:+UseGCLogFileRotation -XX:NumberOfGCLogFiles=10 -XX:GCLogFileSize=50M' % (log_dir, server)
    return common + ' -XX:+UseStringDeduplication -Xlog:gc*,safepoint:file=%s/gc-%s.log:time,uptime,level,tags:filecount=10,filesize=50M' % (log_dir, server)

def merge_args(existing, desired):
    drop_prefixes = [
        '-Xms', '-Xmx', '-Xmn', '-Xloggc:', '-Xlog:gc',
        '-XX:MaxMetaspaceSize=', '-XX:MaxPermSize=',
        '-XX:+UseG1GC', '-XX:+UseParallelGC', '-XX:+UseConcMarkSweepGC',
        '-XX:+UseStringDeduplication', '-XX:MaxGCPauseMillis=',
        '-XX:+PrintGCDetails', '-XX:+PrintGCDateStamps',
        '-XX:+UseGCLogFileRotation', '-XX:NumberOfGCLogFiles=',
        '-XX:GCLogFileSize=', '-XX:+HeapDumpOnOutOfMemoryError',
        '-XX:HeapDumpPath='
    ]
    kept = []
    for token in (existing or '').split():
        drop = False
        for prefix in drop_prefixes:
            if token.startswith(prefix):
                drop = True
                break
        if not drop:
            kept.append(token)
    for token in desired.split():
        if token not in kept:
            kept.append(token)
    return ' '.join(kept)

readDomain(domain_home)

for server in servers:
    path = '/Servers/' + server
    try:
        cd(path)
    except:
        log('WARN: server not found, skipping ' + server)
        continue
    log('Tuning server ' + server)
    cmo.setAcceptBacklog(accept_backlog)
    cmo.setMaxOpenSockCount(max_open_sock_count)
    cmo.setStuckThreadMaxTime(stuck_thread_max_time)
    if enable_plugin:
        cmo.setWeblogicPluginEnabled(True)
    try:
        cd(path + '/ServerStart/' + server)
        existing = cmo.getArguments()
        cmo.setArguments(merge_args(existing, server_jvm_args(server)))
    except:
        log('WARN: could not update ServerStart arguments for ' + server + '. If this server uses custom scripts, copy JVM arguments from the report.')

if tune_jdbc:
    for ds in datasources:
        path = '/JDBCSystemResources/' + ds + '/JDBCResource/' + ds + '/JDBCConnectionPoolParams/' + ds
        try:
            cd(path)
        except:
            log('WARN: JDBC pool not found, skipping ' + ds)
            continue
        log('Tuning JDBC data source ' + ds)
        cmo.setInitialCapacity(jdbc_initial)
        cmo.setMinCapacity(jdbc_min)
        cmo.setMaxCapacity(jdbc_max)
        cmo.setStatementCacheSize(jdbc_statement_cache)
        cmo.setSecondsToTrustAnIdlePoolConnection(10)
        cmo.setTestConnectionsOnReserve(False)

updateDomain()
closeDomain()
log('Completed. Restart affected managed servers for changes to take effect.')
EOF
  add_applied "Wrote WLST tuning script $WLST_SCRIPT"
}

backup_domain_config() {
  mkdir -p "$CONFIG_BACKUP_DIR" || die "Could not create backup directory: $CONFIG_BACKUP_DIR"
  cp -p "$CONFIG_XML" "$CONFIG_BACKUP_DIR/config.xml.bak" || die "Could not back up config.xml"
  if [[ -d "$DOMAIN_HOME/config/jdbc" ]]; then
    mkdir -p "$CONFIG_BACKUP_DIR/jdbc" || die "Could not create JDBC backup directory"
    find "$DOMAIN_HOME/config/jdbc" -type f -name '*.xml' -exec cp -p {} "$CONFIG_BACKUP_DIR/jdbc/" \; 2>/dev/null
  fi
  add_applied "Backed up domain config under $CONFIG_BACKUP_DIR"
}

run_wlst_script() {
  [[ "$RUN_WLST" -eq 1 ]] || return
  local wlst=""
  if [[ -n "$ORACLE_HOME" && -x "$ORACLE_HOME/oracle_common/common/bin/wlst.sh" ]]; then
    wlst="$ORACLE_HOME/oracle_common/common/bin/wlst.sh"
  elif [[ -n "$ORACLE_HOME" && -x "$ORACLE_HOME/wlserver/common/bin/wlst.sh" ]]; then
    wlst="$ORACLE_HOME/wlserver/common/bin/wlst.sh"
  elif command -v wlst.sh >/dev/null 2>&1; then
    wlst="$(command -v wlst.sh)"
  fi

  [[ -n "$wlst" ]] || die "Could not find wlst.sh. Provide --oracle-home or run generated script manually: $WLST_SCRIPT"
  local log_file="$REPORT_DIR/wlst-apply.log"
  if "$wlst" "$WLST_SCRIPT" > "$log_file" 2>&1; then
    add_applied "Ran WLST tuning script successfully. Log: $log_file"
  else
    add_finding "[ERROR] WLST apply failed. Review $log_file and restore backups from $CONFIG_BACKUP_DIR if needed."
    die "WLST apply failed. See $log_file"
  fi
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
    mkdir -p "$BACKUP_DIR" || die "Could not create backup directory: $BACKUP_DIR"
    cp -p "$file" "$BACKUP_DIR/$(basename "$file").bak" || die "Could not back up $file"
  else
    [[ -w "$dir" ]] || die "Directory is not writable: $dir"
  fi
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/oam-os-tune.XXXXXX")" || die "mktemp failed"
  local line
  for line in "$@"; do
    printf '%s\n' "$line"
  done > "$tmp"
  cat "$tmp" > "$file" || die "Could not write $file"
  chmod 0644 "$file" 2>/dev/null || true
  rm -f "$tmp"
}

apply_os_tuning() {
  [[ "$NO_OS_TUNING" -eq 0 && "$APPLY_OS_TUNING" -eq 1 ]] || return
  local somaxconn="$1"
  local syn_backlog="$2"
  local port_range="$3"
  local fin_timeout="$4"
  local file_max="$5"
  local swappiness="$6"
  local soft_nofile="$7"
  local hard_nofile="$8"
  local nproc_limit="$9"
  local override_file
  override_file="$(systemd_override_file)"

  local uid
  uid="$(id -u 2>/dev/null || printf '1')"
  if [[ "$uid" != "0" ]]; then
    if [[ "$SYSCTL_LOAD" -eq 1 || "$SYSCTL_FILE" = /etc/* || "$LIMITS_FILE" = /etc/* || "$override_file" = /etc/* || ( -n "$SYSTEMD_SERVICE" && "$SYSTEMD_RELOAD" -eq 1 ) ]]; then
      die "--apply-os-tuning needs root for /etc writes, sysctl loading, or systemd reload. Run as root, or use custom target files with --no-sysctl-load and --no-systemd-reload."
    fi
  fi

  detect_os_user
  info ""
  info "OS tuning apply"
  write_os_tuning_file "$SYSCTL_FILE" \
    "# Generated by tune-oam-wls-managed-server.sh for OAM/WebLogic managed servers." \
    "net.core.somaxconn = $somaxconn" \
    "net.ipv4.tcp_max_syn_backlog = $syn_backlog" \
    "net.ipv4.ip_local_port_range = $port_range" \
    "net.ipv4.tcp_fin_timeout = $fin_timeout" \
    "fs.file-max = $file_max" \
    "vm.swappiness = $swappiness"
  add_applied "Wrote OS sysctl drop-in $SYSCTL_FILE"
  info "  Wrote $SYSCTL_FILE"

  if [[ "$SYSCTL_LOAD" -eq 1 ]]; then
    local sysctl_log="$REPORT_DIR/sysctl-load.log"
    if sysctl -p "$SYSCTL_FILE" > "$sysctl_log" 2>&1; then
      add_applied "Loaded sysctl settings from $SYSCTL_FILE"
      info "  Loaded sysctl settings from $SYSCTL_FILE"
    else
      add_finding "[WARN] sysctl load failed for $SYSCTL_FILE. Review $sysctl_log."
      info "  WARN: sysctl -p failed. See $sysctl_log"
    fi
  else
    info "  Skipped live sysctl load by --no-sysctl-load"
  fi

  write_os_tuning_file "$LIMITS_FILE" \
    "# Generated by tune-oam-wls-managed-server.sh for OAM/WebLogic managed servers." \
    "$OS_USER soft nofile $soft_nofile" \
    "$OS_USER hard nofile $hard_nofile" \
    "$OS_USER soft nproc $nproc_limit" \
    "$OS_USER hard nproc $nproc_limit"
  add_applied "Wrote OS limits drop-in $LIMITS_FILE"
  info "  Wrote $LIMITS_FILE"

  if [[ -n "$override_file" ]]; then
    write_os_tuning_file "$override_file" \
      "# Generated by tune-oam-wls-managed-server.sh for OAM/WebLogic managed servers." \
      "[Service]" \
      "LimitNOFILE=$hard_nofile" \
      "LimitNPROC=$nproc_limit"
    add_applied "Wrote systemd override $override_file"
    info "  Wrote $override_file"
    if [[ "$SYSTEMD_RELOAD" -eq 1 ]]; then
      local systemd_log="$REPORT_DIR/systemd-daemon-reload.log"
      if systemctl daemon-reload > "$systemd_log" 2>&1; then
        add_applied "Ran systemctl daemon-reload"
        info "  Ran systemctl daemon-reload"
      else
        add_finding "[WARN] systemctl daemon-reload failed. Review $systemd_log."
        info "  WARN: systemctl daemon-reload failed. See $systemd_log"
      fi
    else
      info "  Skipped systemd daemon-reload by --no-systemd-reload"
    fi
  fi
}

print_apply_summary() {
  [[ "$APPLY" -eq 1 || "$COMMAND" = "plan" ]] || return
  info "Generated artifacts"
  info "  WLST script: $WLST_SCRIPT"
  if [[ "$APPLY" -eq 1 ]]; then
    info "  Backups: $BACKUP_DIR"
  fi
  info ""
  if [[ "$APPLY" -eq 1 ]]; then
    info "Applied/prepared changes"
    if [[ "${#APPLIED_CHANGES[@]}" -eq 0 ]]; then
      info "  No changes were prepared."
    else
      local c
      for c in "${APPLIED_CHANGES[@]}"; do
        info "  $c"
      done
    fi
    if [[ "$RUN_WLST" -eq 0 ]]; then
      info "  WLST was not run. Re-run with --run-wlst, or run the generated script manually with wlst.sh."
    fi
    info ""
  fi
}

print_next_steps() {
  info "Next steps"
  info "  1. Review the report and generated WLST script."
  info "  2. Confirm JDBC MaxCapacity with the database team before enabling --tune-jdbc in production."
  info "  3. Stop affected OAM managed servers before offline WLST apply, or follow your site WLST/FMW Control process."
  info "  4. Restart OAM managed servers after JVM, ServerStart, socket, JDBC, or OS limit changes."
  info "  5. Load test protected-resource login flows and watch execute thread queueing, JDBC waiters, GC pauses, heap occupancy, open sockets, and OHS 503/CONNECTION_REFUSED events."
  info ""
  info "Report written to: $REPORT_FILE"
}

main() {
  parse_args "$@"
  discover_domain
  discover_servers
  discover_datasources

  local cpu memory targets heap metaspace backlog maxsock stuck jdbc_initial jdbc_min jdbc_max stmt_cache fd_target
  cpu="$(cpu_count)"
  memory="$(mem_mb)"
  targets="$(calc_targets "$cpu" "$memory")"
  IFS='|' read -r heap metaspace backlog maxsock stuck jdbc_initial jdbc_min jdbc_max stmt_cache fd_target <<< "$targets"
  local jdk_major
  jdk_major="$(detect_jdk_major)"

  local os_targets somaxconn syn_backlog port_range fin_timeout file_max swappiness soft_nofile hard_nofile nproc_limit
  if [[ "$NO_OS_TUNING" -eq 0 ]]; then
    os_targets="$(build_os_targets "$backlog" "$fd_target" "$maxsock")"
    IFS='|' read -r somaxconn syn_backlog port_range fin_timeout file_max swappiness soft_nofile hard_nofile nproc_limit <<< "$os_targets"
    evaluate_os_state "$somaxconn" "$syn_backlog" "$port_range" "$fin_timeout" "$file_max" "$swappiness" "$soft_nofile"
  fi

  evaluate_state "$backlog" "$maxsock" "$heap" "$fd_target"
  print_current_state "$jdk_major"
  print_findings
  print_recommendations "$heap" "$metaspace" "$backlog" "$maxsock" "$stuck" \
    "$jdbc_initial" "$jdbc_min" "$jdbc_max" "$stmt_cache" "$fd_target" "$jdk_major"
  if [[ "$NO_OS_TUNING" -eq 0 ]]; then
    print_os_recommendations "$somaxconn" "$syn_backlog" "$port_range" "$fin_timeout" \
      "$file_max" "$swappiness" "$soft_nofile" "$hard_nofile" "$nproc_limit"
  else
    print_os_recommendations "" "" "" "" "" "" "" "" ""
  fi

  if [[ "$COMMAND" = "plan" || "$APPLY" -eq 1 ]]; then
    write_wlst_script "$heap" "$metaspace" "$backlog" "$maxsock" "$stuck" \
      "$jdbc_initial" "$jdbc_min" "$jdbc_max" "$stmt_cache" "$jdk_major"
  fi

  if [[ "$APPLY" -eq 1 ]]; then
    backup_domain_config
    apply_os_tuning "$somaxconn" "$syn_backlog" "$port_range" "$fin_timeout" \
      "$file_max" "$swappiness" "$soft_nofile" "$hard_nofile" "$nproc_limit"
    run_wlst_script
  fi

  print_apply_summary
  print_next_steps
}

main "$@"
