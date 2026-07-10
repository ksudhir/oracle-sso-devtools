# OHS WebLogic/WebGate Performance Tuning Tool

`tune-ohs-wls-webgate.sh` audits and optionally tunes Oracle HTTP Server 12c/14c on Linux for environments where:

- OHS routes protected requests to WebLogic Server through `mod_wl_ohs`.
- Oracle WebGate is installed in OHS for SSO.
- Login/protected-resource traffic needs higher concurrency or cleaner failover behavior.

The script is audit-first. It writes a report by default and changes files only when you use the `apply` mode.

## What It Checks

- OHS staging config discovery from `DOMAIN_HOME`, `--config-dir`, or running `httpd -f` process arguments.
- WebGate and `mod_wl_ohs` presence.
- Linux/event or worker MPM tuning values:
  - `MaxRequestWorkers`
  - `ServerLimit`
  - `ThreadsPerChild`
  - `StartServers`
  - `MinSpareThreads`
  - `MaxSpareThreads`
  - `ListenBacklog`
  - `KeepAlive`
  - `KeepAliveTimeout`
  - `Timeout`
- WebLogic proxy plug-in routing values:
  - `WebLogicCluster`
  - `DynamicServerList`
  - `KeepAliveEnabled`
  - `KeepAliveSecs`
  - `ConnectTimeoutSecs`
  - `ConnectRetrySecs`
  - `WLSocketTimeoutSecs`
  - `WLIOTimeoutSecs`
  - `DebugConfigInfo`
  - `WLTempDir`
- Shared filesystem signals where OHS mutex or WebLogic proxy temp-file placement can hurt throughput.
- Linux runtime limits such as `ulimit -n`, `net.core.somaxconn`, `tcp_fin_timeout`, and ephemeral port range.
- Optional Linux OS tuning drop-ins for:
  - `/etc/sysctl.d/98-ohs-wls-webgate.conf`
  - `/etc/security/limits.d/98-ohs-wls-webgate.conf`
  - `/etc/systemd/system/<service>.service.d/override.conf`

## Basic Usage

Audit a known OHS instance:

```bash
./scripts/tune-ohs-wls-webgate.sh audit \
  --domain-home /u01/oracle/config/domains/prod_domain \
  --instance ohs1
```

Create an explicit plan with reviewable snippets:

```bash
./scripts/tune-ohs-wls-webgate.sh plan \
  --config-dir /u01/oracle/config/domains/prod_domain/config/fmwconfig/components/OHS/ohs1 \
  --profile webgate-balanced
```

Apply conservative edits after reviewing the plan:

```bash
./scripts/tune-ohs-wls-webgate.sh apply \
  --domain-home /u01/oracle/config/domains/prod_domain \
  --instance ohs1 \
  --profile webgate-balanced \
  --wls-cluster wls1.example.com:8001,wls2.example.com:8001
```

Apply OHS config and OS tuning together:

```bash
sudo ./scripts/tune-ohs-wls-webgate.sh apply \
  --domain-home /u01/oracle/config/domains/prod_domain \
  --instance ohs1 \
  --profile webgate-balanced \
  --wls-cluster wls1.example.com:8001,wls2.example.com:8001 \
  --apply-os-tuning \
  --os-user oracle
```

If OHS or Node Manager is launched by systemd, also write a service override so the process inherits the file descriptor limits:

```bash
sudo ./scripts/tune-ohs-wls-webgate.sh apply \
  --config-dir /u01/oracle/config/domains/prod_domain/config/fmwconfig/components/OHS/ohs1 \
  --apply-os-tuning \
  --os-user oracle \
  --systemd-service nodemanager
```

For a `WebLogicCluster` list that is not a real WebLogic cluster, keep dynamic cluster discovery disabled:

```bash
./scripts/tune-ohs-wls-webgate.sh apply \
  --config-dir /u01/oracle/config/domains/prod_domain/config/fmwconfig/components/OHS/ohs1 \
  --static-backends
```

## Profiles

- `webgate-balanced`: default. Raises concurrency moderately for OHS + WebGate + WebLogic routing.
- `throughput`: higher concurrency and backlog for load-tested high-volume tiers.
- `latency`: shorter client keep-alive and request timeout values.
- `conservative`: smaller changes for first-pass production hardening.

Every calculated value can be overridden:

```bash
./scripts/tune-ohs-wls-webgate.sh plan \
  --config-dir /path/to/OHS/ohs1 \
  --max-request-workers 1200 \
  --threads-per-child 50 \
  --listen-backlog 2048 \
  --keepalive-timeout 3 \
  --wl-io-timeout 180
```

## Apply Mode Behavior

In `apply` mode, the script:

1. Backs up every changed config file under the report directory.
2. Updates existing active directives when they are already present.
3. Adds a managed block only for directives that are missing.
4. Writes `mod_wl_ohs` defaults in an `<IfModule weblogic_module>` block when needed.
5. Runs `ORACLE_HOME/ohs/bin/httpd -t -f <httpd.conf>` when it can locate the OHS binary.

The script does not restart OHS. Restart during a maintenance window after reviewing validation output.

## OS Tuning Behavior

OS tuning is always shown in the audit and plan report unless you use `--no-os-tuning`.

The script writes OS files only when all of these are true:

- Mode is `apply`.
- `--apply-os-tuning` is supplied.
- The process has permission to write the target files.

By default, OS apply mode writes:

```text
/etc/sysctl.d/98-ohs-wls-webgate.conf
/etc/security/limits.d/98-ohs-wls-webgate.conf
```

The generated sysctl values are tied to the OHS target concurrency and backlog:

- `net.core.somaxconn`
- `net.ipv4.tcp_max_syn_backlog`
- `net.ipv4.ip_local_port_range`
- `net.ipv4.tcp_fin_timeout`
- `fs.file-max`

The generated process limits are tied to the calculated OHS `MaxRequestWorkers` and recommended runtime `nofile` value:

- `soft nofile`
- `hard nofile`
- `soft nproc`
- `hard nproc`

Use these options when needed:

```bash
--os-user oracle
--sysctl-file /etc/sysctl.d/98-ohs-wls-webgate.conf
--limits-file /etc/security/limits.d/98-ohs-wls-webgate.conf
--systemd-service nodemanager
--no-sysctl-load
--no-systemd-reload
```

Important: `/etc/security/limits.d` affects new PAM/login sessions. If OHS or Node Manager is launched by systemd, use `--systemd-service` or manually set `LimitNOFILE` and `LimitNPROC` on the service; otherwise the higher limits may not reach the OHS process.

## Important Operational Notes

- Edit the staging config directory, not `.../OHS/instances/<name>`, because runtime files can be overwritten.
- For WebLogic-managed OHS domains, follow your normal Fusion Middleware Control/WLST change process. If manual edits are allowed, stop the Administration Server first so changes are not overwritten by management operations.
- Do not blindly use `DynamicServerList ON` when `WebLogicCluster` is only a list of non-clustered managed servers. Use `--static-backends`.
- Size WebLogic `AcceptBackLog` and OS file descriptors along with OHS `MaxRequestWorkers`; OHS concurrency alone cannot fix refused backend connections.
- Keep OHS, WebGate, and `mod_wl_ohs` debug logging off during steady-state load tests.
- Restart OHS or the Node Manager/service that launches OHS after OS limits or systemd overrides change.

## Oracle Documentation References

- Oracle HTTP Server 12c Admin Guide: performance directives and monitoring.
  https://docs.oracle.com/en/middleware/fusion-middleware/web-tier/12.2.1.4/administer-ohs/man_server.html
- Oracle HTTP Server 14c Admin Guide.
  https://docs.oracle.com/en/middleware/fusion-middleware/web-tier/14.1.2/administer-ohs/index.html
- Oracle WebLogic Server Proxy Plug-Ins 14c: `mod_wl_ohs` parameters.
  https://docs.oracle.com/en/middleware/standalone/weblogic-server/14.1.1.0/develop-plugin/plugin_params.html
- Oracle WebLogic Server Proxy Plug-Ins 14c: Apache/OHS routing, dynamic server list, and connection failure guidance.
  https://docs.oracle.com/en/middleware/standalone/weblogic-server/14.1.1.0/develop-plugin/apache.html
