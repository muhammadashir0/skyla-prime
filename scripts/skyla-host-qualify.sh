#!/bin/sh
# SKYLA PRIME second-host qualification (v0.2.4, addresses HOST-01).
#
# Produces a machine-readable record of whether a host is capable of running the
# platform, then runs the full qualification suite and writes the results.
# Designed so a result from one host can be compared field-for-field with another.
#
#   scripts/skyla-host-qualify.sh check     capability report only (read-only)
#   scripts/skyla-host-qualify.sh run       check + full suite + summary
#
# Exits non-zero if any MANDATORY capability is missing, so it can gate CI.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${SKYLA_QUALIFY_OUT:-$ROOT/qualification-results}"
PY="${PYTHON:-python3}"
mkdir -p "$OUT"

say() { printf '%s\n' "$*" | tee -a "$OUT/capabilities.txt" >/dev/null; }
report() { printf '%-34s %s\n' "$1" "$2" | tee -a "$OUT/capabilities.txt"; }

check() {
    : > "$OUT/capabilities.txt"
    say "# SKYLA PRIME host capability report"
    say "# generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    say ""

    report "hostname" "$(hostname)"
    report "kernel" "$(uname -r)"
    report "arch" "$(uname -m)"
    report "distro" "$( (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || echo unknown)"
    report "cpus" "$(nproc 2>/dev/null || echo unknown)"
    report "memory_mb" "$(free -m 2>/dev/null | awk '/^Mem:/{print $2}')"
    report "python" "$($PY -c 'import sys;print(sys.version.split()[0])' 2>/dev/null || echo MISSING)"
    say ""

    # --- mandatory capabilities ------------------------------------------------
    fail=0
    chk() {  # chk <name> <command...>
        name="$1"; shift
        if "$@" >/dev/null 2>&1; then report "$name" "PRESENT"
        else report "$name" "MISSING"; fail=1; fi
    }

    say "## mandatory"
    chk "ip" command -v ip
    chk "iptables" sh -c 'command -v iptables || ls /usr/sbin/iptables'
    chk "ip6tables" sh -c 'command -v ip6tables || ls /usr/sbin/ip6tables'
    chk "iptables-save" sh -c 'command -v iptables-save || ls /usr/sbin/iptables-save'
    chk "iptables-restore" sh -c 'command -v iptables-restore || ls /usr/sbin/iptables-restore'
    chk "unshare" command -v unshare
    chk "setpriv" command -v setpriv
    chk "netns_usable" sh -c 'ip netns add skyla-probe && ip netns del skyla-probe'
    chk "netns_of_others" sh -c 'ip netns add skyla-probe2 && ip netns exec skyla-probe2 ip link && ip netns del skyla-probe2'

    say ""
    say "## cgroups"
    cgv=$(stat -fc %T /sys/fs/cgroup 2>/dev/null || echo unknown)
    report "cgroup_version" "$cgv"
    if [ "$cgv" = "cgroup2fs" ]; then report "cgroup_v2" "PRESENT"; else report "cgroup_v2" "MISSING"; fail=1; fi
    report "cgroup_controllers" "$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null)"
    report "cgroup_subtree" "$(cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null)"
    report "delegated_subtree_exists" "$([ -d /sys/fs/cgroup/skyla ] && echo yes || echo no)"

    say ""
    say "## kernel security features"
    ll=$($PY - <<'PY' 2>/dev/null || echo -1
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
r = libc.syscall(444, None, 0, 1)   # landlock_create_ruleset(NULL,0,1) -> ABI
print(r)
PY
)
    report "landlock_abi" "$ll"
    report "seccomp_built_in" "$(zgrep -q 'CONFIG_SECCOMP=y' /proc/config.gz 2>/dev/null && echo yes || echo unknown)"
    report "landlock_built_in" "$(zgrep -q 'CONFIG_SECURITY_LANDLOCK=y' /proc/config.gz 2>/dev/null && echo yes || echo unknown)"

    say ""
    say "## ipv6"
    v6=$(ip -6 addr show scope global 2>/dev/null | grep -c inet6 || true)
    report "global_ipv6_addrs" "${v6:-0}"
    say ""
    say "## result"
    if [ "$fail" = "0" ]; then say "CAPABLE"; else say "NOT_CAPABLE (see MISSING above)"; fi
    echo "capability report: $OUT/capabilities.txt"
    return "$fail"
}

run() {
    check || echo "warning: host is missing mandatory capabilities; continuing to record how the suite behaves" >&2
    log="$OUT/suite-$(date -u +%Y%m%dT%H%M%SZ).txt"
    echo "running suite -> $log"
    # Unprivileged, as required: the supervisor refuses to run untrusted jobs as root.
    ( cd "$ROOT" && $PY -m pytest tests/ -q -rs ) > "$log" 2>&1 || true
    tail -3 "$log"
    echo
    echo "=== skip accounting (every skip with its reason) ==="
    grep '^SKIPPED' "$log" | sed 's/^SKIPPED \[\([0-9]*\)\] /\1 x /' | cut -c1-150 | sort | uniq -c
    echo
    echo "results written to $OUT"
}

case "${1:-check}" in
    check) check ;;
    run)   run ;;
    *) echo "usage: $0 [check|run]" >&2; exit 2 ;;
esac
