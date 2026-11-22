#!/bin/sh
# SKYLA PRIME launcher.
#
# cgroup v2 will not let a process migrate workloads unless that process already
# lives inside the delegated subtree (write access is required on every ancestor,
# and /sys/fs/cgroup/cgroup.procs is root-owned). This launcher places the service
# process inside /sys/fs/cgroup/skyla/service before exec'ing it, which is the
# same contract systemd provides with `Delegate=yes`.
#
# v0.2.5 fix — POSIX `test -w` LIES ON CGROUPFS
# ---------------------------------------------
# The previous version decided with `[ -w "$SERVICE/cgroup.procs" ]`. On cgroupfs
# the kernel's write handler adds checks the POSIX mode bits do not reflect, so
# that test returns success while the subsequent write fails with EPERM. The
# write error was swallowed by `|| true`, the process stayed outside the subtree,
# and the launch appeared to succeed. That is why 18 cgroup tests skipped with
# "placement unavailable" while the bootstrap had in fact worked.
#
# The fix is to attempt the write and then CONFIRM it from /proc/self/cgroup.
# A launcher that cannot verify its own placement must say so loudly.
#
# Usage: scripts/skyla-run.sh <command> [args...]
#        SKYLA_LAUNCH_VIA_SUDO=1 (root step confined to placing the process)
set -eu

ROOT="${SKYLA_CGROUP_ROOT:-/sys/fs/cgroup/skyla}"
SERVICE="$ROOT/service"

if [ "$#" -eq 0 ]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 2
fi

# The delegation root must exist (run scripts/cgroup_bootstrap.sh as root once).
if [ ! -d "$ROOT" ]; then
    echo "warning: $ROOT does not exist; cgroup enforcement will be unavailable" >&2
    echo "         run: sudo scripts/cgroup_bootstrap.sh" >&2
    exec "$@"
fi

mkdir -p "$SERVICE" 2>/dev/null || true

# Verify placement by reading the kernel's own record, not by trusting -w.
in_service_cgroup() {
    current=$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null || echo "")
    [ "$current" = "/skyla/service" ]
}

if in_service_cgroup; then
    exec "$@"
fi

# Attempt the move (works when the subtree is delegated to this user).
if printf '%s' "$$" > "$SERVICE/cgroup.procs" 2>/dev/null && in_service_cgroup; then
    exec "$@"
fi

# Fall back to one narrowly-scoped root step only if the caller opted in.
if [ "${SKYLA_LAUNCH_VIA_SUDO:-0}" = "1" ]; then
    exec sudo -n sh -c 'mkdir -p "$1"; printf "%s" "$$" > "$1/cgroup.procs"; shift; exec "$@"' \
        sh "$SERVICE" "$@"
fi

# Not placed. This is NOT a silent degradation: the application detects it via
# placement_ok() and refuses to run untrusted workloads under the namespace
# provider. Say it here too so the operator sees the cause immediately.
echo "warning: cannot place the service into $SERVICE (write refused by the kernel)." >&2
echo "         cgroup enforcement will be reported unavailable; untrusted" >&2
echo "         execution will be REFUSED by the namespace provider." >&2
echo "         to delegate: sudo scripts/cgroup_bootstrap.sh" >&2
echo "         or launch with: SKYLA_LAUNCH_VIA_SUDO=1 $0 ..." >&2
exec "$@"
