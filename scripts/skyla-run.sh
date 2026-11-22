#!/bin/sh
# SKYLA PRIME launcher.
#
# cgroup v2 will not let a process migrate workloads unless that process already
# lives inside the delegated subtree (write access is required on every ancestor,
# and /sys/fs/cgroup/cgroup.procs is root-owned). This launcher places the service
# process inside /sys/fs/cgroup/skyla/service before exec'ing it, which is the
# same contract systemd provides with `Delegate=yes`.
#
# Usage: scripts/skyla-run.sh <command> [args...]
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

# If we cannot move ourselves in, START ANYWAY but let the application detect the
# absence of enforcement and refuse untrusted workloads. Never pretend.
if [ -w "$SERVICE/cgroup.procs" ]; then
    printf '%s' "$$" > "$SERVICE/cgroup.procs" 2>/dev/null || true
    exec "$@"
fi

# Fall back to root only if it is passwordless AND the caller asked for it.
if [ "${SKYLA_LAUNCH_VIA_SUDO:-0}" = "1" ]; then
    exec sudo -n sh -c 'mkdir -p "$1"; printf "%s" "$$" > "$1/cgroup.procs"; shift; exec "$@"' \
        sh "$SERVICE" "$@"
fi

echo "warning: cannot place the service into $SERVICE (no write access)." >&2
echo "         cgroup enforcement will be reported unavailable; untrusted" >&2
echo "         execution will be REFUSED." >&2
exec "$@"
