#!/bin/sh
# SKYLA PRIME — one-time root bootstrap for cgroup v2 delegation.
#
# Why this exists: on cgroup v2 an unprivileged process may only create/move into
# cgroups whose ENTIRE ancestor chain is delegated to it. It cannot delegate to
# itself. So a privileged step is required exactly once, at install time — the
# same contract as systemd's `Delegate=yes`.
#
# After this script runs, the service user owns /sys/fs/cgroup/skyla and every
# controller operation (mkdir, memory.max, pids.max, cpu.max, cgroup.kill) is
# performed WITHOUT privilege. The API never needs root at runtime.
#
# Idempotent: safe to re-run. Removes only its own subtree.
set -eu

SERVICE_USER="${SKYLA_SERVICE_USER:-user}"
ROOT=/sys/fs/cgroup/skyla

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (this is the one-time delegation step)" >&2
    exit 1
fi

if [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" != "cgroup2fs" ]; then
    echo "error: /sys/fs/cgroup is not cgroup2" >&2
    exit 1
fi

# Enable the controllers we require in the root subtree. Each may fail with EBUSY
# if another consumer holds them; we enable individually and report what stuck.
for ctrl in memory pids cpu; do
    if ! grep -qw "$ctrl" /sys/fs/cgroup/cgroup.controllers; then
        echo "error: controller '$ctrl' not available at root" >&2
        exit 1
    fi
    echo "+$ctrl" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
done

# Recreate our subtree from scratch so a re-run is clean.
if [ -d "$ROOT" ]; then
    find "$ROOT" -depth -type d -exec rmdir {} + 2>/dev/null || true
fi
mkdir -p "$ROOT"
echo "+memory +pids +cpu" > "$ROOT/cgroup.subtree_control" 2>/dev/null || true

if ! grep -qw memory "$ROOT/cgroup.controllers"; then
    echo "error: memory controller did not attach to $ROOT" >&2
    exit 1
fi

chown -R "$SERVICE_USER":"$SERVICE_USER" "$ROOT"
chmod 0755 "$ROOT"

echo "delegated: $ROOT -> $SERVICE_USER"
echo "root subtree_control: $(cat /sys/fs/cgroup/cgroup.subtree_control)"
echo "skyla subtree_control: $(cat "$ROOT/cgroup.subtree_control")"
echo "controllers: $(cat "$ROOT/cgroup.controllers")"
