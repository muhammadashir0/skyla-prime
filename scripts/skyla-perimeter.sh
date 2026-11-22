#!/bin/sh
# SKYLA PRIME network perimeter (v0.2.3, closes B-01).
#
# Builds a network namespace whose ONLY reachable peer is the egress proxy, and
# proves it. This is a one-time deploy step requiring root (CAP_NET_ADMIN); the
# service itself then runs unprivileged and enters the namespace per call.
#
#   scripts/skyla-perimeter.sh setup     create + verify
#   scripts/skyla-perimeter.sh verify    verify only (non-destructive)
#   scripts/skyla-perimeter.sh status    show current state
#   scripts/skyla-perimeter.sh destroy   remove
#
# The boundary is the routing table, not a filter: the namespace has one /30
# interface, a route to the proxy host and NO default route. A packet to any other
# address fails with ENETUNREACH before any application code runs.
set -eu

NS="${SKYLA_PERIMETER_NS:-skyla-egress}"
GW="${SKYLA_PERIMETER_GW_NS:-skyla-egress-gw}"
PROXY_PORT="${SKYLA_EGRESS_PORT:-8155}"
PY="${PYTHON:-python3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[ $# -ge 1 ] || usage

case "$1" in
setup)
    "$PY" - "$ROOT" "$NS" "$GW" "$PROXY_PORT" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
from skyla.perimeter import EgressPerimeter
ns, gw, port = sys.argv[2], sys.argv[3], int(sys.argv[4])

p = EgressPerimeter(ns, gateway_name=gw, proxy_port=port)
p.create()
st = p.verify()
print("namespace :", st.namespace)
print("interfaces:", st.interfaces_in_ns)
print("default route present:", st.has_default_route)
print("ipv6 present           :", st.ipv6_present)
if not st.available:
    print("PERIMETER UNAVAILABLE:", st.reason)
    raise SystemExit(1)

proof = p.prove_no_egress()
print("\n-- egress proof from INSIDE the namespace --")
for k, v in proof["inside"].items():
    print(f"  {k:16s} {v}")
print("-- host control (same probe, unconfined) --")
for k, v in proof["host_control"].items():
    print(f"  {k:16s} {v}")
print("\nhost_has_network:", proof["host_has_network"])
print("leaked           :", proof["leaked"])
print("ISOLATED         :", proof["isolated"])
if not proof["isolated"]:
    print("PERIMETER FAILED: traffic escaped the namespace")
    raise SystemExit(1)
print("\nperimeter established and proven")
EOF
    ;;
verify)
    "$PY" - "$ROOT" "$NS" "$GW" "$PROXY_PORT" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
from skyla.perimeter import EgressPerimeter
p = EgressPerimeter(sys.argv[2], gateway_name=sys.argv[3],
                    proxy_port=int(sys.argv[4]))
st = p.verify()
print("available:", st.available, "|", st.reason or "ok")
print("interfaces:", st.interfaces_in_ns, "| default route:", st.has_default_route)
proof = p.prove_no_egress()
print("isolated:", proof["isolated"], "| leaked:", proof["leaked"])
raise SystemExit(0 if (st.available and proof["isolated"]) else 1)
EOF
    ;;
status)
    ip netns list 2>/dev/null | grep -q "^$NS" && echo "namespace '$NS': present" \
        || echo "namespace '$NS': absent"
    ip netns exec "$NS" ip route 2>/dev/null || true
    ip netns exec "$NS" ip -brief addr 2>/dev/null || true
    ;;
destroy)
    ip netns del "$NS" 2>/dev/null && echo "namespace '$NS' removed" || echo "namespace '$NS' already absent"
    ip netns del "$GW" 2>/dev/null && echo "gateway '$GW' removed" || echo "gateway '$GW' already absent"
    ip link del "$NS-gw" 2>/dev/null || true
    ;;
*)
    usage
    ;;
esac
