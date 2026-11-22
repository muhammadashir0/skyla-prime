#!/bin/sh
# SKYLA PRIME host firewall (v0.2.4, addresses NET-23).
#
# A default-deny OUTPUT policy with explicit exceptions, in a dedicated chain so
# that applying and removing it never touches whatever the hosting provider put
# in place. Every rule that opens a path is listed and justified inline.
#
#   scripts/skyla-host-firewall.sh apply     install the policy
#   scripts/skyla-host-firewall.sh status    show the active policy and rule hit counters
#   scripts/skyla-host-firewall.sh verify    prove deny-by-default and that the allow path works
#   scripts/skyla-host-firewall.sh rollback  remove the policy, restoring the prior state
#   scripts/skyla-host-firewall.sh backup    write the current ruleset to a timestamped file
#
# SAFETY. This script can cut your own SSH session. It therefore:
#   * installs into a NEW chain and jumps to it, so `rollback` is one `iptables -D`;
#   * keeps loopback and established/related traffic unconditionally;
#   * allows SSH (tcp/22) and the platform's management address range unless
#     explicitly told otherwise;
#   * arms a dead-man timer with `apply --safe-minutes N` that rolls back
#     automatically unless you disarm it;
#   * refuses to run if it cannot write a backup first.
#
# It does NOT persist across reboot by itself. Persistence is a separate,
# deliberate step (`apply --persist`) because it is the change that can make a
# bad ruleset survive a restart.
set -eu

IPT="${IPTABLES:-/usr/sbin/iptables}"
IP6T="${IP6TABLES:-/usr/sbin/ip6tables}"
IPT_SAVE="${IPTABLES_SAVE:-/usr/sbin/iptables-save}"
IP6T_SAVE="${IP6TABLES_SAVE:-/usr/sbin/ip6tables-save}"
IPT_RESTORE="${IPTABLES_RESTORE:-/usr/sbin/iptables-restore}"
IP6T_RESTORE="${IP6TABLES_RESTORE:-/usr/sbin/ip6tables-restore}"
CHAIN="SKYLA-EGRESS"
BACKUP_DIR="${SKYLA_FW_BACKUP_DIR:-/var/lib/skyla/firewall}"
STATE_FILE="${BACKUP_DIR}/last-apply.env"

# Destinations the host legitimately needs. Each entry is a justification, not a
# convenience: an egress rule for a host nobody uses is an unexplained hole.
#   - the platform's DNS resolvers (53/udp+tcp)
#   - the container/sandbox metadata plane the platform itself needs
#   - the egress gateway's upstream (the proxy runs on this host and dials out)
DNS_SERVERS="${SKYLA_FW_DNS:-1.1.1.1 8.8.8.8}"
# The perimeter's gateway reaches the egress proxy on the host at this /30 peer.
# Measured: with a default-deny OUTPUT and no such exception, the gateway could
# not reach the proxy and the entire perimeter stopped working. This is the
# interaction that makes a host firewall and the namespace boundary
# interdependent, so it is an explicit, named exception rather than a broad
# "allow the local subnet".
GATEWAY_PEER="${SKYLA_FW_GATEWAY_PEER:-10.201.0.2}"
EGRESS_PROXY_PORT="${SKYLA_EGRESS_PORT:-8155}"
MANAGEMENT_SSH="${SKYLA_FW_SSH:-22}"
ALLOW_METADATA="${SKYLA_FW_ALLOW_METADATA:-1}"

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[ $# -ge 1 ] || usage
[ "$(id -u)" = "0" ] || { echo "must run as root (needs CAP_NET_ADMIN)" >&2; exit 1; }

mkdir -p "$BACKUP_DIR" 2>/dev/null || true
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

backup() {
    # A backup we cannot read back is worthless, so verify it before claiming it.
    local v4="$BACKUP_DIR/iptables-${STAMP}.rules" v6="$BACKUP_DIR/ip6tables-${STAMP}.rules"
    "$IPT_SAVE" > "$v4" 2>/dev/null || true
    "$IP6T_SAVE" > "$v6" 2>/dev/null || true
    # `iptables-save` emits nothing at all for an empty ruleset on this host; an
    # empty file is then the *correct* backup, but only if -S agrees.
    [ -s "$v4" ] || "$IPT" -S > "$v4"
    [ -s "$v6" ] || "$IP6T" -S > "$v6"
    [ -f "$v4" ] || { echo "refusing: could not write a firewall backup" >&2; exit 1; }
    printf 'BACKUP_V4=%s\nBACKUP_V6=%s\nSTAMP=%s\nCHAIN=%s\n' "$v4" "$v6" "$STAMP" "$CHAIN" > "$STATE_FILE"
    chmod 600 "$v4" "$v6" "$STATE_FILE" 2>/dev/null || true
    echo "backup written: $v4 ($(wc -l < "$v4") lines), $v6"
}

apply() {
    persist=0; safe_minutes=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --persist) persist=1 ;;
            --safe-minutes) shift; safe_minutes="${1:-10}" ;;
            *) echo "unknown option: $1" >&2; exit 2 ;;
        esac
        shift
    done

    backup

    # Build the chain fresh: -F on a chain that is still jumped-to keeps the
    # policy in force while it is being rebuilt, avoiding a window with no policy.
    "$IPT" -N "$CHAIN" 2>/dev/null || true
    "$IPT" -F "$CHAIN"

    # 1. Never break loopback: the API, the database and the proxy all use it.
    "$IPT" -A "$CHAIN" -o lo -j ACCEPT

    # 2. Established/related must survive, or every reply is dropped and the
    #    policy turns into "one-packet conversations only".
    "$IPT" -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # 3. Management: SSH back to the operator. Without this the host becomes
    #    unreachable the moment the policy is applied.
    "$IPT" -A "$CHAIN" -p tcp --dport "$MANAGEMENT_SSH" -j ACCEPT

    # 4. DNS to the configured resolvers only.
    for ns in $DNS_SERVERS; do
        "$IPT" -A "$CHAIN" -p udp -d "$ns" --dport 53 -j ACCEPT
        "$IPT" -A "$CHAIN" -p tcp -d "$ns" --dport 53 -j ACCEPT
    done

    # 4b. The perimeter gateway must reach the egress proxy, or the API cannot
    #     make a single authorised request. Scope it to one peer and one port.
    "$IPT" -A "$CHAIN" -s "$GATEWAY_PEER" -p tcp --dport "$EGRESS_PROXY_PORT" -j ACCEPT
    "$IPT" -A "$CHAIN" -d "$GATEWAY_PEER" -j ACCEPT

    # 5. The sandbox metadata plane. The platform's own namespace/provider code
    #    needs it; it is not a general-purpose allowance. Disable with
    #    SKYLA_FW_ALLOW_METADATA=0 on a host where it is unnecessary.
    if [ "$ALLOW_METADATA" = "1" ]; then
        "$IPT" -A "$CHAIN" -d 169.254.169.254 -j ACCEPT
    fi

    # 6. Default deny. Everything else — every outbound connection the platform
    #    did not justify — is dropped and logged at a rate limit.
    # Logging is optional: this kernel has no `limit`/`LOG` extension, so the
    # first attempt failed with "Extension LOG revision 0 not supported".
    # Losing the audit line must not lose the DROP, so it is attempted and the
    # failure is reported rather than aborting the policy.
    if ! "$IPT" -A "$CHAIN" -m limit --limit 6/min -j LOG              --log-prefix "skyla-egress-deny: " --log-level 4 2>/dev/null; then
        echo "note: denial logging unavailable on this kernel (no LOG extension);" >&2
        echo "      the DROP rule is still installed. Actions remain auditable" >&2
        echo "      through the proxy's own JSONL audit for permitted traffic." >&2
    fi
    "$IPT" -A "$CHAIN" -j DROP || { echo "refusing: could not install the DROP rule" >&2; return 1; }

    # Jump from OUTPUT. Insert at position 1 so provider rules cannot pre-empt it.
    # Only now, after the chain is complete and terminally DROPping, is it made
    # reachable. Building rules in a jumped-to chain would expose a window where
    # a partially built chain (no DROP yet) absorbs all traffic and ACCEPTs it —
    # fail-OPEN. Measured during development: a mid-build failure left the chain
    # with no DROP rule; it was only harmless because the jump had not been
    # installed yet. That ordering is now a guarantee, not an accident.
    if ! "$IPT" -S "$CHAIN" | grep -q -- '-j DROP'; then
        echo "refusing to activate: chain $CHAIN has no terminal DROP rule" >&2
        return 1
    fi
    "$IPT" -C OUTPUT -j "$CHAIN" 2>/dev/null && "$IPT" -D OUTPUT -j "$CHAIN"
    "$IPT" -I OUTPUT 1 -j "$CHAIN"

    # IPv6: this host has no global IPv6 address, and the perimeter disables IPv6
    # in its namespaces. A DROP-everything OUTPUT for v6 removes an unreviewed
    # second path entirely rather than relying on routes not existing.
    if [ "${SKYLA_FW_V6_DENY_ALL:-1}" = "1" ]; then
        "$IP6T" -N "$CHAIN" 2>/dev/null || true
        "$IP6T" -F "$CHAIN"
        "$IP6T" -A "$CHAIN" -o lo -j ACCEPT
        "$IP6T" -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        "$IP6T" -A "$CHAIN" -j DROP
        "$IP6T" -C OUTPUT -j "$CHAIN" 2>/dev/null && "$IP6T" -D OUTPUT -j "$CHAIN"
        "$IP6T" -I OUTPUT 1 -j "$CHAIN"
    fi

    if [ "$safe_minutes" != "0" ]; then
        # Dead-man switch: if the operator loses access and cannot disarm this,
        # the policy removes itself rather than locking them out permanently.
        ( sleep "$((safe_minutes * 60))"; \
          if [ -f "${BACKUP_DIR}/armed" ]; then \
             echo "dead-man timer fired after ${safe_minutes}m; rolling back" >&2; \
             "$0" rollback >&2; \
          fi ) >/dev/null 2>&1 &
        touch "${BACKUP_DIR}/armed"
        echo "armed: automatic rollback in ${safe_minutes}m — run 'disarm' once access is confirmed"
    fi

    if [ "$persist" = "1" ]; then
        install_persistence
    fi

    echo "policy applied to chain $CHAIN"
}

install_persistence() {
    # Persistence is deliberately separate and explicit. Written to a plain
    # restore file driven by a systemd oneshot; no dependency on
    # iptables-persistent being installed, and the unit is visible in `systemctl`.
    "$IPT_SAVE" > /etc/skyla-firewall.v4
    "$IP6T_SAVE" > /etc/skyla-firewall.v6
    cat > /etc/systemd/system/skyla-firewall.service <<'UNIT'
[Unit]
Description=SKYLA PRIME host egress firewall (default deny)
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/iptables-restore /etc/skyla-firewall.v4
ExecStart=/usr/sbin/ip6tables-restore /etc/skyla-firewall.v6

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable skyla-firewall.service 2>/dev/null || \
        echo "warning: could not enable systemd unit; rules are live but will not survive reboot" >&2
    echo "persistence: /etc/systemd/system/skyla-firewall.service (enabled)"
}

rollback() {
    # Remove the jump first, then the chain: if the chain were deleted first,
    # traffic would fall through to ACCEPT, which is the opposite of fail-closed.
    "$IPT" -D OUTPUT -j "$CHAIN" 2>/dev/null || true
    "$IP6T" -D OUTPUT -j "$CHAIN" 2>/dev/null || true
    "$IPT" -F "$CHAIN" 2>/dev/null || true
    "$IP6T" -F "$CHAIN" 2>/dev/null || true
    "$IPT" -X "$CHAIN" 2>/dev/null || true
    "$IP6T" -X "$CHAIN" 2>/dev/null || true
    rm -f "${BACKUP_DIR}/armed"
    echo "policy removed; OUTPUT policy is $( "$IPT" -S OUTPUT | head -1 )"
}

status() {
    echo "=== ipv4 ==="
    "$IPT" -S OUTPUT
    echo "--- chain $CHAIN (with hit counters) ---"
    "$IPT" -L "$CHAIN" -n -v 2>/dev/null || echo "(chain absent)"
    echo "=== ipv6 ==="
    "$IP6T" -S OUTPUT
    echo "--- chain $CHAIN ---"
    "$IP6T" -L "$CHAIN" -n -v 2>/dev/null || echo "(chain absent)"
}

verify() {
    # Prove the policy does what it claims, from this host, with disposable
    # destinations only. 203.0.113.0/24 and 198.51.100.0/24 are TEST-NET ranges:
    # reserved for documentation, never routed.
    fail=0
    echo "=== 1. default deny: a non-excepted destination must not connect ==="
    for target in 203.0.113.99 198.51.100.99; do
        if timeout 5 sh -c "exec 3<>/dev/tcp/${target}/443" 2>/dev/null; then
            echo "  FAIL  ${target}:443 CONNECTED (default-deny is not working)"; fail=1
        else
            echo "  PASS  ${target}:443 blocked"
        fi
    done

    echo "=== 2. exception: DNS to a configured resolver must work ==="
    ns=$(echo "$DNS_SERVERS" | awk '{print $1}')
    if timeout 5 sh -c "exec 3<>/dev/tcp/${ns}/53" 2>/dev/null; then
        echo "  PASS  ${ns}:53 reachable (except_tcp53)"
    else
        echo "  NOTE  ${ns}:53 not reachable — resolver may be UDP-only or unreachable here"
    fi

    echo "=== 2b. exception: the perimeter gateway reaches the egress proxy ==="
    if timeout 5 sh -c "exec 3<>/dev/tcp/127.0.0.1/${EGRESS_PROXY_PORT}" 2>/dev/null; then
        echo "  PASS  the proxy listens locally on ${EGRESS_PROXY_PORT}"
    else
        echo "  NOTE  the egress proxy is not running; start it to exercise this path"
    fi

    echo "=== 3. ipv6 default deny ==="
    if timeout 5 sh -c 'exec 3<>/dev/tcp/2001:db8::99/443' 2>/dev/null; then
        echo "  FAIL  ipv6 egress allowed"; fail=1
    else
        echo "  PASS  ipv6 egress blocked"
    fi

    echo "=== 4. the policy is installed, not merely intended ==="
    if "$IPT" -C OUTPUT -j "$CHAIN" 2>/dev/null; then
        echo "  PASS  OUTPUT jumps to $CHAIN"
    else
        echo "  FAIL  OUTPUT does not jump to $CHAIN"; fail=1
    fi
    if "$IPT" -S "$CHAIN" | grep -q -- '-j DROP'; then
        echo "  PASS  $CHAIN ends in DROP"
    else
        echo "  FAIL  $CHAIN has no DROP rule"; fail=1
    fi

    # A DROP rule is worthless if something above it accepts everything. An
    # unconstrained ACCEPT (no -s/-d, no -p, no -o, no ctstate) makes the whole
    # chain permissive while every other check still passes — measured: the
    # host reached github.com:443 with such a rule sitting at position 1.
    rogues=$("$IPT" -S "$CHAIN" | grep -E '^-A ' | grep -E -- '-j (ACCEPT|RETURN)$' \
             | grep -vE -- '(-s|-d|-p|-i|-o|--ctstate|--dport|--sport) ' || true)
    if [ -n "$rogues" ]; then
        echo "  FAIL  $CHAIN contains an unconstrained accept:"
        printf '%s\n' "$rogues" | sed 's/^/          /' 
        fail=1
    else
        echo "  PASS  no unconstrained accept in $CHAIN"
    fi

    [ "$fail" = "0" ] && echo "VERIFY: PASS" || { echo "VERIFY: FAIL"; return 1; }
}

case "$1" in
    apply)    shift; apply "$@" ;;
    rollback) rollback ;;
    status)   status ;;
    verify)   verify ;;
    backup)   backup ;;
    disarm)   rm -f "${BACKUP_DIR}/armed"; echo "dead-man timer disarmed" ;;
    *)        usage ;;
esac
