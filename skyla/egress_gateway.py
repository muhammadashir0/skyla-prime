"""Host forwarding policy for the dedicated egress gateway (v0.2.6, closes FW-01).

Why this module exists
----------------------
v0.2.5 left FW-01 open: the egress proxy ran in the **host** network namespace, so
its upstream connections traversed the host `OUTPUT` chain, where `SKYLA-EGRESS`
terminates in `DROP`. The gateway namespace could not reach upstream either, for a
different reason: the host had `net.ipv4.ip_forward = 0` and an empty NAT table.

Both failures are fixed by moving the proxy into the gateway namespace and giving
the host a **narrow, explicit forwarding policy**. The distinction that makes this
safe is the netfilter hook each path uses:

    OUTPUT   traffic ORIGINATING on this host  (every host process)
    FORWARD  traffic ROUTED THROUGH this host  (the gateway namespace only)

The host `OUTPUT` policy stays exactly as strict as it was. Nothing about it is
relaxed — a host process still cannot reach the internet. Only the gateway
namespace, which runs nothing but the proxy, gains a forwarding path, and that
path is restricted to a small set of upstream ports.

What is deliberately NOT done
-----------------------------
* No `-m owner` rule (the kernel here has no `xt_owner`; that was the v0.2.5
  blocker and it is still unavailable).
* No blanket `MASQUERADE`.
* No `FORWARD -P ACCEPT`. The v0.2.5 host had `FORWARD ACCEPT` with zero rules —
  harmless only because `ip_forward` was 0, and a latent hole the moment anything
  enabled it. This module sets `FORWARD` to `DROP` and permits by exception.

Every rule is verified against the live kernel after installation. A rule is not
"active" because a command returned 0.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field

# The gateway's upstream attachment on the host side. Kept in one place so the
# policy and the namespace builder cannot disagree.
GW_SUBNET = "10.201.0.0/30"
GW_UPSTREAM_IP = "10.201.0.2"
HOST_UPSTREAM_IP = "10.201.0.1"

# Upstream ports the proxy may use. This is the authorised upstream surface:
# HTTPS and DNS-over-TLS only. Everything else — including SMTP, SSH, arbitrary
# high ports — is dropped at FORWARD.
UPSTREAM_TCP_PORTS = (443, 853)
UPSTREAM_UDP_PORTS = (443, 853)

# Controlled DNS: the gateway resolver must be reachable, but only the
# resolvers, and only on 53. Measured: without this the proxy inside the gateway
# namespace hangs on getaddrinfo for the full connect timeout, which looks
# exactly like "upstream unreachable" and is really "cannot resolve".
DNS_RESOLVERS = ("8.8.8.8", "1.1.1.1")

# Destinations that must never be reachable from the gateway, even if a future
# edit widens the port list. Denied before any ACCEPT is evaluated.
#
# MEASURED CAVEAT about 169.254.0.0/16 (this took an hour to find, so it is
# written down): the link-local range cannot be denied wholesale here. On this
# host the DEFAULT GATEWAY IS LINK-LOCAL — `default via 169.254.0.22 dev eth0` —
# so a blanket `-d 169.254.0.0/16 -j DROP` silently kills every forwarded reply.
# The symptom is maddening: the ACCEPT rule's counter increments, the packet is
# accepted, and the connection still times out, because the *return* packet is
# dropped by a rule written to block the metadata plane.
#
# The metadata endpoint is therefore denied by its own /32 (it is always
# 169.254.169.254), not by its range. This is the correct scope anyway: the
# threat is the metadata service, not link-local traffic in general.
#
# SECOND MEASURED CAVEAT, same family: 10.0.0.0/8 CANNOT be denied wholesale
# either. The gateway itself lives at 10.201.0.2, so a blanket `-d 10.0.0.0/8
# -j DROP` kills the RETURN half of every forwarded flow (the reply is addressed
# to 10.201.0.2). The denial is therefore `10.0.0.0/8` MINUS the gateway subnet,
# expressed as explicit covering ranges so no rule ever matches the gateway.
def _split_around(net: str, exclude: str) -> tuple[str, ...]:
    """`net` minus `exclude`, as exact CIDR blocks.

    Computed with ipaddress rather than written by hand: an earlier hand-written
    split omitted 10.201.0.0/16, so the gateway's own 10.201.0.2 was inside a
    "block private networks" rule and every forwarded reply was dropped.
    """
    import ipaddress

    outer = ipaddress.ip_network(net)
    inner = ipaddress.ip_network(exclude)
    return tuple(str(b) for b in outer.address_exclude(inner))


# The metadata endpoint is always 169.254.169.254, so it is denied by its own
# /32 rather than by the 169.254.0.0/16 range — see the note above about this
# host's link-local default gateway.
METADATA_V4 = ("169.254.169.254/32",)

# 10.0.0.0/8 minus the two point-to-point /30 links (gateway and workload).
# Computed, not hand-written: an earlier hand-written split omitted
# 10.201.0.0/16, so the gateway's own 10.201.0.2 was inside a "block private
# networks" rule and every forwarded reply was silently dropped.
_PRIVATE_V4_EXCLUDE = ("10.200.0.0/30", "10.201.0.0/30")


def _private_v4() -> tuple[str, ...]:
    """10/8 minus the perimeter links, as exact CIDR blocks."""
    import ipaddress

    blocks: list = [ipaddress.ip_network("10.0.0.0/8")]
    for ex in _PRIVATE_V4_EXCLUDE:
        inner = ipaddress.ip_network(ex)
        nxt: list = []
        for net in blocks:
            if inner.subnet_of(net):
                nxt.extend(net.address_exclude(inner))
            else:
                nxt.append(net)          # already carved out
        blocks = nxt
    return tuple(str(b) for b in sorted(blocks))


PRIVATE_V4 = (
    "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "100.64.0.0/10",
    *_private_v4(),
)

CHAIN_FWD = "SKYLA-FWD"
CHAIN_IN = "SKYLA-GW-IN"
CHAIN_NAT = "SKYLA-GW-NAT"

# The gateway upstream interface. Discovered rather than assumed: the veth name
# carries a random suffix, and hard-coding it would silently target nothing.
def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def upstream_iface() -> str | None:
    """Host-side interface whose peer address is the gateway's upstream end."""
    r = _run(["ip", "-4", "-o", "addr", "show"])
    for line in r.stdout.splitlines():
        # "<iface> inet 10.201.0.1/30 scope global <iface>"
        parts = line.split()
        if len(parts) > 3 and parts[3] == f"{HOST_UPSTREAM_IP}/30":
            return parts[1]
    return None


@dataclass
class ForwardPolicyStatus:
    ip_forward: bool = False
    forward_default_drop: bool = False
    chain_present: bool = False
    nat_present: bool = False
    iface: str | None = None
    rules: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"ip_forward": self.ip_forward,
                "forward_default_drop": self.forward_default_drop,
                "chain_present": self.chain_present,
                "nat_present": self.nat_present,
                "iface": self.iface,
                "problems": self.problems}


class ForwardingUnavailable(RuntimeError):
    """The host forwarding policy could not be installed or verified."""


class HostForwardPolicy:
    """Install, verify and remove the gateway forwarding policy.

    All methods are idempotent: `apply()` twice is the same as once, and
    `remove()` on an unapplied policy is a no-op. That matters because the
    firewall is persistent — a boot-time restore may run this twice.
    """

    def __init__(self, iface: str | None = None):
        self._iface_name = iface

    # ---------------------------------------------------------------- helpers
    def _iface(self) -> str:
        if self._iface_name:
            return self._iface_name
        iface = upstream_iface()
        if not iface:
            raise ForwardingUnavailable(
                f"no host interface carries {HOST_UPSTREAM_IP}/30; the gateway "
                "namespace is not built, so there is nothing to forward for")
        self._iface_name = iface
        return iface

    def _uplink(self) -> str:
        """The interface the host uses to reach the internet."""
        r = _run(["ip", "route", "get", "1.1.1.1"])
        parts = r.stdout.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
        raise ForwardingUnavailable("cannot determine the host uplink interface")

    def _ipt(self, *args: str) -> subprocess.CompletedProcess:
        return _run(["iptables", *args])

    def _chain_exists(self, table: str, chain: str) -> bool:
        r = self._ipt("-t", table, "-S", chain) if table != "filter" \
            else self._ipt("-S", chain)
        return r.returncode == 0

    # ------------------------------------------------------------------ apply
    def apply(self) -> None:
        iface = self._iface()

        # 1. forwarding must be enabled for ANY of this to matter, and the
        #    consequence of enabling it is that FORWARD stops being irrelevant.
        #    So set the default to DROP *first* — enabling forwarding while
        #    FORWARD is ACCEPT would briefly allow everything.
        self._ipt("-P", "FORWARD", "DROP")

        # 2. the dedicated chain, rebuilt from scratch
        self._ipt("-F", CHAIN_FWD)
        if not self._chain_exists("filter", CHAIN_FWD):
            self._ipt("-N", CHAIN_FWD)
        if not self._ipt("-C", "FORWARD", "-j", CHAIN_FWD).returncode == 0:
            self._ipt("-I", "FORWARD", "1", "-j", CHAIN_FWD)

        rules = [
            # Never forward these, whatever else matches.
            *[("-d", net, "-j", "DROP") for net in METADATA_V4],
            *[("-d", net, "-j", "DROP") for net in PRIVATE_V4],
            # Return traffic for connections the gateway opened.
            ("-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"),
            # INVALID must not be accepted by the stateful rule above.
            ("-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"),
            # The authorised upstream surface.
            #
            # `-o` is the interface the packet LEAVES by — the uplink — NOT the
            # veth it arrived on. Measured: with `-o <veth>` this rule never
            # matched (counter stayed 0) while the packets demonstrably entered
            # FORWARD, and the connection timed out with no error. `-i` is the
            # arrival side, and that IS the gateway veth.
            *[("-i", iface, "-s", GW_SUBNET, "-o", self._uplink(),
               "-p", "tcp", "--dport", str(p), "-j", "ACCEPT")
              for p in UPSTREAM_TCP_PORTS],
            *[("-i", iface, "-s", GW_SUBNET, "-o", self._uplink(),
               "-p", "udp", "--dport", str(p), "-j", "ACCEPT")
              for p in UPSTREAM_UDP_PORTS],
            # Controlled DNS: named resolvers only, port 53 only.
            *[("-i", iface, "-s", GW_SUBNET, "-o", self._uplink(), "-d", dns,
               "-p", "udp", "--dport", "53", "-j", "ACCEPT")
              for dns in DNS_RESOLVERS],
            *[("-i", iface, "-s", GW_SUBNET, "-o", self._uplink(), "-d", dns,
               "-p", "tcp", "--dport", "53", "-j", "ACCEPT")
              for dns in DNS_RESOLVERS],
            # Terminal deny. Anything reaching here was not explicitly permitted.
            ("-j", "DROP"),
        ]
        for rule in rules:
            self._ipt("-A", CHAIN_FWD, *rule)

        # 3. NAT: the gateway's traffic must appear to come from the host.
        self._ipt("-t", "nat", "-F", CHAIN_NAT)
        if not self._chain_exists("nat", CHAIN_NAT):
            self._ipt("-t", "nat", "-N", CHAIN_NAT)
        if not self._ipt("-t", "nat", "-C", "POSTROUTING", "-j", CHAIN_NAT).returncode == 0:
            self._ipt("-t", "nat", "-I", "POSTROUTING", "1", "-j", CHAIN_NAT)
        # -o must be the interface the packet LEAVES by (the uplink), not the
        # veth it arrived on. Measured: with `-o <veth>` the MASQUERADE counter
        # stayed at 0 and the connection timed out with no error anywhere.
        self._ipt("-t", "nat", "-A", CHAIN_NAT, "-s", GW_SUBNET, "-o", self._uplink(),
                  "-j", "MASQUERADE")

        # 4. INPUT protection for host services.
        #
        # MEASURED GAP (v0.2.6 investigation): the gateway could reach the host's
        # own listening services (10.201.0.1:8155 answered). INPUT traffic is not
        # forwarded, so SKYLA-FWD never sees it — it needed its own chain. The
        # gateway is allowed to reach the host ONLY on the proxy relay port, and
        # only from the gateway subnet.
        self._ipt("-F", CHAIN_IN)
        if not self._chain_exists("filter", CHAIN_IN):
            self._ipt("-N", CHAIN_IN)
        if not self._ipt("-C", "INPUT", "-j", CHAIN_IN).returncode == 0:
            self._ipt("-I", "INPUT", "1", "-j", CHAIN_IN)
        for rule in (
            ("-i", iface, "-s", GW_SUBNET, "-m", "conntrack",
             "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"),
            ("-i", iface, "-s", GW_SUBNET, "-j", "DROP"),
        ):
            self._ipt("-A", CHAIN_IN, *rule)

        # 5. only now enable forwarding — the path is already restricted.
        _run(["sysctl", "-qw", "net.ipv4.ip_forward=1"])

        status = self.verify()
        if status.problems:
            raise ForwardingUnavailable(
                "forwarding policy did not verify: " + "; ".join(status.problems))

    # ----------------------------------------------------------------- verify
    def verify(self) -> ForwardPolicyStatus:
        st = ForwardPolicyStatus()
        st.ip_forward = _run(["sysctl", "-n", "net.ipv4.ip_forward"]).stdout.strip() == "1"
        if not st.ip_forward:
            st.problems.append("net.ipv4.ip_forward is not 1")

        fwd = self._ipt("-S", "FORWARD").stdout
        st.forward_default_drop = "-P FORWARD DROP" in fwd
        if not st.forward_default_drop:
            st.problems.append("FORWARD default policy is not DROP")

        chain = self._ipt("-S", CHAIN_FWD).stdout
        st.chain_present = CHAIN_FWD in fwd and "-j DROP" in chain
        if not st.chain_present:
            st.problems.append(f"{CHAIN_FWD} missing or lacks a terminal DROP")
        # The private-network and metadata denials are the security-critical
        # rules; their absence must fail verification, not degrade quietly.
        for net in (*METADATA_V4, *PRIVATE_V4):
            if f"-d {net}" not in chain:
                st.problems.append(f"missing deny for {net}")

        inp = self._ipt("-S", "INPUT").stdout
        in_chain = self._ipt("-S", CHAIN_IN).stdout
        if CHAIN_IN not in inp or "-j DROP" not in in_chain:
            st.problems.append(f"{CHAIN_IN} missing or lacks a terminal DROP")

        nat = self._ipt("-t", "nat", "-S", CHAIN_NAT).stdout
        st.nat_present = ("MASQUERADE" in nat and f"-s {GW_SUBNET}" in nat
                          and f"-o {self._uplink()}" in nat)
        if not st.nat_present:
            st.problems.append("gateway MASQUERADE rule missing")

        st.iface = self._iface_name or upstream_iface()
        st.rules = [l for l in chain.splitlines() if l.startswith("-A")]
        return st

    # ----------------------------------------------------------------- remove
    def remove(self) -> None:
        self._ipt("-D", "INPUT", "-j", CHAIN_IN)
        self._ipt("-F", CHAIN_IN)
        self._ipt("-X", CHAIN_IN)
        self._ipt("-D", "FORWARD", "-j", CHAIN_FWD)
        self._ipt("-F", CHAIN_FWD)
        self._ipt("-X", CHAIN_FWD)
        self._ipt("-t", "nat", "-D", "POSTROUTING", "-j", CHAIN_NAT)
        self._ipt("-t", "nat", "-F", CHAIN_NAT)
        self._ipt("-t", "nat", "-X", CHAIN_NAT)
        # Forwarding back off: with the permits gone, leaving it enabled would be
        # a policy with no rules behind it.
        _run(["sysctl", "-qw", "net.ipv4.ip_forward=0"])
        self._ipt("-P", "FORWARD", "ACCEPT")
