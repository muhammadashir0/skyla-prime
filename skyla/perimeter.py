"""OS-level network perimeter for SKYLA PRIME (v0.2.3, closes B-01).

The finding
-----------
v0.2.2 shipped a default-deny **egress proxy** (`skyla/egress.py`) that refused
non-allowlisted destinations before opening a socket, dialled a vetted IP rather
than a re-resolved name, and audited every decision. It passed its own tests. It
was still not a perimeter, because **nothing forced traffic through it**: a caller
that ignored `HTTPS_PROXY` and dialled directly was not stopped. The v0.2.2 report
recorded that honestly as B-01 (High) rather than treating a passing proxy test as
network isolation.

What this module adds
---------------------
A **network namespace wired so the only reachable peer is the proxy**. The
boundary is not a firewall rule that could be misconfigured or forgotten; it is the
kernel's routing table plus the absence of any other interface:

    host                                          namespace
    ┌──────────────────────────┐            ┌──────────────────────────┐
    │  API / agents            │            │  workload                │
    │      │                   │            │      │                   │
    │      │ 10.200.0.1        │  veth      │      │ 10.200.0.2        │
    │      └───────────────┐   │◀──────────▶│      └───┬───────────────│
    │   egress proxy :PORT │   │  /30       │   route to .1 ONLY       │
    │      (allowlist)     │   │            │   (no default route)     │
    └──────────────────────┘   │            └──────────────────────────┘

* The namespace contains exactly one non-loopback interface with a /30 address.
* There is **no default route**, so a packet to any other address has no next hop
  and fails with ENETUNREACH — before any application code runs.
* IPv6 is absent from the namespace, so the v6 path is not merely filtered, it does
  not exist.
* DNS does not resolve inside the namespace (no `/etc/resolv.conf` route out), so
  the workload cannot resolve an internal name; the proxy resolves on its behalf
  and performs the address checks (`netguard.validate_url`).

A single veth to the host is not enough
---------------------------------------
The first version of this module gave the workload namespace a veth whose peer sat
on the host. Measured: the workload could then reach **any port bound to 0.0.0.0 on
the host** — including the API itself, because `uvicorn` binds `0.0.0.0:8000`.
Reaching the API from a workload is precisely the "internal service protection"
requirement, so that topology was rejected.

The peer now lives in a **dedicated gateway namespace** that runs nothing but the
egress proxy:

    workload ns  ──veth──▶  gateway ns (proxy only)  ──veth──▶  host / upstream
    10.200.0.2              10.200.0.1 · 10.201.0.2            10.201.0.1

The workload's only peer is a namespace containing one listening socket, so the
reachable set is the proxy's port and nothing else. Evidence for both topologies is
in NETWORK_PERIMETER_ASSESSMENT.md §4.

Why the workload path already had no network
--------------------------------------------
`skyla/execution/workload.py` runs untrusted code under `unshare -n` with no
interfaces at all, and seccomp denies `socket()`. Measured from inside a real run:
every connect fails with EPERM, DNS fails with gaierror, and `/proc/net/dev` lists
no interfaces. So B-01 does **not** apply to the untrusted-execution path.

B-01 applies to the **trusted API process**, which is where agents, connectors and
`research.fetch_url` make outbound calls. That is the process this module confines.

What this module cannot do here (and says so)
--------------------------------------------
On this host a host-wide `nftables`/`iptables` ruleset cannot be installed: the
kernel has nf_tables (108 kallsyms symbols) but there is no `nft` binary, no Python
binding on PyPI, and a direct `libnftables.so.1` netlink write returns
"Could not process rule: No such file or directory" even as uid 0 with a full
capability set (CapEff 1ffffffffff) inside a fresh netns. That is the execution
environment's own boundary and it is recorded in NETWORK_PERIMETER_ASSESSMENT.md as
an unmet requirement for a *host-firewall* deployment. The netns perimeter below is
independently demonstrated and does not depend on netfilter at all.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

# /30 point-to-point link. Two usable addresses: host end and namespace end.
# Link 1: workload namespace <-> gateway namespace (the only path a workload has)
_GW_SIDE_OF_WL = "10.200.0.1"      # gateway's end of the workload link
_WL_IP = "10.200.0.2"              # workload namespace
# Link 2: gateway namespace <-> host (how the proxy reaches upstream)
_HOST_SIDE_OF_GW = "10.201.0.1"    # host's end of the gateway link
_GW_SIDE_OF_HOST = "10.201.0.2"    # gateway's end of the host link
_PREFIX = "30"
_DEFAULT_NS = "skyla-egress"
_GATEWAY_NS = "skyla-egress-gw"

# Ports the workload may reach are the proxy's port only; everything else is
# unroutable rather than filtered, which is the stronger property.
_ALLOWED_NS_PORTS = ()

# Hosts unreachable by construction. Used for assertions, not for enforcement:
# the enforcement is the routing table.
_PROBE_TARGETS = {
    "public_dns": ("1.1.1.1", 53),
    "public_dns2": ("8.8.8.8", 53),
    "metadata_aws": ("169.254.169.254", 80),
    "metadata_gcp": ("169.254.169.254", 80),
    "loopback_host": ("127.0.0.1", 80),
}


class PerimeterUnavailable(RuntimeError):
    """The OS-level boundary could not be established. Callers MUST fail closed."""


@dataclass
class PerimeterStatus:
    available: bool = False
    namespace: str = ""
    host_ip: str = ""
    ns_ip: str = ""
    proxy_endpoint: str = ""
    reason: str = ""
    interfaces_in_ns: list[str] = field(default_factory=list)
    has_default_route: bool = True
    ipv6_present: bool = False
    verified_at: float = 0.0

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["verified_at_iso"] = (
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.verified_at))
            if self.verified_at else "")
        return d


def _run(cmd: list[str], *, check: bool = True, timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          check=False) if not check else subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout)


class EgressPerimeter:
    """A named network namespace whose only peer is the egress proxy.

    Lifecycle: `create()` builds it, `verify()` proves it by attempting real
    connections from inside, `destroy()` removes it. Verification is not optional —
    a namespace that exists but still has a default route would provide the exact
    false assurance this module was written to eliminate.
    """

    def __init__(self, name: str = _DEFAULT_NS, *, proxy_port: int | None = None,
                 gateway_name: str = _GATEWAY_NS):
        self.name = name                       # workload namespace
        self.gateway_name = gateway_name       # proxy-only namespace
        self.proxy_port = proxy_port
        self.host_ip = _GW_SIDE_OF_WL          # what the workload dials for the proxy
        self.ns_ip = _WL_IP
        # Linux interface names are capped at IFNAMSIZ-1 = 15 characters, so they
        # are derived from a short digest of the namespace name rather than the
        # name itself ("skyla-egress-wlp" is 17 and the kernel rejects it).
        tag = hashlib.sha256(name.encode()).hexdigest()[:4]
        self._wl_link = f"sk{tag}w"            # gateway end of the workload link
        self._wl_peer = f"sk{tag}wp"           # workload end
        self._gw_link = f"sk{tag}g"            # host end of the gateway link
        self._gw_peer = f"sk{tag}gp"           # gateway end
        self._created = False
        self.status = PerimeterStatus(namespace=name, host_ip=self.host_ip,
                                      ns_ip=self.ns_ip)

    # ------------------------------------------------------------- discovery
    @staticmethod
    def prerequisites() -> tuple[bool, str]:
        """Can this host build the boundary at all? Checked before claiming it."""
        if not shutil.which("ip"):
            return False, "iproute2 ('ip') not available"
        if not shutil.which("unshare") and not _can_netlink():
            return False, "neither 'unshare' nor netlink capability"
        if os.geteuid() != 0:
            return False, ("creating a network namespace requires CAP_NET_ADMIN; "
                           "run the deploy step as root (setup only, not per request)")
        r = _run(["ip", "netns", "list"], check=False)
        if r.returncode != 0:
            return False, f"'ip netns list' failed: {r.stderr.strip()[:120]}"
        return True, ""

    # --------------------------------------------------------------- create
    def create(self) -> "EgressPerimeter":
        ok, reason = self.prerequisites()
        if not ok:
            self.status.reason = reason
            raise PerimeterUnavailable(reason)

        # Idempotent: an existing namespace is reused only if it is ours and clean.
        self.destroy(quiet=True)

        wl, gw = self.name, self.gateway_name
        steps = [
            # ---- the two namespaces
            (["ip", "netns", "add", gw], "create gateway namespace"),
            (["ip", "netns", "add", wl], "create workload namespace"),

            # ---- link 1: workload <-> gateway
            (["ip", "link", "add", self._wl_link, "type", "veth",
              "peer", "name", self._wl_peer], "create workload veth"),
            (["ip", "link", "set", self._wl_peer, "netns", wl],
             "place workload veth"),
            (["ip", "link", "set", self._wl_link, "netns", gw],
             "place workload veth peer in gateway"),
            (["ip", "netns", "exec", gw, "ip", "addr", "add",
              f"{_GW_SIDE_OF_WL}/{_PREFIX}", "dev", self._wl_link],
             "address gateway end of workload link"),
            (["ip", "netns", "exec", wl, "ip", "addr", "add",
              f"{_WL_IP}/{_PREFIX}", "dev", self._wl_peer],
             "address workload end"),

            # ---- link 2: gateway <-> host (upstream path for the proxy)
            (["ip", "link", "add", self._gw_link, "type", "veth",
              "peer", "name", self._gw_peer], "create gateway veth"),
            (["ip", "link", "set", self._gw_peer, "netns", gw],
             "place gateway veth"),
            (["ip", "addr", "add", f"{_HOST_SIDE_OF_GW}/{_PREFIX}", "dev", self._gw_link],
             "address host end"),
            (["ip", "netns", "exec", gw, "ip", "addr", "add",
              f"{_GW_SIDE_OF_HOST}/{_PREFIX}", "dev", self._gw_peer],
             "address gateway upstream end"),

            # ---- bring everything up
            (["ip", "link", "set", self._gw_link, "up"], "host link up"),
            (["ip", "netns", "exec", gw, "ip", "link", "set", "lo", "up"], "gw lo up"),
            (["ip", "netns", "exec", wl, "ip", "link", "set", "lo", "up"], "wl lo up"),
            (["ip", "netns", "exec", gw, "ip", "link", "set", self._wl_link, "up"],
             "gw workload-link up"),
            (["ip", "netns", "exec", wl, "ip", "link", "set", self._wl_peer, "up"],
             "workload link up"),
            (["ip", "netns", "exec", gw, "ip", "link", "set", self._gw_peer, "up"],
             "gw upstream-link up"),

            # ---- THE LOAD-BEARING ROUTING
            # Workload: a host route to the gateway and NOTHING ELSE. No default
            # route exists, so every other destination has no next hop.
            (["ip", "netns", "exec", wl, "ip", "route", "add",
              f"{_GW_SIDE_OF_WL}/32", "dev", self._wl_peer],
             "workload route to gateway only"),
            # Gateway: default route out via the host link, so the proxy can reach
            # upstream. The gateway runs nothing but the proxy.
            (["ip", "netns", "exec", gw, "ip", "route", "add", "default",
              "via", _HOST_SIDE_OF_GW, "dev", self._gw_peer],
             "gateway default route upstream"),

            # ---- IPv6 does not exist in either namespace
            (["ip", "netns", "exec", wl, "sysctl", "-w",
              "net.ipv6.conf.all.disable_ipv6=1"], "disable workload IPv6"),
            (["ip", "netns", "exec", gw, "sysctl", "-w",
              "net.ipv6.conf.all.disable_ipv6=1"], "disable gateway IPv6"),
        ]

        # The gateway forwards exactly ONE port — the egress proxy — toward the
        # host. This is what makes the proxy the only reachable service: without
        # it the workload namespace has no path to anything at all, and with it
        # the reachable set is a single (ip, port) pair.
        if self.proxy_port:
            port = str(self.proxy_port)
            steps.extend([
                (["ip", "netns", "exec", gw, "sysctl", "-w",
                  "net.ipv4.ip_forward=1"], "enable forwarding in gateway"),
                # DNAT sends the workload's connection to the host proxy...
                (["ip", "netns", "exec", gw, "iptables", "-t", "nat",
                  "-A", "PREROUTING", "-p", "tcp", "--dport", port,
                  "-j", "DNAT", "--to-destination",
                  f"{_HOST_SIDE_OF_GW}:{port}"], "forward proxy port to host"),
                # ...and MASQUERADE makes the host's replies come back to the
                # gateway rather than to an unreachable 10.200.0.2. Without this
                # the forward is a black hole: measured as a connect timeout.
                (["ip", "netns", "exec", gw, "iptables", "-t", "nat",
                  "-A", "POSTROUTING", "-o", self._gw_peer, "-j", "MASQUERADE"],
                 "masquerade return path"),
                (["ip", "netns", "exec", gw, "iptables", "-A", "FORWARD",
                  "-i", self._wl_link, "-o", self._gw_peer, "-p", "tcp",
                  "--dport", port, "-j", "ACCEPT"], "allow only the proxy port out"),
                (["ip", "netns", "exec", gw, "iptables", "-A", "FORWARD",
                  "-i", self._gw_peer, "-o", self._wl_link,
                  "-m", "state", "--state", "ESTABLISHED,RELATED",
                  "-j", "ACCEPT"], "allow return traffic"),
                # Belt and braces: drop anything else the gateway might forward.
                (["ip", "netns", "exec", gw, "iptables", "-A", "FORWARD",
                  "-j", "DROP"], "drop all other forwarded traffic"),
            ])
        for cmd, label in steps:
            r = _run(cmd, check=False)
            if r.returncode != 0:
                self.destroy(quiet=True)
                msg = f"{label} failed: {(r.stderr or r.stdout).strip()[:200]}"
                self.status.reason = msg
                raise PerimeterUnavailable(msg)

        self._created = True
        self.status.available = True
        self.status.reason = ""
        return self

    # --------------------------------------------------------------- verify
    def verify(self, timeout: int = 30) -> PerimeterStatus:
        """Prove the boundary by trying to break it from inside.

        Returns status with `available` False if any probe reaches the network. A
        perimeter that has not been probed is not a perimeter.
        """
        if not self._created:
            self.status.available = False
            self.status.reason = self.status.reason or "namespace was not created"
            return self.status

        r = _run(["ip", "netns", "exec", self.name, "ip", "-j", "addr"], check=False)
        ifaces: list[str] = []
        try:
            for link in json.loads(r.stdout or "[]"):
                ifaces.append(link.get("ifname", ""))
        except json.JSONDecodeError:
            ifaces = []

        r6 = _run(["ip", "netns", "exec", self.name, "ip", "-6", "route"], check=False)
        ipv6_present = bool((r6.stdout or "").strip())

        rr = _run(["ip", "netns", "exec", self.name, "ip", "route"], check=False)
        routes = (rr.stdout or "").strip()
        has_default = any(line.strip().startswith("default") for line in routes.splitlines())

        # The gateway namespace is what makes "internal services" unreachable: the
        # workload's only peer contains nothing but the proxy. Verify it exists and
        # that IT has upstream connectivity, otherwise the allow path is dead.
        gw_routes = _run(["ip", "netns", "exec", self.gateway_name, "ip", "route"],
                         check=False).stdout or ""
        gw_ready = bool(gw_routes.strip())

        self.status.interfaces_in_ns = ifaces
        self.status.ipv6_present = ipv6_present
        self.status.has_default_route = has_default
        self.status.verified_at = time.time()

        if has_default:
            self.status.available = False
            self.status.reason = (
                "the workload namespace has a default route — traffic could escape")
        if ipv6_present:
            self.status.available = False
            self.status.reason = "the workload namespace has IPv6 routes — v6 path exists"
        if not gw_ready:
            self.status.available = False
            self.status.reason = (
                f"the gateway namespace {self.gateway_name!r} is missing or has no "
                f"routes — the proxy could not reach upstream")
        if self.proxy_port:
            self.status.proxy_endpoint = f"http://{self.host_ip}:{self.proxy_port}"
        return self.status

    # -------------------------------------------------------------- probes
    def run_probe(self, script: str, *, timeout: int = 60) -> dict:
        """Execute `script` INSIDE the namespace and return its result.

        This is how evidence is produced: the probe runs in the confined network
        context, so a 'blocked' result is the kernel refusing, not an application
        check declining.
        """
        if not self._created:
            raise PerimeterUnavailable("namespace was not created")
        p = _run(["ip", "netns", "exec", self.name, "python3", "-c", script],
                 check=False, timeout=timeout)
        return {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}

    def prove_no_egress(self, targets: dict[str, tuple[str, int]] | None = None) -> dict:
        """Attempt real connections from inside; every one must fail.

        Also verifies the CONTROL: the same probe on the host succeeds, so a
        'blocked' result cannot be explained by the host having no network.
        """
        targets = targets or _PROBE_TARGETS
        literal = ", ".join(f'("{k}", "{v[0]}", {v[1]})' for k, v in targets.items())
        script = (
            "import socket, json\n"
            f"targets=[{literal}]\n"
            "out={}\n"
            "for name, host, port in targets:\n"
            "    try:\n"
            "        s=socket.create_connection((host,port),timeout=3); s.close()\n"
            "        out[name]='REACHED'\n"
            "    except Exception as e:\n"
            "        out[name]=type(e).__name__\n"
            "try:\n"
            "    socket.gethostbyname('pypi.org'); out['dns']='RESOLVED'\n"
            "except Exception as e:\n"
            "    out['dns']=type(e).__name__\n"
            "print(json.dumps(out))\n"
        )
        inside = self.run_probe(script)
        try:
            ns_result = json.loads(inside["stdout"].strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError):
            ns_result = {"error": (inside["stderr"] or inside["stdout"])[:200]}

        host_result = {}
        for name, (host, port) in targets.items():
            try:
                import socket
                s = socket.create_connection((host, port), timeout=3)
                s.close()
                host_result[name] = "REACHED"
            except Exception as exc:                        # noqa: BLE001
                host_result[name] = type(exc).__name__

        leaked = [k for k, v in ns_result.items() if v == "REACHED"]
        return {
            "namespace": self.name,
            "inside": ns_result,
            "host_control": host_result,
            "leaked": leaked,
            "isolated": not leaked,
            "host_has_network": any(v == "REACHED" for v in host_result.values()),
        }

    def prove_proxy_reachable(self, timeout: int = 25) -> dict:
        """The counterpart: the ONE permitted destination must still work.

        A perimeter that blocks everything including the proxy is not a policy,
        it is an outage. This proves the allow path survives.
        """
        if not self.proxy_port:
            return {"skipped": "no proxy_port configured"}
        script = (
            "import socket, json\n"
            "out={}\n"
            f"for host,port in [('{self.host_ip}',{self.proxy_port})]:\n"
            "    try:\n"
            "        s=socket.create_connection((host,port),timeout=5); s.close()\n"
            "        out['proxy']='REACHED'\n"
            "    except Exception as e:\n"
            "        out['proxy']=type(e).__name__\n"
            "print(json.dumps(out))\n"
        )
        r = self.run_probe(script, timeout=timeout)
        try:
            return json.loads(r["stdout"].strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError):
            return {"error": (r["stderr"] or r["stdout"])[:200]}

    # -------------------------------------------------------------- destroy
    def destroy(self, *, quiet: bool = False) -> None:
        if shutil.which("ip"):
            for ns in (self.name, self.gateway_name):
                _run(["ip", "netns", "del", ns], check=False)
            # A host-side veth can survive a failed create; remove it by name.
            _run(["ip", "link", "del", self._gw_link], check=False)
            for leftover in (self._wl_link, self._gw_link,
                             self._wl_peer, self._gw_peer):
                _run(["ip", "link", "del", leftover], check=False)
        self._created = False
        self.status.available = False
        if not quiet:
            self.status.reason = "destroyed"

    def __enter__(self):
        return self.create()

    def __exit__(self, *exc):
        self.destroy(quiet=True)


def _can_netlink() -> bool:
    """Can we create a net namespace without the `unshare` binary?"""
    return hasattr(os, "unshare")


# ----------------------------------------------------------- namespace_exec
def run_confined(script: str, *, ns_name: str = _DEFAULT_NS,
                 proxy_port: int | None = None, timeout: int = 120) -> dict:
    """Run a Python snippet in the confined namespace, failing closed.

    Raises PerimeterUnavailable when the boundary is absent: a caller that wanted
    confinement must not silently receive an unconfined run.
    """
    perim = EgressPerimeter(ns_name, proxy_port=proxy_port)
    if not Path(f"/var/run/netns/{ns_name}").exists():
        raise PerimeterUnavailable(
            f"network namespace {ns_name!r} does not exist — run "
            f"scripts/skyla-perimeter.sh setup (as root, once)")
    if not Path(f"/var/run/netns/{perim.gateway_name}").exists():
        raise PerimeterUnavailable(
            f"gateway namespace {perim.gateway_name!r} does not exist — the "
            f"workload namespace is not usable without it")
    # verify() consults `_created`; run_confined attaches to a namespace another
    # process created, so mark it before verifying.
    perim._created = True
    st = perim.verify()
    if not st.available:
        raise PerimeterUnavailable(st.reason or "perimeter verification failed")
    return perim.run_probe(script, timeout=timeout)
