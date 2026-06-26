#!/usr/bin/env python3
"""
mudgen_pcap.py — Generate an RFC 8520 MUD file from a directory of pcap
captures for a single IoT device.

Inputs:
  - A directory containing one or more *.pcap files.
  - A file ``_iotdevice-mac.txt`` in that directory holding the device's
    Ethernet MAC address (one line, colon-separated).

Behaviour:
  - All traffic to/from that MAC is collected.
  - Flows are aggregated by (direction, IP version, L4 protocol,
    remote endpoint, remote service port).
  - For TCP, the side that sent a SYN (without ACK) is recorded as the
    connection initiator; that information drives the
    ``ietf-mud:direction-initiated`` leaf.
  - Remote endpoints are classified:

      * Private / link-local / multicast / broadcast addresses are
        treated as RFC 8520 ``local-networks``.
      * Public addresses are reverse-resolved.  When the PTR record
        looks like a residential / consumer-ISP record (it embeds the
        IP octets or contains residential keywords such as ``dyn``,
        ``dsl``, ``cable``, ``cpe`` …) the endpoint is treated as the
        RFC 8520 ``my-controller`` abstraction.
      * Public addresses with a "normal" PTR use that name via the
        ``ietf-acldns:src-dnsname`` / ``ietf-acldns:dst-dnsname``
        extension.
      * Public addresses with no PTR at all fall back to an RFC 8519
        ``destination-ipv4-network`` / ``source-ipv4-network`` (or the
        IPv6 equivalent) match against the bare /32 or /128 prefix.

The output is a single MUD file (JSON) written to stdout or to the file
named with ``--output``.  Only constructs defined by RFC 8520 and the
ACL model in RFC 8519 (with the ``ietf-acldns`` extension from
RFC 8520) are emitted.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import glob
import ipaddress
import json
import os
import random
import re
import socket
import sys
from collections import defaultdict
from typing import Dict, Optional, Tuple

try:
    from scapy.all import ARP, IP, IPv6, TCP, UDP, Ether, ICMP, rdpcap  # type: ignore
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "scapy is required: install with `pip install scapy`\n"
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Endpoint classification
# ---------------------------------------------------------------------------

# Substrings that strongly suggest a residential / consumer-ISP PTR.
_RESIDENTIAL_HINTS = (
    "dyn", "dynamic", "dsl", "adsl", "vdsl", "cable", "kabel",
    "broadband", "pool", "dhcp", "cust", "customer", "fiber", "ftth",
    "ppp", "cpe", "resnet", "hsd", "sat-net", "wireless", "wifi",
    "mobile", "lte", "umts", "gprs",
)

# Substrings indicating a datacenter / cloud / CDN PTR.  When matched we
# prefer the DNS name (or raw IP) rather than the ``my-controller``
# abstraction.
_DATACENTER_HINTS = (
    "amazonaws.com", "compute.amazonaws", "googleusercontent.com",
    "googlecloud", "1e100.net", "azure", "cloudapp.net", "akamai",
    "akamaitechnologies", "fastly", "cloudfront", "cloudflare",
    "ovh.net", "ovh.com", "digitalocean", "linode", "hetzner",
    "scaleway", "vultr", "oraclecloud", "rackspace", "alibabacloud",
    "tencentcloud", "edgecastcdn", "stackpathdns", "githubusercontent",
)


def _ip_appears_in_hostname(ip: str, hostname: str) -> bool:
    """Return True if the hostname embeds the IP address octets.

    Matches a range of common ISP encodings, e.g. ``81-14-202-72``,
    ``81.14.202.72``, ``81_14_202_72`` and the reversed form.
    """
    host = hostname.lower()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if isinstance(addr, ipaddress.IPv4Address):
        octets = ip.split(".")
        candidates = []
        for sep in (".", "-", "_"):
            candidates.append(sep.join(octets))
            candidates.append(sep.join(reversed(octets)))
        # Some ISPs zero-pad the octets.
        padded = [o.zfill(3) for o in octets]
        for sep in (".", "-", "_"):
            candidates.append(sep.join(padded))
            candidates.append(sep.join(reversed(padded)))
        return any(c in host for c in candidates)

    # IPv6: look for the exploded address with the colons replaced.
    exploded = addr.exploded
    for sep in (":", "-", ""):
        if exploded.replace(":", sep) in host:
            return True
    return False


def _looks_residential(ip: str, hostname: Optional[str]) -> bool:
    """Heuristic: does the PTR look like a home / consumer-ISP record?"""
    if not hostname:
        return False
    host = hostname.lower().rstrip(".")
    if any(dc in host for dc in _DATACENTER_HINTS):
        return False
    if _ip_appears_in_hostname(ip, host):
        return True
    # Look for hints in the hostname labels.
    labels = re.split(r"[.\-_]", host)
    return any(hint in labels or hint in host for hint in _RESIDENTIAL_HINTS)


def _is_local(ip: str) -> bool:
    """Private, link-local, multicast, broadcast or loopback."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_loopback
        or addr.is_unspecified
        or (isinstance(addr, ipaddress.IPv4Address)
            and str(addr) == "255.255.255.255")
    )


# ---------------------------------------------------------------------------
# Flow extraction
# ---------------------------------------------------------------------------

class Flow:
    """A unique remote endpoint reachable on one service port."""

    __slots__ = ("ipver", "proto", "remote_ip", "service_port",
                 "initiator", "samples")

    def __init__(self, ipver: int, proto: str, remote_ip: str,
                 service_port: Optional[int]) -> None:
        self.ipver = ipver
        self.proto = proto              # "tcp" | "udp" | "icmp"
        self.remote_ip = remote_ip
        self.service_port = service_port
        # "from-device" | "to-device" | None (unknown)
        self.initiator: Optional[str] = None
        self.samples = 0

    @property
    def key(self) -> Tuple:
        return (self.ipver, self.proto, self.remote_ip, self.service_port)


def collect_flows(pcap_files, device_mac: str) -> Dict[Tuple, Flow]:
    """Walk every pcap and return a dict of Flow records."""
    flows: Dict[Tuple, Flow] = {}
    mac = device_mac.lower()

    for path in pcap_files:
        try:
            pkts = rdpcap(path)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"warning: skipping {path}: {exc}\n")
            continue

        for pkt in pkts:
            if not pkt.haslayer(Ether):
                continue
            eth = pkt[Ether]
            src_mac = eth.src.lower()
            dst_mac = eth.dst.lower()
            if src_mac != mac and dst_mac != mac:
                continue
            from_device = src_mac == mac

            if pkt.haslayer(IP):
                l3 = pkt[IP]
                ipver = 4
            elif pkt.haslayer(IPv6):
                l3 = pkt[IPv6]
                ipver = 6
            else:
                # ARP and other L2-only frames have no MUD representation.
                continue

            remote_ip = l3.dst if from_device else l3.src

            sport = dport = None
            proto: Optional[str] = None
            tcp_initiator: Optional[str] = None

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                proto = "tcp"
                sport, dport = int(tcp.sport), int(tcp.dport)
                flags = int(tcp.flags)
                syn = bool(flags & 0x02)
                ack = bool(flags & 0x10)
                if syn and not ack:
                    tcp_initiator = "from-device" if from_device else "to-device"
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                proto = "udp"
                sport, dport = int(udp.sport), int(udp.dport)
            elif pkt.haslayer(ICMP) or (ipver == 6
                                        and getattr(l3, "nxt", None) == 58):
                proto = "icmp"
            else:
                # Skip exotic IP protocols.
                continue

            if proto in ("tcp", "udp"):
                # The "service port" is the remote-side port.  When the
                # device initiated the connection that is the
                # destination port; when the remote initiated, it is the
                # source port.  If neither end is obviously the
                # initiator (no SYN seen for this packet) we fall back
                # to "the lower of the two ports" — well-known services
                # always sit below the ephemeral range.
                if from_device:
                    service_port = dport
                else:
                    service_port = sport
                if service_port is not None and service_port >= 1024:
                    other = sport if from_device else dport
                    if other is not None and other < service_port:
                        service_port = other
            else:
                service_port = None

            # DHCP (UDP/67, UDP/68) is handled by the network
            # infrastructure and is not expressed in MUD policy.
            if proto == "udp" and {sport, dport} & {67, 68}:
                continue

            # DNS to a local resolver (the gateway / local network) is
            # likewise infrastructure traffic; skip it.
            if (proto in ("tcp", "udp")
                    and service_port == 53
                    and _is_local(remote_ip)):
                continue

            flow = flows.get((ipver, proto, remote_ip, service_port))
            if flow is None:
                flow = Flow(ipver, proto, remote_ip, service_port)
                flows[(ipver, proto, remote_ip, service_port)] = flow
            flow.samples += 1
            if tcp_initiator and flow.initiator is None:
                flow.initiator = tcp_initiator

    return flows


# ---------------------------------------------------------------------------
# MUD document construction
# ---------------------------------------------------------------------------

# Endpoint classification result.
#   kind     :  "local" | "controller" | "dnsname" | "ipnet"
#   value    :  hostname, ip prefix string, or None
class Endpoint:
    __slots__ = ("kind", "value")

    def __init__(self, kind: str, value: Optional[str]) -> None:
        self.kind = kind
        self.value = value


def classify_endpoint(ip: str, do_dns: bool,
                      cache: Dict[str, Endpoint],
                      *, local_use_networks: bool = True) -> Endpoint:
    """Classify a remote IP.

    ``local_use_networks`` controls how local-network peers are
    represented.  When True (more than one distinct local peer was seen
    across all flows) we emit the RFC 8520 ``local-networks``
    abstraction.  When False (only a single local peer talks to the
    device) that peer is treated as the device's ``my-controller``.
    """
    if ip in cache:
        return cache[ip]

    if _is_local(ip):
        ep = Endpoint("local" if local_use_networks else "controller",
                      None)
        cache[ip] = ep
        return ep

    hostname: Optional[str] = None
    if do_dns:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            hostname = None

    if hostname and _looks_residential(ip, hostname):
        ep = Endpoint("controller", None)
    elif hostname:
        ep = Endpoint("dnsname", hostname.lower().rstrip("."))
    else:
        addr = ipaddress.ip_address(ip)
        prefix = "/32" if isinstance(addr, ipaddress.IPv4Address) else "/128"
        ep = Endpoint("ipnet", f"{ip}{prefix}")

    cache[ip] = ep
    return ep


def _proto_number(proto: str, ipver: int) -> int:
    if proto == "tcp":
        return 6
    if proto == "udp":
        return 17
    if proto == "icmp":
        return 58 if ipver == 6 else 1
    raise ValueError(proto)


def _l3_key(ipver: int) -> str:
    return "ipv6" if ipver == 6 else "ipv4"


def _acl_type(ipver: int) -> str:
    return "ipv6-acl-type" if ipver == 6 else "ipv4-acl-type"


def _net_key(ipver: int, side: str) -> str:
    # side is "source" or "destination"
    suffix = "ipv6-network" if ipver == 6 else "ipv4-network"
    return f"{side}-{suffix}"


def build_ace(flow: Flow, endpoint: Endpoint, direction: str,
              ace_name: str) -> dict:
    """Build a single ACE.  ``direction`` is 'from' or 'to' (device)."""
    ipver = flow.ipver
    l3 = _l3_key(ipver)
    matches: Dict[str, dict] = {l3: {"protocol": _proto_number(flow.proto,
                                                               ipver)}}

    # Remote endpoint match.
    if endpoint.kind == "dnsname":
        key = "dst-dnsname" if direction == "from" else "src-dnsname"
        matches[l3][f"ietf-acldns:{key}"] = endpoint.value
    elif endpoint.kind == "ipnet":
        side = "destination" if direction == "from" else "source"
        matches[l3][_net_key(ipver, side)] = endpoint.value
    elif endpoint.kind == "controller":
        matches["ietf-mud:mud"] = {"my-controller": [None]}
    elif endpoint.kind == "local":
        matches["ietf-mud:mud"] = {"local-networks": [None]}

    # L4 ports / direction-initiated.
    if flow.proto in ("tcp", "udp") and flow.service_port is not None:
        l4: Dict[str, object] = {}
        if direction == "from":
            l4["destination-port"] = {"operator": "eq",
                                      "port": flow.service_port}
        else:
            l4["source-port"] = {"operator": "eq",
                                 "port": flow.service_port}
        if flow.proto == "tcp" and flow.initiator:
            l4["ietf-mud:direction-initiated"] = flow.initiator
        matches[flow.proto] = l4

    return {
        "name": ace_name,
        "matches": matches,
        "actions": {"forwarding": "accept"},
    }


def build_mud(flows: Dict[Tuple, Flow], do_dns: bool, *, mud_url: str,
              mfg: str, model: str, systeminfo: str,
              documentation: Optional[str],
              cache_validity: int) -> dict:
    cache: Dict[str, Endpoint] = {}

    # The RFC 8520 ``local-networks`` abstraction is only meaningful
    # when more than one local device actually communicates with this
    # device.  A solitary local peer is more accurately described as
    # the device's ``my-controller``.
    local_peers = {f.remote_ip for f in flows.values()
                   if _is_local(f.remote_ip)}
    local_use_networks = len(local_peers) > 1

    # Split flows per IP version and direction.  Direction here is
    # derived from "where the service lives": every flow we record has a
    # remote endpoint, so it appears in both the from-device and
    # to-device ACLs (one matches the outbound packet, one matches the
    # response).
    aces: Dict[Tuple[str, int], list] = defaultdict(list)

    # Stable ordering for reproducible output.
    sorted_flows = sorted(flows.values(),
                          key=lambda f: (f.ipver, f.proto, f.remote_ip,
                                         f.service_port or 0))

    counter = 0
    for flow in sorted_flows:
        endpoint = classify_endpoint(flow.remote_ip, do_dns, cache,
                                     local_use_networks=local_use_networks)
        counter += 1
        base = f"ace{counter}"
        aces[("from", flow.ipver)].append(
            build_ace(flow, endpoint, "from", f"{base}-frdev"))
        aces[("to", flow.ipver)].append(
            build_ace(flow, endpoint, "to", f"{base}-todev"))

    mud_tag = f"mud-{random.randint(10000, 99999)}"

    acls: list = []
    from_lists: list = []
    to_lists: list = []

    for ipver in (4, 6):
        if aces[("from", ipver)]:
            name = f"{mud_tag}-v{ipver}fr"
            acls.append({"name": name, "type": _acl_type(ipver),
                         "aces": {"ace": aces[("from", ipver)]}})
            from_lists.append({"name": name})
        if aces[("to", ipver)]:
            name = f"{mud_tag}-v{ipver}to"
            acls.append({"name": name, "type": _acl_type(ipver),
                         "aces": {"ace": aces[("to", ipver)]}})
            to_lists.append({"name": name})

    mud: Dict[str, object] = {
        "mud-version": 1,
        "mud-url": mud_url,
        "last-update": _dt.datetime.now(_dt.timezone.utc)
                                 .replace(microsecond=0).isoformat(),
        "cache-validity": cache_validity,
        "is-supported": True,
        "systeminfo": systeminfo,
        "mfg-name": mfg,
        "model-name": model,
    }
    if documentation:
        mud["documentation"] = documentation
    mud["from-device-policy"] = {"access-lists": {"access-list": from_lists}}
    mud["to-device-policy"] = {"access-lists": {"access-list": to_lists}}

    return {
        "ietf-mud:mud": mud,
        "ietf-access-control-list:acls": {"acl": acls},
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def _read_mac_file(directory: str) -> Optional[str]:
    """Return the MAC from ``_iotdevice-mac.txt`` or None if absent."""
    path = os.path.join(directory, "_iotdevice-mac.txt")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="ascii") as fh:
        line = fh.readline().strip()
    if not re.fullmatch(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}", line):
        raise SystemExit(f"{path}: not a MAC address: {line!r}")
    return line.lower()


def _infer_device_mac(pcap_files) -> str:
    """Find the single MAC address that appears (as src or dst) in
    *every* Ethernet frame across all pcaps.  Raise SystemExit if no
    such address exists, or if more than one address qualifies (in
    which case the caller must disambiguate with ``--mac``).
    """
    common: Optional[set] = None
    saw_frame = False
    for path in pcap_files:
        try:
            pkts = rdpcap(path)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"warning: skipping {path}: {exc}\n")
            continue
        for pkt in pkts:
            if not pkt.haslayer(Ether):
                continue
            saw_frame = True
            eth = pkt[Ether]
            macs = {eth.src.lower(), eth.dst.lower()}
            common = macs if common is None else common & macs
            if not common:
                raise SystemExit(
                    "could not infer device MAC: no single MAC address "
                    "appears in every frame; create "
                    "_iotdevice-mac.txt or pass --mac")
    if not saw_frame:
        raise SystemExit(
            "could not infer device MAC: no Ethernet frames found")
    if len(common) > 1:
        raise SystemExit(
            "could not infer device MAC: multiple MACs appear in every "
            f"frame ({sorted(common)}); disambiguate with --mac or "
            "create _iotdevice-mac.txt")
    return next(iter(common))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument("directory",
                   help="directory containing *.pcap files (and "
                        "optionally _iotdevice-mac.txt)")
    p.add_argument("--mac", help="device MAC address; overrides "
                                  "_iotdevice-mac.txt and auto-detection")
    p.add_argument("--mud-url",
                   help="value for ietf-mud:mud/mud-url "
                        "(default derived from --model)")
    p.add_argument("--mfg", default="Unknown Manufacturer",
                   help="value for mfg-name")
    p.add_argument("--model",
                   help="value for model-name (default: directory basename)")
    p.add_argument("--systeminfo",
                   help="value for systeminfo")
    p.add_argument("--documentation",
                   help="value for documentation URL")
    p.add_argument("--cache-validity", type=int, default=48,
                   help="value for cache-validity (hours), default 48")
    p.add_argument("--no-dns", action="store_true",
                   help="do not perform reverse DNS lookups")
    p.add_argument("--output", "-o",
                   help="write MUD JSON here (default: stdout)")
    args = p.parse_args(argv)

    directory = os.path.abspath(args.directory)
    if not os.path.isdir(directory):
        raise SystemExit(f"{directory}: not a directory")

    pcap_files = sorted(glob.glob(os.path.join(directory, "*.pcap"))
                        + glob.glob(os.path.join(directory, "*.pcapng")))
    if not pcap_files:
        raise SystemExit(f"{directory}: no pcap files found")

    if args.mac:
        mac = args.mac.lower()
    else:
        mac = _read_mac_file(directory)
        if mac is None:
            mac = _infer_device_mac(pcap_files)
            sys.stderr.write(f"inferred device MAC: {mac}\n")

    model = args.model or os.path.basename(directory.rstrip("/")) or "device"
    mud_url = args.mud_url or (
        f"https://example.com/.well-known/mud/{model}")
    systeminfo = (args.systeminfo
                  or f"MUD policy derived from pcap captures for {model}")

    flows = collect_flows(pcap_files, mac)
    if not flows:
        sys.stderr.write(
            f"warning: no IP traffic involving {mac} found in any pcap\n")

    mud = build_mud(
        flows,
        do_dns=not args.no_dns,
        mud_url=mud_url,
        mfg=args.mfg,
        model=model,
        systeminfo=systeminfo,
        documentation=args.documentation,
        cache_validity=args.cache_validity,
    )

    text = json.dumps(mud, indent=2) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
