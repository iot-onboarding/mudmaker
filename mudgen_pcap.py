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
      * For public addresses we first consult an ``IP -> name`` map
        built from DNS responses observed *in the captures
        themselves*.  When the IP appears in that map the queried
        name is used directly via the ``ietf-acldns:src-dnsname`` /
        ``ietf-acldns:dst-dnsname`` extension.
      * Otherwise (and only when ``--no-dns`` is not set) we fall
        back to a reverse-PTR lookup.  When the PTR record looks
        like a residential / consumer-ISP record (it embeds the IP
        octets or contains residential keywords such as ``dyn``,
        ``dsl``, ``cable``, ``cpe`` …) the endpoint is treated as
        the RFC 8520 ``my-controller`` abstraction; a "normal" PTR
        is used as the DNS name.
      * Public addresses with no name at all fall back to an
        RFC 8519 ``destination-ipv4-network`` /
        ``source-ipv4-network`` (or the IPv6 equivalent) match
        against the bare /32 or /128 prefix.

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
    from scapy.all import (  # type: ignore
        ARP, DNS, DNSRR, IP, IPv6, TCP, UDP, Ether, ICMP, rdpcap,
    )
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
                # ICMP / ICMPv6 cannot be represented in the
                # mudmaker UI (the protocol dropdown only offers
                # any/TCP/UDP) and is typically infrastructure
                # diagnostic traffic.  Skip it.
                continue
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

            # NTP (UDP/123) is also infrastructure traffic; skip it so
            # it doesn't appear in the generated MUD policy.
            if proto == "udp" and {sport, dport} & {123}:
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


def collect_dns_map(pcap_files) -> Dict[str, str]:
    """Build an ``IP -> hostname`` map by scanning DNS responses in
    the supplied pcaps.

    For every DNS response packet we look at the query (``qd.qname``)
    and every ``A`` / ``AAAA`` resource record in the answer section.
    Each answer IP is associated with the **query name** (not the
    CNAME chain target), because the query name is what the device
    actually asked for and is the most useful match in a MUD ACE.

    When the same IP appears in multiple responses for different
    names, the first one wins.  This is deterministic given a stable
    pcap-file order.
    """
    mapping: Dict[str, str] = {}

    def _decode(n) -> Optional[str]:
        if n is None:
            return None
        if isinstance(n, bytes):
            try:
                n = n.decode("ascii", errors="ignore")
            except Exception:  # noqa: BLE001
                return None
        n = str(n).strip().rstrip(".").lower()
        return n or None

    for path in pcap_files:
        try:
            pkts = rdpcap(path)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"warning: skipping {path}: {exc}\n")
            continue

        for pkt in pkts:
            if not pkt.haslayer(DNS):
                continue
            dns = pkt[DNS]
            # Only look at responses with at least one answer.
            if int(getattr(dns, "qr", 0)) != 1:
                continue
            if int(getattr(dns, "ancount", 0) or 0) == 0:
                continue

            qname = None
            if dns.qd is not None:
                qname = _decode(getattr(dns.qd, "qname", None))
            if not qname:
                continue

            an = dns.an
            if an is None:
                continue
            # ``dns.an`` is a scapy ``_list`` of DNSRR records; iterate
            # by index up to ``ancount``.
            try:
                n = len(an)
            except TypeError:
                n = 0
            for i in range(n):
                try:
                    rr = an[i]
                except (IndexError, TypeError):
                    break
                rtype = int(getattr(rr, "type", 0) or 0)
                rdata = getattr(rr, "rdata", None)
                # type 1 = A, type 28 = AAAA
                if rtype in (1, 28) and rdata:
                    ip = str(rdata)
                    if ip and ip not in mapping:
                        mapping[ip] = qname

    return mapping


# Threshold for collapsing high-port flows into a single "any port"
# ACE.  When more than ``_EPHEMERAL_MIN_FLOWS - 1`` distinct service
# ports strictly greater than ``_EPHEMERAL_PORT_THRESHOLD`` are seen
# to the same ``(ipver, proto, remote_ip)`` endpoint, those flows are
# merged into a single flow with ``service_port = None``.
#
# IMPORTANT: collapsing only affects the L4 port; the remote_ip is
# preserved verbatim so ``classify_endpoint`` produces exactly the
# same Endpoint kind for the merged flow as it did for the inputs.
# This guarantees that flows whose host part is a read-only RFC 8520
# abstraction (``local-networks`` or ``my-controller``) stay that
# way after the merge — they never degrade to an editable
# ``destination-ipv4-network`` / ``source-ipv4-network`` prefix.
_EPHEMERAL_PORT_THRESHOLD = 10000
_EPHEMERAL_MIN_FLOWS = 4  # "more than three"


def collapse_ephemeral_flows(flows: Dict[Tuple, Flow]) -> Dict[Tuple, Flow]:
    """Merge groups of high-port flows to the same remote endpoint.

    Flows are grouped by ``(ipver, proto, remote_ip)``.  Within each
    group, every TCP/UDP flow whose service port is strictly greater
    than ``_EPHEMERAL_PORT_THRESHOLD`` is a candidate.  When more
    than three such candidates exist for one endpoint, they are
    replaced by a single merged flow with ``service_port=None``
    (which ``build_ace`` renders as no port restriction → "any").

    Low-port flows in the same group are left untouched so their
    well-known service ports remain explicit in the MUD policy.

    The merged flow's ``remote_ip`` is unchanged, so endpoint
    classification (local / my-controller / dnsname / ipnet) is
    identical to that of the input flows.  The merged flow keeps an
    initiator only when every input flow agreed on it.
    """
    groups: Dict[Tuple[int, str, str], list] = defaultdict(list)
    for flow in flows.values():
        if flow.proto in ("tcp", "udp"):
            groups[(flow.ipver, flow.proto, flow.remote_ip)].append(flow)

    result = dict(flows)
    for (ipver, proto, remote_ip), group in groups.items():
        eph = [f for f in group
               if f.service_port is not None
               and f.service_port > _EPHEMERAL_PORT_THRESHOLD]
        if len(eph) < _EPHEMERAL_MIN_FLOWS:
            continue
        for f in eph:
            result.pop(f.key, None)
        merged = Flow(ipver, proto, remote_ip, None)
        inits = {f.initiator for f in eph if f.initiator}
        if len(inits) == 1:
            merged.initiator = inits.pop()
        merged.samples = sum(f.samples for f in eph)
        result[merged.key] = merged
    return result


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
                      *, local_use_networks: bool = True,
                      dns_map: Optional[Dict[str, str]] = None) -> Endpoint:
    """Classify a remote IP.

    ``local_use_networks`` controls how local-network peers are
    represented.  When True (more than one distinct local peer was seen
    across all flows) we emit the RFC 8520 ``local-networks``
    abstraction.  When False (only a single local peer talks to the
    device) that peer is treated as the device's ``my-controller``.

    ``dns_map`` is a precomputed ``IP -> hostname`` mapping derived
    from DNS responses observed in the pcap captures.  When the
    remote IP is present in the map, that name is used directly
    (no PTR lookup is attempted).
    """
    if ip in cache:
        return cache[ip]

    if _is_local(ip):
        ep = Endpoint("local" if local_use_networks else "controller",
                      None)
        cache[ip] = ep
        return ep

    hostname: Optional[str] = None
    # Prefer DNS answers observed in the captures themselves.
    if dns_map and ip in dns_map:
        hostname = dns_map[ip]
    elif do_dns:
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
              cache_validity: int,
              dns_map: Optional[Dict[str, str]] = None) -> dict:
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

    # Build (from-device, to-device) ACE pairs per flow with placeholder
    # names; we will dedupe and renumber below.
    pairs_per_ipver: Dict[int, list] = defaultdict(list)
    for flow in sorted_flows:
        endpoint = classify_endpoint(flow.remote_ip, do_dns, cache,
                                     local_use_networks=local_use_networks,
                                     dns_map=dns_map)
        fr = build_ace(flow, endpoint, "from", "_")
        to = build_ace(flow, endpoint, "to", "_")
        pairs_per_ipver[flow.ipver].append((fr, to))

    # Dedupe pairs whose match content is identical apart from
    # ``ietf-mud:direction-initiated``.  When two pairs share the same
    # stripped signature, keep the one that carries an initiator (so
    # we never lose that information just because another packet
    # ordering produced a less-specific duplicate ACE).
    def _strip_initiator(matches: dict) -> dict:
        out: dict = {}
        for k, v in matches.items():
            if isinstance(v, dict):
                out[k] = {kk: vv for kk, vv in v.items()
                          if kk != "ietf-mud:direction-initiated"}
            else:
                out[k] = v
        return out

    def _has_initiator(ace: dict) -> bool:
        for v in ace["matches"].values():
            if isinstance(v, dict) and "ietf-mud:direction-initiated" in v:
                return True
        return False

    def _signature(pair: Tuple[dict, dict]) -> str:
        fr, to = pair
        sig = (_strip_initiator(fr["matches"]),
               _strip_initiator(to["matches"]))
        return json.dumps(sig, sort_keys=True)

    deduped_per_ipver: Dict[int, list] = defaultdict(list)
    for ipver, pairs in pairs_per_ipver.items():
        chosen: Dict[str, Tuple[dict, dict]] = {}
        order: list = []
        for pair in pairs:
            sig = _signature(pair)
            if sig not in chosen:
                chosen[sig] = pair
                order.append(sig)
                continue
            # Prefer the pair that carries direction-initiated.
            current = chosen[sig]
            cur_has = _has_initiator(current[0]) or _has_initiator(current[1])
            new_has = _has_initiator(pair[0]) or _has_initiator(pair[1])
            if new_has and not cur_has:
                chosen[sig] = pair
        deduped_per_ipver[ipver] = [chosen[s] for s in order]

    # Post-classification subsumption: if two pairs share the same
    # host classification and protocol but one has "any port" (no
    # L4 port restriction) and the other has a specific port, the
    # specific one is redundant and is dropped.  This catches cases
    # like multiple ``local-networks`` UDP flows where one is
    # port=any — the specific-port siblings add no security value.
    def _host_signature(pair: Tuple[dict, dict]) -> str:
        # Build a signature from each ACE that ignores the L4 dict
        # entirely (so port + initiator + everything L4 is stripped).
        def _strip_l4(ace: dict) -> dict:
            return {k: v for k, v in ace["matches"].items()
                    if k not in ("tcp", "udp")}
        return json.dumps((_strip_l4(pair[0]), _strip_l4(pair[1])),
                          sort_keys=True)

    def _is_any_port(pair: Tuple[dict, dict]) -> bool:
        # "Any port" means no tcp/udp L4 match block at all.
        for ace in pair:
            for k in ("tcp", "udp"):
                if k in ace["matches"]:
                    return False
        return True

    for ipver, pairs in deduped_per_ipver.items():
        any_host_sigs = {_host_signature(p) for p in pairs
                         if _is_any_port(p)}
        if not any_host_sigs:
            continue
        deduped_per_ipver[ipver] = [
            p for p in pairs
            if _is_any_port(p) or _host_signature(p) not in any_host_sigs
        ]

    # Renumber the surviving ACEs so paired from-/to-device names stay
    # aligned across the two ACLs.  The naming convention matches what
    # the mudmaker UI expects (regex /^..(ace.*)/ in reloadFields):
    # ``fr{aceBase}`` for from-device and ``to{aceBase}`` for to-device,
    # where ``aceBase`` is e.g. ``ace7``.  Using this format lets the UI
    # pair the two ACLs back into a single form row per flow.
    for ipver, pairs in deduped_per_ipver.items():
        for i, (fr, to) in enumerate(pairs, start=1):
            fr["name"] = f"frace{i}"
            to["name"] = f"toace{i}"
            aces[("from", ipver)].append(fr)
            aces[("to", ipver)].append(to)

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


def _is_unicast_mac(mac: str) -> bool:
    """True if *mac* is a real unicast Ethernet address.

    Excludes broadcast (``ff:ff:ff:ff:ff:ff``), IPv4/IPv6 multicast
    mappings, and any other multicast address (LSB of the first octet
    set)."""
    try:
        first = int(mac.split(":", 1)[0], 16)
    except ValueError:
        return False
    return (first & 0x01) == 0 and mac.lower() != "ff:ff:ff:ff:ff:ff"


def _infer_device_mac(pcap_files) -> str:
    """Pick the device MAC from the supplied pcaps.

    Rules:
      1. If exactly two unicast MACs appear across all captures, pick
         the one that sources only a single distinct IP address (its
         own).  The other MAC sources many IPs and is the access point
         / gateway.
      2. Otherwise, fall back to the MAC that appears (as Ethernet src
         or dst) in *every* packet.  If exactly one MAC qualifies,
         return it; otherwise raise SystemExit.
    """
    common: Optional[set] = None
    saw_frame = False
    all_unicast: set = set()
    src_ips_per_mac: Dict[str, set] = defaultdict(set)

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
            src = eth.src.lower()
            dst = eth.dst.lower()
            macs = {src, dst}
            common = macs if common is None else common & macs
            for m in macs:
                if _is_unicast_mac(m):
                    all_unicast.add(m)
            if pkt.haslayer(IP):
                src_ips_per_mac[src].add(pkt[IP].src)
            elif pkt.haslayer(IPv6):
                src_ips_per_mac[src].add(pkt[IPv6].src)

    if not saw_frame:
        raise SystemExit(
            "could not infer device MAC: no Ethernet frames found in "
            "any pcap; supply --mac or create _iotdevice-mac.txt")

    # Rule 1: exactly two unicast MACs → the one with a single source IP
    # is the device; the multi-IP one is the AP.
    if len(all_unicast) == 2:
        scored = [(m, len(src_ips_per_mac.get(m, set())))
                  for m in all_unicast]
        singles = [m for m, n in scored if n == 1]
        multi = [m for m, n in scored if n > 1]
        if len(singles) == 1 and len(multi) == 1:
            return singles[0]
        # Ambiguous (both single-IP, both multi-IP, or one has zero
        # source IPs): fall through to the "in every packet" rule.

    # Rule 2: unique MAC present in every Ethernet frame.
    if not common:
        raise SystemExit(
            "could not infer device MAC: no MAC appears in every "
            "packet; supply --mac or create _iotdevice-mac.txt")

    if len(common) > 1:
        raise SystemExit(
            "could not infer device MAC: multiple MACs appear in every "
            f"packet ({', '.join(sorted(common))}); disambiguate with "
            "--mac or create _iotdevice-mac.txt")

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
                   help="do not perform reverse PTR lookups; the "
                        "name map built from DNS responses in the "
                        "captures is still used")
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
    flows = collapse_ephemeral_flows(flows)
    if not flows:
        # Help the user pick a different MAC: list every unicast MAC
        # that actually has IP traffic in these pcaps.
        try:
            seen: Dict[str, int] = defaultdict(int)
            for path in pcap_files:
                try:
                    pkts = rdpcap(path)
                except Exception:  # noqa: BLE001
                    continue
                for pkt in pkts:
                    if not pkt.haslayer(Ether):
                        continue
                    if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                        continue
                    eth = pkt[Ether]
                    for m in (eth.src.lower(), eth.dst.lower()):
                        try:
                            unicast = (int(m.split(":")[0], 16) & 1) == 0
                        except ValueError:
                            unicast = False
                        if unicast:
                            seen[m] += 1
            other = sorted(
                ((m, c) for m, c in seen.items() if m != mac),
                key=lambda kv: -kv[1])[:8]
            hint = (
                "; MACs with IP traffic: " +
                ", ".join(f"{m} ({c} pkts)" for m, c in other)
            ) if other else ""
        except Exception:  # noqa: BLE001
            hint = ""
        raise SystemExit(
            f"no IP traffic involving {mac} found in any pcap" + hint)

    mud = build_mud(
        flows,
        do_dns=not args.no_dns,
        mud_url=mud_url,
        mfg=args.mfg,
        model=model,
        systeminfo=systeminfo,
        documentation=args.documentation,
        cache_validity=args.cache_validity,
        dns_map=collect_dns_map(pcap_files),
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
