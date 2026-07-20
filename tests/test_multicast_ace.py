"""Regression tests for the multicast/broadcast classification in
mudgen_pcap.  Multicast (IPv4 224.0.0.0/4, IPv6 ff00::/8) must:

  * NOT be treated as ``local`` (so they do not contribute to the
    ``local-networks`` aggregation), and
  * classify as an ``ipnet`` endpoint with a /32 or /128 prefix so
    ``build_ace`` emits an RFC 8519 destination-prefix ACE.

The IPv4 limited broadcast (255.255.255.255) is likewise excluded
from ``local-networks``, but higher-level flow collection now
suppresses broadcast traffic entirely (see ``collect_flows``), so
no ACE is emitted for it.

The tests are pure-Python (no scapy required) and exercise the
classifiers/builders directly.

Run from the repository root::

    python3 tests/test_multicast_ace.py
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import mudgen_pcap  # noqa: E402  (sys.path fiddling)


FAILURES = []


def _check(cond, label):
    if cond:
        print("  ok   " + label)
    else:
        print("FAIL " + label)
        FAILURES.append(label)


def test_is_multicast_or_broadcast():
    print("_is_multicast_or_broadcast:")
    for ip in ("224.0.0.1", "224.0.0.251", "239.255.255.250",
               "255.255.255.255", "ff02::fb", "ff05::1:3", "ff00::1"):
        _check(mudgen_pcap._is_multicast_or_broadcast(ip),
               f"{ip} is multicast/broadcast")
    for ip in ("10.0.0.1", "192.168.1.1", "169.254.1.1", "127.0.0.1",
               "0.0.0.0", "8.8.8.8", "195.65.87.71",
               "fe80::1", "::1", "2001:db8::1"):
        _check(not mudgen_pcap._is_multicast_or_broadcast(ip),
               f"{ip} is not multicast/broadcast")


def test_is_local_excludes_multicast_and_broadcast():
    print("\n_is_local excludes multicast/broadcast:")
    # Positive: unicast local addresses still classify as local.
    for ip in ("10.0.0.1", "192.168.1.1", "169.254.1.1", "127.0.0.1",
               "fe80::1", "::1"):
        _check(mudgen_pcap._is_local(ip), f"{ip} is local")
    # Negative: multicast and broadcast no longer count as local.
    for ip in ("224.0.0.1", "224.0.0.251", "239.255.255.250",
               "255.255.255.255", "ff02::fb", "ff05::1:3"):
        _check(not mudgen_pcap._is_local(ip), f"{ip} is NOT local")


def test_classify_endpoint_produces_ipnet_for_multicast():
    print("\nclassify_endpoint(multicast) -> ipnet with /32 or /128:")
    cache = {}
    ep = mudgen_pcap.classify_endpoint("239.255.255.250", cache,
                                       local_use_networks=True,
                                       dns_map={})
    _check(ep.kind == "ipnet" and ep.value == "239.255.255.250/32",
           "IPv4 multicast -> ipnet 239.255.255.250/32 "
           f"(got kind={ep.kind!r}, value={ep.value!r})")

    cache = {}
    ep = mudgen_pcap.classify_endpoint("255.255.255.255", cache,
                                       local_use_networks=True,
                                       dns_map={})
    _check(ep.kind == "ipnet" and ep.value == "255.255.255.255/32",
           "IPv4 broadcast -> ipnet 255.255.255.255/32 "
           f"(got kind={ep.kind!r}, value={ep.value!r})")

    cache = {}
    ep = mudgen_pcap.classify_endpoint("ff02::fb", cache,
                                       local_use_networks=True,
                                       dns_map={})
    _check(ep.kind == "ipnet" and ep.value == "ff02::fb/128",
           "IPv6 multicast -> ipnet ff02::fb/128 "
           f"(got kind={ep.kind!r}, value={ep.value!r})")


def test_build_ace_multicast_is_destination_prefix():
    print("\nbuild_ace(multicast endpoint) emits destination prefix:")
    Flow = mudgen_pcap.Flow
    Endpoint = mudgen_pcap.Endpoint

    # SSDP: UDP/1900 from device -> 239.255.255.250.
    flow = Flow(4, "udp", "239.255.255.250", 1900)
    ep = Endpoint("ipnet", "239.255.255.250/32")
    fr = mudgen_pcap.build_ace(flow, ep, "from", "frace1")
    ipm = fr["matches"]["ipv4"]
    _check(ipm.get("destination-ipv4-network") == "239.255.255.250/32",
           "from-device ACE uses destination-ipv4-network=239.255.255.250/32")
    _check("source-ipv4-network" not in ipm,
           "from-device ACE does NOT carry source-ipv4-network")
    _check("ietf-mud:mud" not in fr["matches"],
           "from-device ACE does NOT carry ietf-mud:mud (no local-networks)")

    # IPv6 mDNS: UDP/5353 from device -> ff02::fb.
    flow6 = Flow(6, "udp", "ff02::fb", 5353)
    ep6 = Endpoint("ipnet", "ff02::fb/128")
    fr6 = mudgen_pcap.build_ace(flow6, ep6, "from", "frace1")
    ipm6 = fr6["matches"]["ipv6"]
    _check(ipm6.get("destination-ipv6-network") == "ff02::fb/128",
           "IPv6 from-device ACE uses destination-ipv6-network=ff02::fb/128")


def test_is_broadcast_ip():
    print("\n_is_broadcast_ip:")
    _check(mudgen_pcap._is_broadcast_ip("255.255.255.255"),
           "255.255.255.255 is the limited broadcast")
    for ip in ("224.0.0.1", "239.255.255.250", "192.168.1.255",
               "10.0.0.1", "8.8.8.8", "ff02::fb", "::1", "not-an-ip"):
        _check(not mudgen_pcap._is_broadcast_ip(ip),
               f"{ip} is not the limited broadcast")


def test_build_mud_multicast_is_not_local_networks():
    """A device whose only 'local' peers are multicast destinations
    must not produce any ``local-networks`` ACE — those destinations
    must appear individually as destination-prefix ACEs.

    Broadcast destinations (e.g. 255.255.255.255) are suppressed
    entirely at flow-collection time, so this test does not include
    them; see ``test_broadcast_suppressed_from_flows``.
    """
    print("\nbuild_mud: multicast-only device has no local-networks ACE:")
    Flow = mudgen_pcap.Flow
    flows = {}
    for ip, port in (("239.255.255.250", 1900),
                     ("224.0.0.251", 5353)):
        f = Flow(4, "udp", ip, port)
        f.samples = 1
        flows[f.key] = f

    mud = mudgen_pcap.build_mud(
        flows, mud_url="https://example.com/x.json",
        mfg="TestCo", model="TestModel", systeminfo="test",
        documentation=None, cache_validity=48, dns_map=None)

    aces = []
    for acl in mud["ietf-access-control-list:acls"]["acl"]:
        aces.extend(acl["aces"]["ace"])

    def matches_has_local_networks(ace):
        mud_match = ace["matches"].get("ietf-mud:mud") or {}
        return "local-networks" in mud_match

    local_net_aces = [a for a in aces if matches_has_local_networks(a)]
    _check(not local_net_aces,
           f"no local-networks ACE emitted (got {len(local_net_aces)})")

    # Each multicast destination should appear at least once as a
    # destination-ipv4-network prefix (on the from-device side).
    fr_prefixes = set()
    for acl in mud["ietf-access-control-list:acls"]["acl"]:
        if not acl["name"].endswith("fr"):
            continue
        for ace in acl["aces"]["ace"]:
            pfx = (ace["matches"].get("ipv4") or {}).get(
                "destination-ipv4-network")
            if pfx:
                fr_prefixes.add(pfx)
    for expected in ("239.255.255.250/32", "224.0.0.251/32"):
        _check(expected in fr_prefixes,
               f"from-device ACL contains destination prefix {expected}")
    _check("255.255.255.255/32" not in fr_prefixes,
           "from-device ACL contains NO 255.255.255.255/32 prefix "
           "(broadcasts are suppressed)")


if __name__ == "__main__":
    test_is_multicast_or_broadcast()
    test_is_local_excludes_multicast_and_broadcast()
    test_classify_endpoint_produces_ipnet_for_multicast()
    test_build_ace_multicast_is_destination_prefix()
    test_build_mud_multicast_is_not_local_networks()
    test_is_broadcast_ip()
    if FAILURES:
        print(f"\n{len(FAILURES)} FAILED")
        sys.exit(1)
    print("\nOK")
