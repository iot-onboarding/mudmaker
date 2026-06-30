"""Regression test for the mudgen_pcap.collect_flows service-port
heuristic, specifically the SYN-derived service-port fix that prevents
device-side ephemeral source ports from masquerading as the peer's
service port.

The EdimaxPlug1101W IoT-Sentinel fixture used to produce seven distinct
flow entries for the device's cloud-control rendezvous at
54.217.230.12 — one per device ephemeral source port (3299, 3301, 3536,
3800, 3802, 4391, 4393) — because the lower-port-wins fallback
incorrectly overrode the SYN-without-ACK dport (8767) whenever the real
service port lived above the device's ephemeral range.  After the fix,
those seven phantom flows collapse into one flow keyed at port 8767.

The test also exercises three correct-behaviour cases that the fix must
not regress:

  * peer-initiated connections to a device service (10.10.10.30:10000):
    no SYN-from-device evidence; the lower-port-wins fallback still
    consolidates the per-connection ephemeral peer source ports onto
    the device's listening port.

  * peer-initiated connections with no SYN observed (mid-stream capture
    from 192.168.20.100): pure lower-port-wins fallback unchanged.

  * UDP flows to www.myedimax.com (122.248.252.67) on three distinct
    service ports: must remain three separate flows, not be merged.

Run from the repository root::

    python3 tests/test_collect_flows_service_port.py
"""
import glob
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURE = REPO / "tmp" / "captures_IoT-Sentinel" / "EdimaxPlug1101W"

if not FIXTURE.is_dir():
    sys.exit("fixture missing: " + str(FIXTURE))

try:
    import scapy  # noqa: F401
except ImportError:
    sys.exit("scapy not installed; skipping")

sys.path.insert(0, str(REPO))
import mudgen_pcap  # noqa: E402  (sys.path fiddling)


def _check(cond, label):
    if not cond:
        print("FAIL " + label)
        sys.exit(1)
    print("  ok   " + label)


def test_edimax_plug_1101w_consolidation():
    mac = (FIXTURE / "_iotdevice-mac.txt").read_text().strip()
    pcaps = sorted(glob.glob(os.path.join(str(FIXTURE), "*.pcap")))
    if not pcaps:
        sys.exit("no pcaps found in " + str(FIXTURE))

    flows = mudgen_pcap.collect_flows(pcaps, mac)

    # Index by (proto, remote_ip) for clarity.
    by_remote = {}
    for f in flows.values():
        by_remote.setdefault((f.proto, f.remote_ip), []).append(f)

    print("collect_flows() (post-fix):")

    # 1. EXACTLY one TCP flow for 54.217.230.12, on the real peer
    #    service port (8767).  No phantom flows on the device's
    #    ephemeral source ports.
    aws = by_remote.get(("tcp", "54.217.230.12"), [])
    _check(len(aws) == 1,
           "54.217.230.12 has exactly one TCP flow (got %d)" % len(aws))
    aws_flow = aws[0]
    _check(aws_flow.service_port == 8767,
           "54.217.230.12 service port is 8767 "
           "(got %r)" % (aws_flow.service_port,))
    _check(aws_flow.initiator == "from-device",
           "54.217.230.12 initiator is from-device "
           "(got %r)" % (aws_flow.initiator,))
    bogus_ports = {3299, 3301, 3536, 3800, 3802, 4391, 4393}
    bogus_seen = {
        f.service_port for f in flows.values()
        if f.proto == "tcp" and f.remote_ip == "54.217.230.12"
    } & bogus_ports
    _check(not bogus_seen,
           "no flow for 54.217.230.12 on a device-ephemeral port "
           "(saw %r)" % (sorted(bogus_seen),))

    # 2. Peer-initiated TCP service exposed by the device (port 10000)
    #    must still consolidate via the lower-port fallback.
    one = by_remote.get(("tcp", "10.10.10.30"), [])
    _check(len(one) == 1 and one[0].service_port == 10000,
           "10.10.10.30 consolidates to one flow at port 10000 "
           "(got %r)" % ([(f.service_port, f.initiator) for f in one],))
    _check(one[0].initiator == "to-device",
           "10.10.10.30 initiator is to-device "
           "(got %r)" % (one[0].initiator,))

    two = by_remote.get(("tcp", "192.168.20.100"), [])
    _check(len(two) == 1 and two[0].service_port == 10000,
           "192.168.20.100 (no SYN seen) consolidates to one flow "
           "at port 10000 (got %r)" %
           ([(f.service_port, f.initiator) for f in two],))

    # 3. UDP flows to www.myedimax.com on three service ports stay
    #    distinct (no spurious merge).
    edimax = sorted(
        (f.service_port for f in by_remote.get(
            ("udp", "122.248.252.67"), [])
         if f.service_port is not None)
    )
    _check(edimax == [1270, 5336, 8765],
           "122.248.252.67 UDP flows are 1270/5336/8765 "
           "(got %r)" % (edimax,))


if __name__ == "__main__":
    test_edimax_plug_1101w_consolidation()
    print("OK")
