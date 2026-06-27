"""Smoke test for /pcap2mud: upload every SmarterCoffee pcap in one request
and validate the MUD output through the running Docker stack.
"""
import json
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

URL = "http://127.0.0.1:8081/pcap2mud"
ROOT = Path(__file__).resolve().parent.parent
PCAP_DIR = ROOT / "tmp/captures_IoT-Sentinel/SmarterCoffee"

mac = (PCAP_DIR / "_iotdevice-mac.txt").read_text().strip()
pcaps = sorted(PCAP_DIR.glob("*.pcap"))
if not pcaps:
    sys.exit("no pcaps found in " + str(PCAP_DIR))

boundary = "----smoketest-" + uuid.uuid4().hex
crlf = b"\r\n"
parts = []

def text_field(name, value):
    parts.append(("--" + boundary).encode())
    parts.append(
        ('Content-Disposition: form-data; name="' + name + '"').encode()
    )
    parts.append(b"")
    parts.append(value.encode())

text_field("mac", mac)
text_field("mfg", "Smarter")
text_field("model", "SmarterCoffee")

for p in pcaps:
    parts.append(("--" + boundary).encode())
    parts.append(
        ('Content-Disposition: form-data; name="pcap"; filename="' +
         p.name + '"').encode()
    )
    parts.append(b"Content-Type: application/vnd.tcpdump.pcap")
    parts.append(b"")
    parts.append(p.read_bytes())

parts.append(("--" + boundary + "--").encode())
parts.append(b"")
body = crlf.join(parts)

req = urllib.request.Request(
    URL,
    data=body,
    method="POST",
    headers={
        "Content-Type": "multipart/form-data; boundary=" + boundary,
        "Content-Length": str(len(body)),
    },
)

try:
    with urllib.request.urlopen(req, timeout=90) as resp:
        status = resp.status
        body = resp.read().decode("utf-8", "replace")
except urllib.error.HTTPError as e:
    status = e.code
    body = e.read().decode("utf-8", "replace")

try:
    payload = json.loads(body) if body.strip() else {}
except json.JSONDecodeError:
    sys.exit(
        f"HTTP {status} but body is not JSON ({len(body)} bytes):\n"
        + body[:2000]
    )

print("HTTP", status, "uploaded", len(pcaps), "pcap(s)")
assert status == 200, payload
assert "mud" in payload, payload

mud = payload["mud"]
mudblk = mud["ietf-mud:mud"]
acls = mud["ietf-access-control-list:acls"]["acl"]

print("mud-url    :", mudblk.get("mud-url"))
print("mfg-name   :", mudblk.get("mfg-name"))
print("model-name :", mudblk.get("model-name"))
print("acls       :", [a["name"] for a in acls])
if payload.get("notes"):
    print("notes      :", payload["notes"])

ace_count = 0
dns_aces = 0
prefix_aces = 0
myctl_aces = 0

for acl in acls:
    print()
    print(acl["name"], acl["type"])
    for ace in acl["aces"]["ace"]:
        ace_count += 1
        matches = ace["matches"]
        for ipver in ("ipv4", "ipv6"):
            ip = matches.get(ipver, {})
            if any(k.startswith("ietf-acldns:") for k in ip):
                dns_aces += 1
            if any("-network" in k for k in ip):
                prefix_aces += 1
        if matches.get("ietf-mud:mud"):
            myctl_aces += 1
        print(" ", ace["name"], json.dumps(matches))

print()
print("totals: aces=%d dns=%d prefix=%d my-controller=%d" %
      (ace_count, dns_aces, prefix_aces, myctl_aces))

assert ace_count > 0, "expected at least one ACE"
print("OK")
