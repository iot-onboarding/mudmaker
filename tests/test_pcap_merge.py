"""Unit tests for mergePcapMud() — incremental pcap-drop merging.

Exercises the merge helper added to assets/js/mudmaker.js via a Node
harness.  The helper is extracted by walking matching braces so the
test follows the same pattern as test_acl_dedupe.py.

Run from the repository root:
    python3 tests/test_pcap_merge.py
"""
import json
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
JS = (REPO / "assets" / "js" / "mudmaker.js").read_text()

if shutil.which("node") is None:
    sys.exit("node not installed; skipping")


def _extract(name):
    needle = "function " + name + "("
    start = JS.index(needle)
    depth = 0
    i = JS.index("{", start)
    while i < len(JS):
        c = JS[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return JS[start:i + 1]
        i += 1
    raise RuntimeError("function not found: " + name)


# mergePcapMud calls saveMUD/reloadFields/refreshmans plus reaches into
# window.MudMakerVisualizer; the harness stubs those out and substitutes
# a fake document/window so the helper runs untouched in Node.
harness = "\n".join([
    _extract("_aclDirections"),
    _extract("_aceSignature"),
    _extract("mergePcapMud"),
    textwrap.dedent("""
        function saveMUD(){}
        function reloadFields(){}
        function refreshmans(){}
        const window = { sessionStorage: { setItem(){} },
                         MudMakerVisualizer: { scheduleRender(){},
                             initializeLoadedMudFile(mf){
                                 document.mudFile = mf;
                             } } };
        const document = { mudFile: null };
        const MudMakerVisualizer = window.MudMakerVisualizer;
        let raw = '';
        process.stdin.setEncoding('utf8');
        process.stdin.on('data', (c) => { raw += c; });
        process.stdin.on('end', () => {
            const cases = JSON.parse(raw);
            const out = cases.map(function(c) {
                document.mudFile = c.current
                    ? JSON.parse(JSON.stringify(c.current))
                    : null;
                const res = mergePcapMud(c.incoming);
                return { result: res, merged: document.mudFile };
            });
            process.stdout.write(JSON.stringify(out));
        });
    """),
])


def run_js(cases):
    result = subprocess.run(
        ["node", "-e", harness],
        input=json.dumps(cases),
        check=False, capture_output=True, text=True,
    )
    if result.returncode != 0:
        print("node stderr:", result.stderr, file=sys.stderr)
        sys.exit(result.returncode)
    return json.loads(result.stdout)


def check(actual, expected, label):
    if actual != expected:
        print(f"FAIL {label}: got {actual!r}, expected {expected!r}")
        sys.exit(1)
    print(f"  ok   {label}")


# -------- builders --------------------------------------------------

def mud(acl_pairs, *, policy_pairs=None):
    """Build a minimal MUD blob.

    ``acl_pairs`` is a list of (name, aces) tuples.  ``policy_pairs``
    overrides which ACLs are wired to from-/to-device-policy; if None
    we infer from the ACL name suffix (``fr`` -> from, ``to`` -> to).
    """
    from_refs = []
    to_refs = []
    acls = []
    for name, aces in acl_pairs:
        acls.append({"name": name, "type": "ipv4-acl-type",
                     "aces": {"ace": aces}})
        if policy_pairs is None:
            if name.endswith("fr"):
                from_refs.append({"name": name})
            elif name.endswith("to"):
                to_refs.append({"name": name})
    if policy_pairs:
        from_refs = [{"name": n} for n in policy_pairs.get("from", [])]
        to_refs = [{"name": n} for n in policy_pairs.get("to", [])]
    return {
        "ietf-mud:mud": {
            "mud-version": 1,
            "from-device-policy": {
                "access-lists": {"access-list": from_refs},
            },
            "to-device-policy": {
                "access-lists": {"access-list": to_refs},
            },
        },
        "ietf-access-control-list:acls": {"acl": acls},
    }


def ace_dns(name, dns, port, *, src=False):
    """Return an ACE matching ``dns`` on TCP destination port ``port``."""
    key = "ietf-acldns:src-dnsname" if src else "ietf-acldns:dst-dnsname"
    return {
        "name": name,
        "matches": {
            "ipv4": {
                "protocol": 6,
                key: dns,
            },
            "tcp": {"destination-port": {"operator": "eq", "port": port}},
        },
        "actions": {"forwarding": "accept"},
    }


def ace_mycontroller(name, port):
    return {
        "name": name,
        "matches": {
            "ipv4": {"protocol": 6},
            "tcp": {"destination-port": {"operator": "eq", "port": port}},
            "ietf-mud:mud": {"my-controller": [None]},
        },
        "actions": {"forwarding": "accept"},
    }


# -------- tests -----------------------------------------------------

def _aces_of(mf, name):
    for acl in mf["ietf-access-control-list:acls"]["acl"]:
        if acl["name"] == name:
            return acl["aces"]["ace"]
    raise AssertionError("acl not found: " + name)


def _refs_of(mf, side):
    return [r["name"]
            for r in mf["ietf-mud:mud"][side]["access-lists"]["access-list"]]


def test_dedupe_same_ace():
    print("dedupe identical ACE:")
    current = mud([("mud-443-v4fr",
                    [ace_dns("dns0", "api.example.com", 443)])])
    incoming = mud([("mud-443-v4fr",
                     [ace_dns("dnsX", "api.example.com", 443)])])
    [out] = run_js([{"current": current, "incoming": incoming}])
    check(out["result"], {"added": 0, "skipped": 1}, "counters")
    check(len(_aces_of(out["merged"], "mud-443-v4fr")), 1, "ace count")


def test_union_different_ports():
    print("union ACLs with disjoint ports:")
    current = mud([
        ("mud-443-v4fr", [ace_dns("a", "api.example.com", 443)]),
        ("mud-443-v4to", [ace_dns("b", "api.example.com", 443, src=True)]),
    ])
    incoming = mud([
        ("mud-80-v4fr", [ace_dns("c", "ota.example.com", 80)]),
        ("mud-80-v4to", [ace_dns("d", "ota.example.com", 80, src=True)]),
    ])
    [out] = run_js([{"current": current, "incoming": incoming}])
    check(out["result"], {"added": 2, "skipped": 0}, "counters")
    names = sorted(a["name"]
                   for a in out["merged"]["ietf-access-control-list:acls"]["acl"])
    check(names,
          ["mud-443-v4fr", "mud-443-v4to", "mud-80-v4fr", "mud-80-v4to"],
          "acl names union")
    check(sorted(_refs_of(out["merged"], "from-device-policy")),
          ["mud-443-v4fr", "mud-80-v4fr"], "from-device refs wired")
    check(sorted(_refs_of(out["merged"], "to-device-policy")),
          ["mud-443-v4to", "mud-80-v4to"], "to-device refs wired")


def test_new_acl_appended_with_policy_mirror():
    print("brand-new ACL appended + policy mirroring:")
    current = mud([("mud-443-v4fr",
                    [ace_dns("a", "api.example.com", 443)])])
    # Only a from-device ACL exists in current; incoming brings in a
    # paired to-device ACL.  After the merge both refs must be present.
    incoming = mud([("mud-443-v4to",
                     [ace_dns("b", "api.example.com", 443, src=True)])])
    [out] = run_js([{"current": current, "incoming": incoming}])
    check(out["result"], {"added": 1, "skipped": 0}, "counters")
    check(sorted(a["name"]
                 for a in out["merged"]["ietf-access-control-list:acls"]["acl"]),
          ["mud-443-v4fr", "mud-443-v4to"], "both acls present")
    check(_refs_of(out["merged"], "to-device-policy"),
          ["mud-443-v4to"], "to-device ref added")


def test_distinct_targets_kept_separate():
    print("my-controller and dnsname for same port stay distinct:")
    current = mud([("mud-1883-v4fr",
                    [ace_mycontroller("mc", 1883)])])
    incoming = mud([("mud-1883-v4fr",
                     [ace_dns("d", "broker.example.com", 1883)])])
    [out] = run_js([{"current": current, "incoming": incoming}])
    # Different classification targets → different signatures → both
    # ACEs kept.  (Specificity-upgrade is intentionally out of scope.)
    check(out["result"], {"added": 1, "skipped": 0}, "counters")
    check(len(_aces_of(out["merged"], "mud-1883-v4fr")), 2,
          "both aces preserved")


def test_empty_current_falls_back_to_replace():
    print("empty current → degrades to replace:")
    incoming = mud([("mud-443-v4fr",
                     [ace_dns("a", "api.example.com", 443)])])
    [out] = run_js([{"current": None, "incoming": incoming}])
    check(out["result"]["added"], -1, "sentinel for replace path")


def test_dedupe_across_differently_named_acls():
    print("dedupe ignores ACL name (ephemeral source-port suffix):")
    # gitmud names ACLs after the ephemeral source port of the first
    # observed flow, so re-uploading the same pcaps usually produces
    # ACLs with different names but identical ACE content.  The merge
    # must collapse those by content signature, not by ACL name.
    current = mud([("mud-39740-v4fr",
                    [ace_mycontroller("frace1", 2081)]),
                   ("mud-39740-v4to",
                    [ace_mycontroller("toace1", 2081)])])
    incoming = mud([("mud-33211-v4fr",
                     [ace_mycontroller("frace1", 2081)]),
                    ("mud-33211-v4to",
                     [ace_mycontroller("toace1", 2081)])])
    [out] = run_js([{"current": current, "incoming": incoming}])
    check(out["result"], {"added": 0, "skipped": 2}, "counters")
    # No new ACLs appended.
    names = sorted(a["name"]
                   for a in out["merged"]["ietf-access-control-list:acls"]["acl"])
    check(names, ["mud-39740-v4fr", "mud-39740-v4to"],
          "no duplicate ACL appended")


if __name__ == "__main__":
    test_dedupe_same_ace()
    test_union_different_ports()
    test_new_acl_appended_with_policy_mirror()
    test_distinct_targets_kept_separate()
    test_empty_current_falls_back_to_replace()
    test_dedupe_across_differently_named_acls()
    print("all merge tests passed")
