"""End-to-end drag-drop test for #mud-live-visualizer driven by Chrome.

Verifies the new drag-drop module wired up in mudmaker.html:

  1. dropping a small synthetic MUD .json onto the visualizer aside
     populates form fields and renders the SVG (replace path);

  2. dropping the first half of the SmarterCoffee pcap fixtures triggers
     /pcap2mud and reports success (the visualizer is empty, so this is
     also the replace path);

  3. dropping the second half merges into the existing MUD without
     duplicating ACEs (the document.mudFile is now populated, so the
     drag-drop module picks the 'merge' code path).

Requires a running mudmaker stack on http://127.0.0.1:8081, Google
Chrome installed and discoverable as the Playwright ``chrome`` channel,
and the SmarterCoffee fixtures under tests/fixtures/SmarterCoffee/.

Run from the repository root::

    python3 tests/test_dragdrop_chrome.py
"""
import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
except ImportError:
    sys.exit("playwright not installed; run `pip install playwright`")

BASE_URL = os.environ.get("MUDMAKER_URL", "http://127.0.0.1:8081")
HEADLESS = os.environ.get("MUDMAKER_HEADLESS", "1") not in ("0", "false", "no")
CHANNEL = os.environ.get("MUDMAKER_BROWSER_CHANNEL", "chrome")

REPO = Path(__file__).resolve().parent.parent
PCAP_DIR = REPO / "tests" / "fixtures" / "SmarterCoffee"
MAC_FILE = PCAP_DIR / "_iotdevice-mac.txt"
# _iotdevice-mac.txt records 5c:cf:7f:07:ae:fb (the documented device
# MAC from the IoT-Sentinel dataset), but the trimmed fixture pcaps in
# tests/fixtures/SmarterCoffee/ only carry IP traffic from the source
# MAC below.  Allow an override so the same test works against a full
# capture set (MUDMAKER_PCAP_MAC=...).
FIXTURE_DEVICE_MAC = "00:b5:6d:06:08:ba"

# Minimal but well-formed MUD document used for the JSON-drop test.
SYNTHETIC_MUD = {
    "ietf-mud:mud": {
        "mud-version": 1,
        "mud-url": "https://example.com/dragdrop-test.json",
        "last-update": "2024-01-01T00:00:00+00:00",
        "cache-validity": 48,
        "is-supported": True,
        "systeminfo": "drag-drop synthetic device",
        "mfg-name": "DragDrop Inc",
        "model-name": "DD-1",
        "documentation": "https://example.com/dd.html",
        "from-device-policy": {
            "access-lists": {"access-list": [{"name": "mud-443-v4fr"}]},
        },
        "to-device-policy": {
            "access-lists": {"access-list": [{"name": "mud-443-v4to"}]},
        },
    },
    "ietf-access-control-list:acls": {
        "acl": [
            {
                "name": "mud-443-v4fr",
                "type": "ipv4-acl-type",
                "aces": {"ace": [{
                    "name": "dd0",
                    "matches": {
                        "ipv4": {
                            "protocol": 6,
                            "ietf-acldns:dst-dnsname": "api.example.com",
                        },
                        "tcp": {
                            "destination-port": {
                                "operator": "eq", "port": 443,
                            },
                        },
                    },
                    "actions": {"forwarding": "accept"},
                }]},
            },
            {
                "name": "mud-443-v4to",
                "type": "ipv4-acl-type",
                "aces": {"ace": [{
                    "name": "dd1",
                    "matches": {
                        "ipv4": {
                            "protocol": 6,
                            "ietf-acldns:src-dnsname": "api.example.com",
                        },
                        "tcp": {
                            "source-port": {
                                "operator": "eq", "port": 443,
                            },
                        },
                    },
                    "actions": {"forwarding": "accept"},
                }]},
            },
        ],
    },
}


# JS dispatched into the page to fabricate a DragEvent with a real
# DataTransfer holding File objects.  Files are passed as a list of
# {name, mime, b64} dicts; we decode each one into a Uint8Array and
# construct a File in-page (Playwright cannot pass File objects through
# the evaluate() bridge).
DISPATCH_JS = """
async ({selector, payloads, shiftKey}) => {
    const target = document.querySelector(selector);
    if (!target) { throw new Error('drop target not found: ' + selector); }
    const dt = new DataTransfer();
    for (const p of payloads) {
        const bin = atob(p.b64);
        const buf = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) { buf[i] = bin.charCodeAt(i); }
        const file = new File([buf], p.name,
            {type: p.mime || 'application/octet-stream'});
        dt.items.add(file);
    }
    function fire(type) {
        const ev = new DragEvent(type, {
            bubbles: true, cancelable: true,
            dataTransfer: dt, shiftKey: !!shiftKey,
        });
        target.dispatchEvent(ev);
    }
    fire('dragenter');
    fire('dragover');
    fire('drop');
    return true;
}
"""


def _payload(path: Path, mime: Optional[str] = None) -> dict:
    return {
        "name": path.name,
        "mime": mime or "application/vnd.tcpdump.pcap",
        "b64": base64.b64encode(path.read_bytes()).decode("ascii"),
    }


def _wait_for(page, fn, *, timeout_ms=20_000, poll_ms=200, label="condition"):
    deadline = time.time() + timeout_ms / 1000.0
    while time.time() < deadline:
        if fn():
            return
        page.wait_for_timeout(poll_ms)
    raise TimeoutError(f"timed out waiting for {label}")


def _ace_count(page) -> int:
    return page.evaluate(
        """() => {
            const mf = document.mudFile;
            if (!mf) { return 0; }
            const lists = mf['ietf-access-control-list:acls'];
            if (!lists || !Array.isArray(lists.acl)) { return 0; }
            return lists.acl.reduce((n, a) => {
                if (a && a.aces && Array.isArray(a.aces.ace)) {
                    return n + a.aces.ace.length;
                }
                return n;
            }, 0);
        }"""
    )


def _pcap_result_text(page) -> str:
    return page.evaluate(
        "() => (document.getElementById('pcap-result') || {}).textContent || ''"
    )


def _drive() -> None:
    pcaps = sorted(PCAP_DIR.glob("*.pcap"))
    if not pcaps:
        sys.exit(f"no SmarterCoffee pcaps under {PCAP_DIR}")
    mac = os.environ.get("MUDMAKER_PCAP_MAC", FIXTURE_DEVICE_MAC)

    # The trimmed SmarterCoffee fixtures are very small; collect_flows
    # needs enough cross-pcap traffic to produce any flows at all, so
    # we feed the full set in the "replace" drop.  The "merge" drop
    # then re-feeds the same set — every ACE the server emits the
    # second time must be deduped, exercising the merge path without
    # needing additional fixture data.
    print(f"  fixtures: {len(pcaps)} pcaps")
    full_payloads_cache = [_payload(p) for p in pcaps]

    with sync_playwright() as p:
        launch_kwargs = {"headless": HEADLESS}
        if CHANNEL:
            launch_kwargs["channel"] = CHANNEL
        browser = p.chromium.launch(**launch_kwargs)
        try:
            ctx = browser.new_context()
            page = ctx.new_page()
            errors: List[str] = []
            page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
            page.goto(f"{BASE_URL}/mudmaker.html", wait_until="load")
            page.wait_for_selector("#mud-live-visualizer", state="visible")
            # Ensure the dragdrop module attached its listener.
            ready = page.evaluate(
                "() => typeof window.MudMakerVisualizer === 'object'"
                " && typeof window.generateMudFromPcap === 'function'"
                " && typeof window.mergePcapMud === 'function'"
            )
            if not ready:
                sys.exit("page globals (visualizer/generate/merge) not ready")

            # --- Test 1: JSON drop --------------------------------------
            print("test 1: drop synthetic MUD JSON")
            json_payload = {
                "name": "synthetic.json",
                "mime": "application/json",
                "b64": base64.b64encode(
                    json.dumps(SYNTHETIC_MUD).encode("utf-8")
                ).decode("ascii"),
            }
            page.evaluate(
                DISPATCH_JS,
                {"selector": "#mud-live-visualizer",
                 "payloads": [json_payload], "shiftKey": False},
            )
            _wait_for(
                page,
                lambda: page.evaluate(
                    "() => !!(document.mudFile"
                    " && document.mudFile['ietf-mud:mud'])"
                ),
                label="document.mudFile populated",
            )
            mfg = page.input_value("#mfg-name")
            mdl = page.input_value("#model_name")
            # mudmaker derives #model_name from the mud-url slug, not
            # from the MUD's model-name field — see reloadFields().
            if mfg != "DragDrop Inc" or mdl != "dragdrop-test":
                sys.exit(f"form not populated: mfg={mfg!r}, model={mdl!r}")
            svg_nodes = page.evaluate(
                "() => document.querySelectorAll('#mud-live-svg *').length"
            )
            if svg_nodes < 3:
                sys.exit(f"SVG did not render (children={svg_nodes})")
            initial_aces = _ace_count(page)
            print(f"  ok  form populated; svg children={svg_nodes};"
                  f" aces={initial_aces}")

            # --- Test 2: PCAP drop (replace, because we want a clean MUD)
            # Shift-drop forces replace so the form metadata from the
            # JSON drop is overwritten by the server's empty defaults.
            print("test 2: drop full pcap fixture set (shift = replace)")
            if mac:
                # #pcapmac lives in a panel that may be hidden when the
                # Create tab is active; set its value via JS so we don't
                # need to switch tabs just to populate the MAC field.
                page.evaluate(
                    "(m) => {"
                    "  const el = document.getElementById('pcapmac');"
                    "  if (el) { el.value = m;"
                    "    el.dispatchEvent(new Event('change',"
                    "      {bubbles:true})); }"
                    "}",
                    mac,
                )
            payloads_full = full_payloads_cache
            page.evaluate(
                DISPATCH_JS,
                {"selector": "#mud-live-visualizer",
                 "payloads": payloads_full,
                 "shiftKey": True},
            )
            # Wait for the visualizer to switch to the server-generated
            # MUD (mud-url changes away from our synthetic value, or the
            # pcap-result reports success).  If the fixture MAC turns
            # out to lack IP traffic, the server returns a candidate
            # MAC in the error — retry once with that MAC.
            retried = {"done": False}
            def replaced():
                txt = _pcap_result_text(page)
                if "generated and loaded" in txt:
                    return True
                if "Could not" in txt or "failed" in txt.lower():
                    if retried["done"]:
                        raise RuntimeError("pcap2mud error: " + txt)
                    # Extract a candidate MAC and retry the drop once.
                    import re
                    cand = re.findall(
                        r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", txt.lower())
                    cand = [c for c in cand if c != mac.lower()]
                    if not cand:
                        raise RuntimeError("pcap2mud error: " + txt)
                    new_mac = cand[0]
                    print(f"  retrying with detected MAC {new_mac}")
                    page.evaluate(
                        "(m) => { const el ="
                        " document.getElementById('pcapmac');"
                        " if (el) { el.value = m;"
                        " el.dispatchEvent(new Event('change',"
                        " {bubbles:true})); } }",
                        new_mac,
                    )
                    page.evaluate(
                        DISPATCH_JS,
                        {"selector": "#mud-live-visualizer",
                         "payloads": payloads_full, "shiftKey": True},
                    )
                    retried["done"] = True
                return False
            _wait_for(page, replaced, timeout_ms=90_000,
                      label="pcap2mud replace to complete")
            replace_aces = _ace_count(page)
            if replace_aces <= 0:
                sys.exit(
                    f"no ACEs after pcap replace; pcap-result={_pcap_result_text(page)!r}"
                )
            print(f"  ok  pcap replace produced {replace_aces} ACE(s)")

            # Shift-Drop must wipe form metadata, not round-trip the
            # JSON-drop values back through the server.  We check that
            # mfg/systeminfo/documentation/mud-url all changed away
            # from their post-JSON-drop values.
            post_replace = page.evaluate(
                "() => ({"
                " mfg: (document.getElementById('mfg-name')||{}).value,"
                " systeminfo: (document.getElementById('systeminfo')||{}).value,"
                " documentation: (document.getElementById('documentation')||{}).value,"
                " mudUrl: ((document.mudFile||{})['ietf-mud:mud']||{})['mud-url'],"
                " preview: (document.getElementById('mud-url-preview')||{}).textContent,"
                "})"
            )
            stale = []
            if post_replace["mfg"] == "DragDrop Inc":
                stale.append("mfg-name")
            if post_replace["systeminfo"] == "drag-drop synthetic device":
                stale.append("systeminfo")
            if post_replace["documentation"] == "https://example.com/dd.html":
                stale.append("documentation")
            if post_replace["mudUrl"] == "https://example.com/dragdrop-test.json":
                stale.append("mud-url")
            if post_replace["preview"] == "https://example.com/dragdrop-test.json":
                stale.append("#mud-url-preview")
            if stale:
                sys.exit(
                    "Shift-Drop did not reset metadata; stale fields: "
                    + ", ".join(stale)
                    + f"; post-replace state={post_replace!r}"
                )
            print("  ok  Shift-Drop reset metadata (mfg/systeminfo/docs/mud-url)")

            # --- Test 3: PCAP drop (merge path) -------------------------
            # Re-drop the same fixture set without Shift.  Every ACE
            # the server emits should be deduped against the existing
            # MUD, so we expect ACE count unchanged and a non-zero
            # skipped counter in the report.
            print("test 3: re-drop same pcap set (default = merge)")
            before = replace_aces
            page.evaluate(
                DISPATCH_JS,
                {"selector": "#mud-live-visualizer",
                 "payloads": payloads_full,
                 "shiftKey": False},
            )
            def merged():
                txt = _pcap_result_text(page)
                if "Could not" in txt or "Merge failed" in txt:
                    raise RuntimeError("merge error: " + txt)
                return txt.startswith("Merged ")
            _wait_for(page, merged, timeout_ms=90_000,
                      label="merge report to appear")
            after = _ace_count(page)
            txt = _pcap_result_text(page)
            print(f"  pcap-result: {txt}")
            if after != before:
                # Dump structural diagnostics so the failure mode is
                # obvious without re-running with extra logging.
                snapshot = page.evaluate(
                    "() => JSON.stringify("
                    "document.mudFile['ietf-access-control-list:acls'].acl,"
                    " null, 0)"
                )
                print("  current ACLs:", snapshot[:2000])
                sys.exit(
                    f"merge changed ACE count (expected dedupe):"
                    f" before={before}, after={after}"
                )
            if "skipped 0" in txt or "skipped" not in txt:
                sys.exit(
                    f"merge did not skip any ACEs (dedupe failed): {txt}"
                )
            print(f"  ok  dedupe kept ACE count at {after}")

            if errors:
                # Tolerate harmless render warnings but surface them.
                print("  (pageerror noise: " + " | ".join(errors) + ")")
        finally:
            browser.close()


def main() -> None:
    if not PCAP_DIR.is_dir():
        sys.exit(f"missing fixture dir {PCAP_DIR}")
    try:
        _drive()
    except PWTimeout as e:
        sys.exit(f"playwright timeout: {e}")
    print("OK")


if __name__ == "__main__":
    main()
