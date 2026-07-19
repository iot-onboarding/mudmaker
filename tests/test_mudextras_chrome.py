"""End-to-end round-trip test for the mudextras extension checkboxes.

Drives mudmaker.html through Chrome:

  1. tick "sends directed broadcasts" and "receives directed broadcasts",
     assert the in-memory MUD file gains the
     ``mud-directed-broadcasts:directed-broadcasts`` container and the
     ``directed-broadcasts`` extension token;
  2. tick "multicast may cross segments", assert the
     ``multicast-across-segments`` marker joins the extensions array;
  3. capture the MUD file, then feed it back through
     ``MudMakerVisualizer.initializeLoadedMudFile`` (the same code path
     used by the "load saved work" drag-drop flow) and assert the
     checkboxes come back checked;
  4. load a legacy MUD file with the bare ``directed-broadcasts`` key
     and assert ``normalizeMUDFile`` migrates it to the module-qualified
     ``mud-directed-broadcasts:directed-broadcasts`` key;
  5. untick each in turn and assert the container / marker / extension
     tokens disappear again.

Note: a full-page reload (``page.reload()``) is *not* used here because
``assets/js/mudmaker-reload.js`` intentionally treats ``Cmd-R`` as
"start over" and wipes sessionStorage. The real round-trip is via
loading a saved JSON, which is what this test exercises.

Requires a running mudmaker stack on http://127.0.0.1:8081 and Google
Chrome installed and discoverable as the Playwright ``chrome`` channel.

Run from the repository root::

    python3 tests/test_mudextras_chrome.py
"""
import os
import sys

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit("playwright not installed; run `pip install playwright`")

BASE_URL = os.environ.get("MUDMAKER_URL", "http://127.0.0.1:8081")
HEADLESS = os.environ.get("MUDMAKER_HEADLESS", "1") not in ("0", "false", "no")
CHANNEL = os.environ.get("MUDMAKER_BROWSER_CHANNEL", "chrome")

MUD_KEY = "ietf-mud:mud"
DB_KEY = "mud-directed-broadcasts:directed-broadcasts"
EXT_DB = "directed-broadcasts"
EXT_MCAST = "multicast-across-segments"


def expect(cond, msg):
    if not cond:
        sys.exit("FAIL: " + msg)
    print("  ok  " + msg)


def mud(page):
    return page.evaluate(
        "() => document.mudFile && document.mudFile['ietf-mud:mud']"
    ) or {}


def extensions(page):
    return mud(page).get("extensions") or []


def toggle(page, sel, checked):
    """Set the checkbox state and fire change so the onchange handler runs."""
    page.evaluate(
        """([sel, v]) => {
          const el = document.querySelector(sel);
          el.checked = v;
          el.dispatchEvent(new Event('change', { bubbles: true }));
        }""",
        [sel, checked],
    )


def load_mud(page, mud_file):
    """Feed a MUD file through the same code path as the drag-drop
    "load saved work" flow."""
    page.evaluate(
        """(mf) => window.MudMakerVisualizer.initializeLoadedMudFile(mf)""",
        mud_file,
    )


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=HEADLESS, channel=CHANNEL)
        try:
            ctx = browser.new_context(viewport={"width": 1400, "height": 900})
            ctx.add_init_script("window.MUDMAKER_NO_TOUR = true;")
            page = ctx.new_page()
            page.goto(BASE_URL + "/mudmaker.html", wait_until="load")
            page.wait_for_selector("#db-outbound", state="attached")

            print("test 1: initial state — no mudextras data")
            m = mud(page)
            expect(DB_KEY not in m, "no directed-broadcasts container yet")
            exts = m.get("extensions") or []
            expect(EXT_DB not in exts,
                   "extensions has no 'directed-broadcasts' token yet")
            expect(EXT_MCAST not in exts,
                   "extensions has no 'multicast-across-segments' token yet")

            print("test 2: tick directed-broadcasts (both directions)")
            toggle(page, "#db-outbound", True)
            toggle(page, "#db-inbound", True)
            m = mud(page)
            expect(m.get(DB_KEY) == {"inbound": True, "outbound": True},
                   "container has both booleans (module-qualified key)")
            expect(EXT_DB in (m.get("extensions") or []),
                   "'directed-broadcasts' registered in extensions")

            print("test 3: tick multicast-across-segments")
            toggle(page, "#mcast-across-segments", True)
            exts = extensions(page)
            expect(EXT_MCAST in exts,
                   "'multicast-across-segments' registered in extensions")
            expect(EXT_DB in exts,
                   "'directed-broadcasts' still present after adding marker")

            print("test 4: round-trip through load-saved-work path")
            saved = page.evaluate(
                "() => JSON.parse(JSON.stringify(document.mudFile))"
            )
            # Reset the browser state by loading a bare MUD file, then
            # replay the saved file — exactly what a user does when
            # opening a downloaded MUD JSON in a new session.
            load_mud(page, {"ietf-mud:mud": {"mud-version": 1}})
            m = mud(page)
            expect(DB_KEY not in m, "reset cleared the container")
            load_mud(page, saved)
            m = mud(page)
            expect(m.get(DB_KEY) == {"inbound": True, "outbound": True},
                   "container survives round-trip through saved file")
            exts = m.get("extensions") or []
            expect(EXT_DB in exts,
                   "'directed-broadcasts' extension survives round-trip")
            expect(EXT_MCAST in exts,
                   "'multicast-across-segments' extension survives round-trip")
            expect(page.evaluate(
                "() => document.getElementById('db-inbound').checked"),
                   "inbound checkbox re-populated from loaded MUD")
            expect(page.evaluate(
                "() => document.getElementById('db-outbound').checked"),
                   "outbound checkbox re-populated from loaded MUD")
            expect(page.evaluate(
                "() => document.getElementById('mcast-across-segments').checked"),
                   "multicast checkbox re-populated from loaded MUD")

            print("test 5: legacy bare 'directed-broadcasts' key is normalised")
            legacy = {
                "ietf-mud:mud": {
                    "mud-version": 1,
                    "extensions": ["directed-broadcasts"],
                    "directed-broadcasts": {"inbound": True, "outbound": False},
                }
            }
            load_mud(page, legacy)
            m = mud(page)
            expect(m.get(DB_KEY) == {"inbound": True, "outbound": False},
                   "bare key migrated to module-qualified key on load")
            expect("directed-broadcasts" not in m,
                   "bare key removed from mud block")
            expect(page.evaluate(
                "() => document.getElementById('db-inbound').checked"),
                   "inbound checkbox populated from migrated legacy file")
            expect(not page.evaluate(
                "() => document.getElementById('db-outbound').checked"),
                   "outbound checkbox stays unchecked from migrated legacy file")

            print("test 6: untick removes container + tokens")
            toggle(page, "#db-outbound", False)
            toggle(page, "#db-inbound", False)
            m = mud(page)
            expect(DB_KEY not in m,
                   "container removed when both flags unchecked")
            expect(EXT_DB not in (m.get("extensions") or []),
                   "'directed-broadcasts' extension token removed")

            # Re-tick the marker (test 5 loaded a legacy file that lacks it).
            toggle(page, "#mcast-across-segments", True)
            expect(EXT_MCAST in extensions(page),
                   "marker token re-added by ticking checkbox")
            toggle(page, "#mcast-across-segments", False)
            expect(EXT_MCAST not in extensions(page),
                   "'multicast-across-segments' extension token removed")

            print("OK")
        finally:
            browser.close()


if __name__ == "__main__":
    main()

