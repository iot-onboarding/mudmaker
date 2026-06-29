"""End-to-end test for the Basic-Info status chip in the visualizer.

Drives mudmaker.html through Chrome and exercises the chip wired up
to ``#mud-live-toggle``:

  1. chip is hidden by default (visualizer not maximized);
  2. maximizing reveals it with data-status="empty" when no Basic-Info
     fields are filled;
  3. filling every required field flips status to "ok" and the chip
     text shows the manufacturer name;
  4. clearing a required field while still maximized flips status to
     "incomplete";
  5. clicking the chip leaves the maximized state and focuses
     #mfg-name.

Requires a running mudmaker stack on http://127.0.0.1:8081, Google
Chrome installed and discoverable as the Playwright ``chrome``
channel.

Run from the repository root::

    python3 tests/test_basicinfo_chip_chrome.py
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


def expect(cond, msg):
    if not cond:
        sys.exit("FAIL: " + msg)
    print("  ok  " + msg)


def set_value_and_fire(page, sel, value):
    """Programmatically set #id.value and dispatch 'input' so the chip
    listener runs even while the field is hidden by maximize.  Using
    Playwright's fill() would fail because maximized state hides the
    field via display:none."""
    page.evaluate(
        """([sel, v]) => {
          const el = document.querySelector(sel);
          el.value = v;
          el.dispatchEvent(new Event('input', { bubbles: true }));
        }""",
        [sel, value],
    )


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=HEADLESS, channel=CHANNEL)
        try:
            ctx = browser.new_context(viewport={"width": 1400,
                                                "height": 900})
            # Suppress the first-visit guided tour so it does not
            # intercept clicks below.
            ctx.add_init_script(
                "try { localStorage.setItem('mudmaker.tour.seen', '1'); }"
                " catch (e) {}"
            )
            page = ctx.new_page()
            page.goto(BASE_URL + "/mudmaker.html", wait_until="load")
            page.wait_for_selector("#mud-live-toggle", state="visible")

            print("test 1: chip hidden when not maximized")
            chip_visible = page.is_visible("#mud-live-basic-status")
            expect(not chip_visible, "chip hidden by default")
            # Toggle button icon should reflect "maximize" (4-corner
            # brackets, path starting with "M3 6").
            icon_path = page.evaluate(
                "() => { const p = document.querySelector("
                "'#mud-live-toggle svg path'); "
                "return p ? p.getAttribute('d') : null; }")
            expect(icon_path is not None and icon_path.startswith("M3 6"),
                   "maximize icon shows 4-corner SVG (got %r)"
                   % icon_path)

            print("test 2: maximize with empty fields -> status 'empty'")
            page.click("#mud-live-toggle")
            page.wait_for_selector(".maker-live-layout.maximized",
                                   state="attached")
            page.wait_for_selector("#mud-live-basic-status",
                                   state="visible")
            status = page.get_attribute("#mud-live-basic-status",
                                        "data-status")
            expect(status == "empty",
                   "chip data-status == 'empty' (got %r)" % status)
            # Toggle button icon should now reflect "restore-down"
            # (two overlapping squares, back square path "M6 5").
            icon_paths = page.evaluate(
                "() => Array.from(document.querySelectorAll("
                "'#mud-live-toggle svg path')).map(p =>"
                " p.getAttribute('d'))")
            expect(any(p and p.startswith("M6 5") for p in icon_paths),
                   "restore icon shows overlapping-squares SVG"
                   " (got %r)" % icon_paths)

            print("test 3: fill required fields -> status 'ok'")
            set_value_and_fire(page, "#mfg-name", "Acme Corp")
            set_value_and_fire(page, "#systeminfo",
                               "Smart kettle that toasts")
            set_value_and_fire(page, "#documentation",
                               "https://acme.example/docs")
            set_value_and_fire(page, "#email_addr",
                               "support@acme.example")
            page.wait_for_function(
                "() => document.querySelector("
                "'#mud-live-basic-status').getAttribute("
                "'data-status') === 'ok'",
                timeout=2000)
            text = page.inner_text("#mud-live-basic-status")
            expect("Acme Corp" in text,
                   "chip text includes manufacturer (got %r)" % text)

            print("test 4: clear a field while maximized -> 'incomplete'")
            set_value_and_fire(page, "#documentation", "")
            page.wait_for_function(
                "() => document.querySelector("
                "'#mud-live-basic-status').getAttribute("
                "'data-status') === 'incomplete'",
                timeout=2000)
            text = page.inner_text("#mud-live-basic-status")
            expect("missing" in text.lower(),
                   "chip text mentions missing fields (got %r)" % text)

            print("test 5: click chip -> exits maximized, focuses #mfg-name")
            page.click("#mud-live-basic-status")
            page.wait_for_function(
                "() => !document.querySelector('.maker-live-layout')"
                ".classList.contains('maximized')",
                timeout=2000)
            focused_id = page.evaluate(
                "() => document.activeElement && "
                "document.activeElement.id")
            expect(focused_id == "mfg-name",
                   "active element is #mfg-name (got %r)" % focused_id)
            chip_visible = page.is_visible("#mud-live-basic-status")
            expect(not chip_visible,
                   "chip hidden after exiting maximized state")

            print("test 6: dropping a MUD .json while maximized -> 'ok'")
            # Clear everything first so test 6 starts from a known
            # empty state.
            page.evaluate("""() => {
              ['mfg-name','systeminfo','documentation','email_addr']
                .forEach(id => {
                  const el = document.getElementById(id);
                  if (el) {
                    el.value = '';
                    el.dispatchEvent(new Event('input', { bubbles: true }));
                  }
                });
            }""")
            # Maximize: chip should now read 'empty'.
            page.click("#mud-live-toggle")
            page.wait_for_function(
                "() => document.querySelector("
                "'#mud-live-basic-status').getAttribute("
                "'data-status') === 'empty'",
                timeout=2000)
            # Synthesize a MUD JSON drop directly via the public
            # visualizer API — this is the exact path the drag-drop
            # module follows when a .json file is dropped.
            page.evaluate("""() => {
              const mud = {
                'ietf-mud:mud': {
                  'mud-version': 1,
                  'mud-url': 'https://example.com/widget.json',
                  'last-update': '2026-06-28T00:00:00Z',
                  'cache-validity': 48,
                  'is-supported': true,
                  'systeminfo': 'A demo widget',
                  'mfg-name': 'WidgetCo',
                  'documentation': 'https://widgetco.example/docs',
                  'model-name': 'W-100',
                  'from-device-policy': { 'access-lists': { 'access-list': [] } },
                  'to-device-policy': { 'access-lists': { 'access-list': [] } }
                },
                'email_addr': 'support@widgetco.example',
                'ietf-access-control-list:acls': { 'acl': [] }
              };
              window.MudMakerVisualizer.initializeLoadedMudFile(mud);
            }""")
            page.wait_for_function(
                "() => document.querySelector("
                "'#mud-live-basic-status').getAttribute("
                "'data-status') === 'ok'",
                timeout=2000)
            text = page.inner_text("#mud-live-basic-status")
            expect("WidgetCo" in text,
                   "chip text updated after drop (got %r)" % text)
        finally:
            browser.close()
    print("OK")


if __name__ == "__main__":
    main()
