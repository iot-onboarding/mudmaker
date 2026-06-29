"""End-to-end accessibility scan driven by Chrome + axe-core.

Loads mudmaker.html in a real headless Chrome, injects the axe-core
library, and reports any rule violations.  The test is split into
passes so we can scan each tab (axe ignores nodes hidden by
``display:none``):

  * the Create tab (default landing)
  * the Sign/Publish tab
  * the View MUD File tab

By default the test FAILS when axe reports any rule with impact
``critical`` or ``serious`` and prints all violations (any impact) to
stdout so they show up in CI logs.  Set the environment variable
``MUDMAKER_A11Y_STRICT=1`` to fail on *any* impact, or
``MUDMAKER_A11Y_STRICT=0`` to print but never fail.

axe-core is fetched once from a CDN and cached under
``tests/vendor/axe.min.js`` so subsequent runs work offline.

Requires a running mudmaker stack on http://127.0.0.1:8081, Google
Chrome installed and discoverable as the Playwright ``chrome``
channel.

Run from the repository root::

    python3 tests/test_a11y_chrome.py
"""
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit("playwright not installed; run `pip install playwright`")

BASE_URL = os.environ.get("MUDMAKER_URL", "http://127.0.0.1:8081")
HEADLESS = os.environ.get("MUDMAKER_HEADLESS", "1") not in ("0", "false", "no")
CHANNEL = os.environ.get("MUDMAKER_BROWSER_CHANNEL", "chrome")
STRICT = os.environ.get("MUDMAKER_A11Y_STRICT", "default")

AXE_VERSION = "4.10.0"
AXE_URL = (
    "https://cdnjs.cloudflare.com/ajax/libs/axe-core/"
    + AXE_VERSION
    + "/axe.min.js"
)
VENDOR_DIR = Path(__file__).parent / "vendor"
AXE_CACHE = VENDOR_DIR / "axe.min.js"

# Rules disabled because they fire only on legacy upstream template
# markup (the "Asymmetric" HTML5 UP theme) that mudmaker.html inherits.
# They are NOT regressions from the live-MUD UI; suppressing them keeps
# this regression test focused on new code.  To audit the legacy theme,
# comment any of these out and run again.
DISABLED_RULES = [
    # CSS in assets/css/main.css ships button/tab colors that don't
    # meet WCAG AA contrast.  Theme-wide fix is out of scope.
    "color-contrast",
    # Theme markup uses <section> wrappers and no <main>.
    "landmark-one-main",
    # Theme uses an <h2> page title; no <h1> is rendered.
    "page-has-heading-one",
    # Theme content sits outside landmark regions in places.
    "region",
]


def _ensure_axe():
    """Download axe-core on first run, cache under tests/vendor/."""
    if AXE_CACHE.exists() and AXE_CACHE.stat().st_size > 0:
        return
    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    print("  fetching axe-core %s from CDN ..." % AXE_VERSION)
    try:
        urllib.request.urlretrieve(AXE_URL, AXE_CACHE)
    except urllib.error.URLError as exc:  # pragma: no cover - offline CI
        sys.exit(
            "could not fetch axe-core (%s); place axe.min.js manually at %s"
            % (exc, AXE_CACHE)
        )


def _run_axe(page, label):
    """Inject axe and run it against the current DOM state."""
    page.add_script_tag(path=str(AXE_CACHE))
    rules_cfg = {}
    if DISABLED_RULES:
        rules_cfg = {r: {"enabled": False} for r in DISABLED_RULES}
    result = page.evaluate(
        """
async (opts) => {
  const axeOpts = {
    resultTypes: ['violations'],
    runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a',
                                     'wcag21aa', 'best-practice'] },
  };
  if (opts && opts.rules) axeOpts.rules = opts.rules;
  const r = await axe.run(document, axeOpts);
  return {
    violations: r.violations.map(v => ({
      id: v.id,
      impact: v.impact,
      help: v.help,
      helpUrl: v.helpUrl,
      nodes: v.nodes.slice(0, 3).map(n => ({
        target: n.target,
        html: (n.html || '').slice(0, 200),
        failureSummary: n.failureSummary,
      })),
      total: v.nodes.length,
    })),
  };
}
""",
        {"rules": rules_cfg},
    )
    print("  pass %s: %d violation rule(s)" % (label, len(result["violations"])))
    for v in result["violations"]:
        print("    [%s] %s (%d node%s)"
              % (v["impact"] or "n/a", v["id"], v["total"],
                 "" if v["total"] == 1 else "s"))
        print("      help: %s" % v["help"])
        for n in v["nodes"]:
            target = " / ".join(json.dumps(t) for t in n["target"])
            print("        - %s" % target)
            html = n["html"].replace("\n", " ").strip()
            if html:
                print("          %s" % html)
    return result["violations"]


def main():
    _ensure_axe()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=HEADLESS, channel=CHANNEL)
        try:
            ctx = browser.new_context(viewport={"width": 1400,
                                                "height": 900})
            # Suppress the first-visit guided tour so its overlay does
            # not intercept the tab-switch clicks below.
            ctx.add_init_script("window.MUDMAKER_NO_TOUR = true;")
            page = ctx.new_page()
            page.goto(BASE_URL + "/mudmaker.html", wait_until="load")
            page.wait_for_selector("#mud-live-toggle", state="visible")

            all_violations = []
            # Create tab is the default landing.
            all_violations += _run_axe(page, "create-tab")

            # Switch to Publish tab and rescan (its rows are now in DOM).
            page.click("button.tablinks:has-text('Publish')")
            page.wait_for_selector("#publish", state="visible")
            all_violations += _run_axe(page, "publish-tab")

            # View MUD File tab.
            page.click("button.tablinks:has-text('View MUD File')")
            page.wait_for_selector("#viewmudfile", state="visible")
            all_violations += _run_axe(page, "view-tab")
        finally:
            browser.close()

    # Deduplicate by rule id, keeping the worst impact / largest count.
    impact_order = {"critical": 4, "serious": 3, "moderate": 2,
                    "minor": 1, None: 0}
    by_id = {}
    for v in all_violations:
        prev = by_id.get(v["id"])
        if (prev is None
                or impact_order.get(v["impact"], 0)
                > impact_order.get(prev["impact"], 0)):
            by_id[v["id"]] = v

    print()
    print("axe summary: %d unique rule violation(s) across all tabs"
          % len(by_id))
    counts = {"critical": 0, "serious": 0, "moderate": 0, "minor": 0,
              "other": 0}
    for v in by_id.values():
        counts[v["impact"] if v["impact"] in counts else "other"] += 1
    print("  by impact:", counts)

    if STRICT == "0":
        print("MUDMAKER_A11Y_STRICT=0 -> not failing on violations")
        print("OK")
        return

    if STRICT == "1":
        threshold = ("critical", "serious", "moderate", "minor")
    else:  # default
        threshold = ("critical", "serious")

    failing = [v for v in by_id.values() if v["impact"] in threshold]
    if failing:
        print()
        print("FAILED: %d rule(s) at impact %s"
              % (len(failing), "/".join(threshold)))
        for v in failing:
            print("  - %s [%s]" % (v["id"], v["impact"]))
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()
