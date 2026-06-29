"""Smoke test for the guided tour in mudmaker.html.

Loads ``mudmaker.html`` in headless Chrome and exercises the tour:

  * clears ``localStorage`` so the tour auto-opens on first visit
  * walks every step with the Enter key, asserting the title text
    changes between steps and the dialog stays in the DOM
  * verifies Escape closes the tour
  * re-opens via the Tour button and asserts the dialog is back
  * verifies clicking the backdrop closes the tour
  * verifies that after a dismissal, localStorage records the visit
    so the tour does not auto-open on the next page load

Requires a running mudmaker stack on http://127.0.0.1:8081 (the
default ``docker compose`` setup) and Playwright with the ``chrome``
channel installed.

Run from the repository root::

    python3 tests/test_tour_chrome.py
"""
import os
import sys

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit("playwright not installed; run `pip install playwright`")

BASE_URL = os.environ.get("MUDMAKER_URL", "http://127.0.0.1:8081")
HEADLESS = os.environ.get("MUDMAKER_HEADLESS", "1") not in (
    "0", "false", "no")
CHANNEL = os.environ.get("MUDMAKER_BROWSER_CHANNEL", "chrome")

# Keep in sync with STEPS.length in assets/js/mudmaker-tour.js.
EXPECTED_STEP_COUNT = 10


def _reset_tour_state(page):
    page.evaluate("() => { localStorage.removeItem('mudmaker.tour.seen'); }")


def _start_via_button(page):
    page.click("#tour-start")
    page.wait_for_selector(".mud-tour-popover", state="visible")


def _current_title(page):
    return page.text_content(".mud-tour-title")


def _walk_to_end(page):
    """Press Enter through every step; assert title changes each time."""
    titles = []
    for i in range(EXPECTED_STEP_COUNT):
        expected = "Step %d of %d" % (i + 1, EXPECTED_STEP_COUNT)
        # The popover is built synchronously but its text content is
        # populated inside requestAnimationFrame callbacks.  Wait for
        # the progress span to reflect the expected step before
        # reading the title.
        page.wait_for_function(
            "(expected) => {"
            " const el = document.querySelector('.mud-tour-progress');"
            " return el && el.textContent.trim() === expected;"
            "}",
            arg=expected,
            timeout=5000,
        )
        title = _current_title(page)
        if title in titles:
            sys.exit("FAILED: title repeated at step %d: %r"
                     % (i + 1, title))
        titles.append(title)
        # Focus the popover so Enter is captured by the tour handler.
        page.focus(".mud-tour-popover")
        page.keyboard.press("Enter")
    # After the last Enter the overlay should be gone.
    page.wait_for_selector(".mud-tour-root", state="detached", timeout=5000)
    return titles


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=HEADLESS, channel=CHANNEL)
        try:
            ctx = browser.new_context(viewport={"width": 1400,
                                                "height": 900})
            page = ctx.new_page()
            page.goto(BASE_URL + "/mudmaker.html", wait_until="load")
            _reset_tour_state(page)
            page.reload(wait_until="load")

            # Auto-open should fire on first visit (no storage flag).
            page.wait_for_selector(".mud-tour-popover", state="visible",
                                   timeout=5000)
            print("  auto-open: ok")

            # Escape closes the tour.
            page.focus(".mud-tour-popover")
            page.keyboard.press("Escape")
            page.wait_for_selector(".mud-tour-root", state="detached",
                                   timeout=5000)
            print("  Escape closes: ok")

            # localStorage flag was written.
            seen = page.evaluate(
                "() => localStorage.getItem('mudmaker.tour.seen')")
            if seen != "1":
                sys.exit("FAILED: localStorage flag not set after stop")
            print("  storage flag set on dismissal: ok")

            # Tour button re-opens it.
            _start_via_button(page)
            print("  Tour button re-opens: ok")

            # Click backdrop closes it (click far from the popover).
            page.mouse.click(20, 20)
            page.wait_for_selector(".mud-tour-root", state="detached",
                                   timeout=5000)
            print("  backdrop click closes: ok")

            # Walk every step.
            _start_via_button(page)
            titles = _walk_to_end(page)
            print("  walked %d steps, titles all distinct: ok"
                  % len(titles))

            # Reload: tour should NOT auto-open now (flag is set).
            page.reload(wait_until="load")
            # Give the page time; tour is started via setTimeout(250).
            page.wait_for_timeout(500)
            popovers = page.query_selector_all(".mud-tour-popover")
            if popovers:
                sys.exit("FAILED: tour auto-opened on second visit")
            print("  no auto-open on subsequent visit: ok")
        finally:
            browser.close()

    print("OK")


if __name__ == "__main__":
    main()
