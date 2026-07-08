"""Tests for the Phase-1 GitHub ref/path sanitiser.

`_sanitise_ref_component` is the single choke point that stops
attacker-supplied `mfg` / `model` / filename segments from becoming
GitHub REST paths or Git ref names with traversal characters.  Every
combination the threat model called out (T-07, T-08, T-10) is pinned
here so future refactors cannot silently loosen the rules.

Run from the repository root:
    python3 tests/test_ref_sanitise.py
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "gitmud" / "gitmud"))

import app  # noqa: E402


def _accepts(value, expected):
    got = app._sanitise_ref_component(value, "field")
    assert got == expected, f"{value!r} -> {got!r}, expected {expected!r}"


def _rejects(value, reason):
    try:
        got = app._sanitise_ref_component(value, "field")
    except ValueError:
        return
    raise AssertionError(
        f"{value!r} was accepted as {got!r}; expected rejection ({reason})")


def main():
    # -- accepted ----------------------------------------------------
    _accepts("acme", "acme")
    _accepts("Acme Devices", "acme-devices")
    _accepts("Acme  Thermostat", "acme-thermostat")   # collapsed ws
    _accepts("model-42", "model-42")
    _accepts("model_42", "model_42")
    _accepts("v1.2.3", "v1.2.3")
    print("ok accepted: canonical inputs pass through")

    # -- rejected: non-ASCII letters ---------------------------------
    # NFKC normalisation does NOT decompose ``é`` into e+U+0301 so a
    # naked ``é`` remains outside [a-z0-9._-] and is rejected.  This
    # is the intended behaviour: silently transliterating a Unicode
    # string is lossy and locale-dependent, so we prefer a hard
    # rejection with a clear error to the caller.
    _rejects("acmé", "non-ASCII accented letter")
    _rejects("Ω", "non-ASCII greek letter")
    print("ok rejected: non-ASCII letters")

    # -- rejected: path traversal / GitHub URL structural chars ------
    _rejects("../evil", "..")
    _rejects("evil/../thing", "traversal")
    _rejects("acme/widget", "slash inside segment")
    _rejects("acme//widget", "double slash")
    _rejects("thing?ref=main", "query separator")
    _rejects("thing#frag", "fragment")
    _rejects("thing:model", "colon")
    _rejects("thing*star", "glob")
    _rejects("thing[bracket]", "bracket")
    _rejects("thing~tilde", "tilde")
    _rejects("thing^caret", "caret")
    _rejects("thing\\back", "backslash")
    _rejects("thing@{ref}", "reflog syntax")
    print("ok rejected: git-ref-forbidden and URL structural chars")

    # -- rejected: control chars / whitespace edge cases -------------
    _rejects("thing\x00null", "NUL")
    _rejects("thing\nnewline", "newline (log forgery vector)")
    _rejects("thing\x1bescape", "ESC (terminal escape)")
    _rejects("thing\x7fdel", "DEL")
    _rejects("acme\u202egoat", "RTL override (homoglyph attack)")
    print("ok rejected: control chars and Unicode oddities")

    # -- rejected: shape rules (leading/trailing, empty, too long) ---
    _rejects("", "empty")
    _rejects("   ", "whitespace-only")
    _rejects(None, "None")
    _rejects("-leading-dash", "leading dash")
    _rejects(".leading-dot", "leading dot")
    _rejects("trailing.", "trailing dot")
    _rejects("a" * 65, "too long (>64 chars)")
    print("ok rejected: shape rules (bounds, edges, empty)")

    # -- _github_path composes segments safely -----------------------
    p = app._github_path("repos", "alice", "mudfiles",
                         "contents", "acme/model.json")
    assert p == "/repos/alice/mudfiles/contents/acme%2Fmodel.json", p
    p = app._github_path("repos", "alice?query", "x")
    assert p == "/repos/alice%3Fquery/x", p
    print("ok _github_path url-quotes each segment")

    # -- _safe_log strips CR/LF/ctrl and repr-quotes -----------------
    scrubbed = app._safe_log("hi\r\nInjected: yes")
    assert scrubbed == "'hiInjected: yes'", scrubbed
    scrubbed = app._safe_log(None)
    assert scrubbed == "", scrubbed
    scrubbed = app._safe_log("x" * 300)
    # 200-char truncation + surrounding quotes = 202
    assert len(scrubbed) == 202, len(scrubbed)
    print("ok _safe_log scrubs CR/LF and truncates")

    print("OK")


if __name__ == "__main__":
    main()
