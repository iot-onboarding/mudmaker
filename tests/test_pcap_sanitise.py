"""Unit tests for the pcap-filename sanitiser used by /therest.

Run from the repository root:
    python3 tests/test_pcap_sanitise.py
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "gitmud" / "gitmud"))

import app  # noqa: E402  (sys.path fiddling above)


def _check(actual, expected, label):
    if actual != expected:
        print(f"FAIL {label}: got {actual!r}, expected {expected!r}")
        sys.exit(1)
    print(f"  ok   {label}")


def test_sanitiser():
    s = app._sanitise_pcap_filename
    print("sanitiser:")
    _check(s("Setup-A-1-STA.pcap"), "setup-a-1-sta.pcap",
           "preserves hyphens, lowercases")
    _check(s("foo bar.pcap"), "foo_bar.pcap", "spaces -> underscore")
    _check(s("/tmp/foo.pcap"), "foo.pcap", "strips path components")
    _check(s("..\\evil.pcap"), "evil.pcap", "strips windows path + dots")
    _check(s("ünicode.pcap"), "nicode.pcap", "drops bare unicode chars")
    _check(s("multi   spaces.pcap"), "multi_spaces.pcap", "collapses runs")
    _check(s("dots..in..name.pcap"), "dots..in..name.pcap",
           "double-dots in stem are preserved")
    _check(s("CAPS.PCAPNG"), "caps.pcapng", "uppercase extension accepted")
    _check(s("Capture.pcapng"), "capture.pcapng", "pcapng extension works")
    _check(s("notapcap.txt"), None, "wrong extension rejected")
    _check(s("nostem.pcap"), "nostem.pcap", "ok stem")
    _check(s("___.pcap"), None, "stem of only underscores rejected")
    _check(s(""), None, "empty rejected")
    _check(s(None), None, "None rejected")


def test_dedupe():
    d = app._dedupe_target_names
    print("dedupe:")
    _check(d(["a.pcap", "b.pcap"]), ["a.pcap", "b.pcap"], "no collisions")
    _check(d(["a.pcap", "a.pcap"]), ["a.pcap", "a-1.pcap"], "one collision")
    _check(d(["a.pcap", "a.pcap", "a.pcap"]),
           ["a.pcap", "a-1.pcap", "a-2.pcap"], "three same names")
    _check(d(["a.pcap", "a-1.pcap", "a.pcap"]),
           ["a.pcap", "a-1.pcap", "a-2.pcap"],
           "user-supplied collision with bumped name")


if __name__ == "__main__":
    test_sanitiser()
    test_dedupe()
    print("OK")
