"""End-to-end signing smoke test driven through Google Chrome.

Drives the mudmaker UI in a real Chrome instance via Playwright:
  * fill the mandatory form fields
  * switch to the Publish tab and click "Sign"
  * capture the resulting zip download
  * extract it and verify the CMS signature with openssl

Requires a running mudmaker stack on http://127.0.0.1:8081 and the
``playwright`` Python package.  Set ``MUDMAKER_HEADLESS=0`` to watch the
browser locally.

Run from the repository root::

    python3 tests/test_signing_chrome.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit("playwright not installed; run `pip install playwright`")

BASE_URL = os.environ.get("MUDMAKER_URL", "http://127.0.0.1:8081")
HEADLESS = os.environ.get("MUDMAKER_HEADLESS", "1") not in ("0", "false", "no")
CHANNEL = os.environ.get("MUDMAKER_BROWSER_CHANNEL", "chrome")

MODEL = "SmokeWidget"
INPUTS = {
    "mudhost": "example.com",
    "model_name": MODEL,
    "mfg-name": "Acme Inc",
    "systeminfo": "Smoke test device",
    "documentation": "https://example.com/docs",
    "email_addr": "smoke@example.com",
}


def _drive_browser(workdir: Path) -> Path:
    zip_path = workdir / f"{MODEL}.zip"
    with sync_playwright() as p:
        launch_kwargs = {"headless": HEADLESS}
        if CHANNEL:
            launch_kwargs["channel"] = CHANNEL
        browser = p.chromium.launch(**launch_kwargs)
        try:
            ctx = browser.new_context(accept_downloads=True)
            page = ctx.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
            page.goto(f"{BASE_URL}/mudmaker.html", wait_until="load")
            for fid, val in INPUTS.items():
                page.fill(f"#{fid}", val)
            page.select_option("#country", label="United States")
            page.evaluate(
                """() => {
                    ['mudhost','model_name','mfg-name','systeminfo',
                     'documentation','email_addr','country'].forEach(id => {
                        const el = document.getElementById(id);
                        if (el) el.dispatchEvent(new Event('change',{bubbles:true}));
                    });
                }"""
            )
            mud_url = page.evaluate(
                "() => document.mudFile && document.mudFile['ietf-mud:mud']"
                " && document.mudFile['ietf-mud:mud']['mud-url']"
            )
            if not mud_url:
                raise RuntimeError(
                    "mud-url did not populate; form likely failed to fire change "
                    f"handlers. Errors: {errors}"
                )
            print(f"  mud-url populated: {mud_url}")
            page.get_by_role("button", name="Sign/Publish").click()
            with page.expect_download(timeout=30_000) as dl_info:
                page.locator('button[name="Sign"]').click()
            dl_info.value.save_as(str(zip_path))
        finally:
            browser.close()
    if not zip_path.exists():
        sys.exit("no zip captured from Sign click")
    print(f"  downloaded: {zip_path} ({zip_path.stat().st_size} bytes)")
    return zip_path


def _verify_zip(zip_path: Path, workdir: Path) -> None:
    extract = workdir / "extracted"
    extract.mkdir()
    subprocess.run(
        ["unzip", "-q", "-o", str(zip_path), "-d", str(extract)],
        check=True,
    )
    required = [
        f"{MODEL}.json",
        f"{MODEL}.p7s",
        "ca.pem",
        "mudsigner.pem",
        "README.txt",
    ]
    missing = [n for n in required if not (extract / n).exists()]
    if missing:
        sys.exit(f"zip missing files: {missing}; got {sorted(p.name for p in extract.iterdir())}")
    print(f"  zip contents OK ({len(list(extract.iterdir()))} files)")

    # CMS detached signature, exactly as signing.html documents.
    subprocess.run(
        [
            "openssl", "cms", "-verify",
            "-in", str(extract / f"{MODEL}.p7s"),
            "-inform", "DER",
            "-content", str(extract / f"{MODEL}.json"),
            "-CAfile", str(extract / "ca.pem"),
            "-purpose", "any",
            "-binary",
            "-out", "/dev/null",
        ],
        check=True,
    )
    print("  CMS signature verifies against bundled CA")

    # Sanity-check the bundled device cert chain.
    result = subprocess.run(
        ["openssl", "verify", "-CAfile", str(extract / "ca.pem"),
         str(extract / "mudcert.pem"), str(extract / "mudsigner.pem")],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        sys.exit(f"openssl verify failed: {result.stdout}{result.stderr}")
    print(f"  cert chain OK: {result.stdout.strip()}")


def main() -> None:
    if not shutil.which("openssl"):
        sys.exit("openssl not installed; required for signature verification")
    workdir = Path(tempfile.mkdtemp(prefix="mudmaker-sign-"))
    try:
        print(f"workdir: {workdir}")
        zip_path = _drive_browser(workdir)
        _verify_zip(zip_path, workdir)
        # Copy artifacts somewhere CI can pick them up on failure.
        keep = Path(os.environ.get("MUDMAKER_ARTIFACT_DIR", workdir))
        if keep != workdir:
            keep.mkdir(parents=True, exist_ok=True)
            shutil.copy2(zip_path, keep / zip_path.name)
        print("OK")
    except Exception:
        print(f"FAILED — artifacts in {workdir}")
        raise


if __name__ == "__main__":
    main()
