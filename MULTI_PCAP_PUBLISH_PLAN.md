# Plan: multi-PCAP upload to GitHub via `/therest`

This plan defines the minimum set of coordinated changes across client, wire
format, and server to make the **Publish** flow upload every pcap the user
selected — today it silently drops everything except the first one.

## Scope & non-goals

- **In scope:** uploading every pcap the user selected in `#pcapfile` to the
  MUD-files GitHub repo when the user clicks **Publish**, preserving each
  file's original filename, on the same branch / PR as the MUD JSON.
- **Out of scope:** changing the `/pcap2mud` path (already correct), changing
  the PR description format, adding a separate "manage attached pcaps" UI, or
  compressing/zipping the bundle.

## Design decisions to lock in first

1. **How to remember which files belong to this publish.**
   - **Decision:** drop the `sessionStorage('pcap')` blob entirely. At publish
     time, read directly from `document.getElementById('pcapfile').files`.
     This avoids the 5 MiB per-origin sessionStorage cap and stale-blob bugs
     when the user re-selects.
   - Add a one-shot warning in the publish handler if
     `#pcapfile.files.length === 0` ("no pcap files attached to publish").
     Allow the user to confirm-and-continue (current behaviour silently
     publishes no pcap).

2. **Wire format.**
   - **Decision:** change `/therest` from JSON to `multipart/form-data`,
     matching `/pcap2mud`. This:
     - Avoids the 33 % base64 inflation that would multiply N pcaps into a
       single oversized JSON body.
     - Lets Flask cap the request via `MAX_CONTENT_LENGTH` (`/pcap2mud`
       already uses 20 MiB; pick the same).
     - Removes the awkward parallel paths between `/pcap2mud` and `/therest`.
   - Field layout:
     - `mudFile` — base64 JSON (kept; reuses existing format on the wire so
       the server doesn't need to re-marshal).
     - `email`, `user` — form fields.
     - `pcap` — repeated multipart field, one per file, using
       `files.getlist("pcap")` server-side. Preserves the browser-supplied
       filename.
   - **Compatibility window:** accept the legacy JSON body for one release;
     if `Content-Type: application/json`, fall back to the single-`pcap`
     path. Remove after one cycle.

3. **GitHub filename layout.**
   - **Decision:** `<mfg>/<model>/<sanitised-original-filename>` for the
     pcaps, and continue placing the MUD JSON at `<mfg>/<model>.json`.
     - Avoids collisions across pcaps in one publish.
     - Keeps the MUD-files repo browsable per device.
     - Sanitiser: lowercase, replace anything outside `[a-z0-9._-]` with `_`,
       collapse runs of `_`, require `.pcap`/`.pcapng` extension (reject
       otherwise — same allow-list as `/pcap2mud`).
   - If the same filename appears twice in one publish (rare but possible
     after user-merging two folders), append `-1`, `-2`, … before the
     extension.

4. **Idempotency & re-publish.**
   - Each `upload_file()` already calls `existing_file()` first to get the
     SHA and supplies it on the PUT, so re-publish is idempotent per-file.
     The new loop must do the same per-pcap.
   - **Decision:** *don't* delete pcaps that exist in the branch but weren't
     in this publish. The user's branch may legitimately have pcaps from
     previous runs. Document this in the UI.

## Implementation steps

### Phase 1 — server (`gitmud/gitmud/app.py`)

1. Add `MAX_CONTENT_LENGTH = 20 * 1024 * 1024` if not already covering
   `/therest` (it currently does, via the app-wide setdefault from the
   `/pcap2mud` change).
2. Add a sanitiser helper `_sanitise_pcap_filename(name) -> str` with the
   rules above and the `.pcap`/`.pcapng` allow-list. Return `None` for
   rejects.
3. Refactor `do_the_rest()`:
   - Detect `request.content_type` — branch on `multipart/form-data` (new)
     vs `application/json` (legacy).
   - For multipart: read `mudFile`, `email`, `user` from `request.form`;
     read pcaps from `request.files.getlist("pcap")`.
   - Validate: at least one of `mudFile`; pcaps individually pass the
     sanitiser; reject early with 400 + structured
     `{error, received_file_fields, received_form_fields}` (mirrors
     `/pcap2mud`).
   - Compute a sanitised-filename list once. Detect intra-request collisions
     and dedupe with the `-N` suffix.
4. Replace the single `if pcap:` block with a loop:
   ```python
   for pcap_upload, target_name in pcaps_with_names:
       upload["filename"] = f"{mfg}/{model}/{target_name}"
       upload["content"]  = base64.b64encode(pcap_upload.read()).decode("ascii")
       resp = upload_file(upload)
       if not resp:
           return f"PCAP upload failed for {target_name}", 502
   ```
   - Status code change: prefer `502` (upstream GitHub failed) instead of the
     current bare-string `"PCAP upload failed."` with no code, which becomes
     `200` by default.
5. Bundle the per-file results into the existing `200` JSON response under a
   `pcaps` array so the client can confirm what landed.

### Phase 2 — client (`assets/js/mudmaker.js` + `assets/js/omud.js`)

1. Delete the `onchange="loadPCAP(this)"` wiring on `#pcapfile` in
   `mudmaker.html`. Keep `loadPCAP` exported for now if other code paths use
   it; otherwise remove it. Stop writing to `sessionStorage('pcap')`.
2. In `omud.js` at the `/gitShovel/therest` call site:
   - Build a `FormData`:
     ```js
     var fd = new FormData();
     fd.append('mudFile', m64);
     fd.append('email', email);
     fd.append('user', user);
     var picker = document.getElementById('pcapfile');
     if (picker && picker.files) {
         for (var i = 0; i < picker.files.length; i++) {
             fd.append('pcap', picker.files[i]);
         }
     }
     return fetch("/gitShovel/therest", { method: "POST", body: fd });
     ```
   - Drop the `Content-type` header (let the browser set the multipart
     boundary).
3. Update the publish status messaging to show pcap count: "Uploading MUD
   JSON and N pcap file(s)…".
4. On success, render the per-pcap status from the new `pcaps` array in the
   response.

### Phase 3 — Apache / reverse proxy

- Confirm `docker/mudzip-proxy.conf` (and the Apache `mudmaker` container)
  doesn't have a smaller body limit than the new `MAX_CONTENT_LENGTH`.
  `LimitRequestBody 0` is current default in httpd; if a `LimitRequestBody`
  is set anywhere it must be at least 20 MiB. Add a `LimitRequestBody`
  directive to the `/gitShovel/therest` proxy block matching the gitmud
  setting, so the failure mode is a clean 413 rather than a half-uploaded
  body.

### Phase 4 — tests & validation

1. Add a smoke test `tests/smoke_publish_multi.py` that:
   - Mocks GitHub (or runs against a test PAT against a sandbox repo) and
     posts 3 small pcaps + a minimal MUD JSON.
   - Asserts: 200 status, `pcaps` array length 3, each entry has a `path`
     and `sha`, the branch contains all three files under
     `<mfg>/<model>/`.
   - Filename-collision case: include two files named `setup.pcap` from
     different subdirs (mocked as different uploads); assert the second
     lands as `setup-1.pcap`.
2. Add a unit test for `_sanitise_pcap_filename` covering: spaces, slashes,
   unicode, double-extension, wrong extension.
3. Run existing `tests/smoke_smartercoffee.py` after the changes to ensure
   `/pcap2mud` was not regressed.
4. Manual Firefox + Chrome run: select 20 EdimaxPlug pcaps, click **Generate
   MUD** (verifies `/pcap2mud` still works), then **Publish** (verifies the
   same `#pcapfile.files` is reused).

### Phase 5 — docs & cleanup

1. Update `DOCKER.md` and the publish help text in `mudmaker.html` to
   mention "all selected pcaps will be uploaded to the PR".
2. Note in `CONTRIBUTING.md` (or wherever the `/therest` contract is
   implied) that the new endpoint is multipart and the JSON body is
   deprecated.
3. After one release, delete the JSON fallback branch from
   `do_the_rest()`.

## Risk register

| Risk | Mitigation |
| --- | --- |
| Single 20 MiB cap too small for 20+ pcaps. | Print the size of the request before sending; if > 18 MiB, warn the user and offer to send a subset. Long-term: chunked uploads, but out of scope. |
| User picks `#pcapfile` files then navigates between tabs and the picker loses focus on reload. | `<input type="file">` keeps `.files` until the element is re-rendered. The publish tab and the upload tab share the same DOM in `mudmaker.html`, so the list persists. Verify with a click-through. |
| GitHub rate-limit on N sequential `PUT contents` calls. | One commit per file is fine for ≤30 files; if rate becomes a problem later, batch via the Tree API. Out of scope for v1. |
| Stale `sessionStorage('pcap')` from earlier sessions still gets uploaded after we stop writing it. | On first load of the publish handler, `sessionStorage.removeItem('pcap')`. |
| Filename collision after sanitisation surprises the user (e.g. `Setup A.pcap` and `Setup_A.pcap` both become `setup_a.pcap`). | Echo back the `pcaps` array with `{original, stored}` so the user sees the rename. |

## Suggested rollout order

1. Server-side multipart support with JSON fallback (Phase 1) — deployable
   independently.
2. Client switch to multipart (Phase 2) once the server accepts it.
3. Apache cap alignment (Phase 3) bundled with Phase 1.
4. Tests (Phase 4) alongside each phase, with the cross-phase smoke test
   gating the merge.
5. JSON-fallback removal — separate PR, one release later.

## Estimated change footprint

- `gitmud/gitmud/app.py`: ~60 lines added, ~10 lines removed in
  `do_the_rest()` plus the new sanitiser helper.
- `assets/js/omud.js`: ~20 lines around the `/therest` `fetch`.
- `assets/js/mudmaker.js`: 6-line deletion (`loadPCAP`).
- `mudmaker.html`: 1-line attribute removal.
- `tests/`: 2 new files, ~150 lines.
- Docs: small edits in 2-3 files.
