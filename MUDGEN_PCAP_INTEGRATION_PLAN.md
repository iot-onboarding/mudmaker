# mudgen_pcap Integration & RFC 8519 Editor Plan

## Goal

1. Wire `mudgen_pcap.py` into the MudMaker web UI so a user can upload one
   or more pcap files, generate an RFC 8520 MUD file on the server, and
   visualize the result without leaving the browser.
2. Extend the MudMaker form so MUD files that contain RFC 8519 raw IP /
   prefix matches (`source-ipv4-network`, `destination-ipv4-network`,
   and the IPv6 equivalents) can be created and round-tripped through
   the editor, not just rendered by the visualizer.

## Findings: existing PCAP plumbing

| Component | What it actually does |
|---|---|
| [mudmaker.html](mudmaker.html) (lines 86-88) | A file input labeled "Upload PCAP" wired to `onchange="loadPCAP(this)"`. Sits inside the **Publish** tab. |
| `loadPCAP()` in [assets/js/mudmaker.js](assets/js/mudmaker.js) (lines 702-713) | Reads the file as a base64 data URL, strips the `data:` prefix, and stashes it in `sessionStorage.pcap`. No parsing — purely an opaque blob. |
| `do_the_rest()` in [gitmud/gitmud/app.py](gitmud/gitmud/app.py) (lines 447-489) | Picks up the `pcap` field from the JSON body and attaches it to the GitHub PR for the reviewer. |
| Visualizer ([assets/js/mudmaker-visualizer.js](assets/js/mudmaker-visualizer.js) lines 997-1021) | `MudMakerVisualizer.loadSavedWork(input)` takes any MUD JSON file and re-renders. The natural seam for visualizing an externally-generated MUD file. |
| Visualizer endpoints ([assets/js/mudmaker-visualizer.js](assets/js/mudmaker-visualizer.js) lines 228-240 and 524-535) | Already recognises `ietf-acldns:src-dnsname` / `dst-dnsname`, `source-ipv4-network` / `destination-ipv4-network`, the IPv6 equivalents, and all RFC 8520 abstractions. Raw RFC 8519 prefixes render, but as a generic `internet-host` with no distinct icon. |
| Form UI (`addEntry()` in [assets/js/mudmaker.js](assets/js/mudmaker.js) lines 321-360) | Form only supports `dns`-style (`cl` / `mfg`) or `url`-style (`ctl`) endpoint inputs; no path for a raw IP / prefix. `reloadFields()` (lines 660-696) only knows how to round-trip `ietf-acldns:*-dnsname` ACEs, so a MUD file with `*-ipv4-network` matches visualizes but does not populate the Create-tab editor. |

## Part A — integrate `mudgen_pcap.py` so its output is visualizable

The script already produces a clean RFC 8520 MUD file. The shortest path
to visualization is to route it through the existing `loadSavedWork`
seam.

### A1. Backend endpoint (gitmud)

Add a new Flask route `POST /pcap2mud` that:

- Accepts `multipart/form-data` with one or more `pcap` files and
  optional fields: `mac`, `mfg`, `model`, `systeminfo`,
  `documentation`, `no_dns`.
- Saves the uploads to a per-request tempdir, writes
  `_iotdevice-mac.txt` if `mac` was supplied, then invokes
  `mudgen_pcap.py` either as a subprocess or by importing it (its
  `main(argv)` is already a clean entry point).
- Returns the resulting JSON, or a structured error such as
  `{"error": "could not infer device MAC: …"}`.
- Hardening: `Flask MAX_CONTENT_LENGTH` upload cap, allowed extensions
  (`.pcap`, `.pcapng`), tempdir cleanup, `subprocess.run(..., timeout=…)`,
  runs as the existing non-privileged `gitmud` user.
- Docker plumbing: add `scapy` to [gitmud/requirements.txt](gitmud/requirements.txt) (one line), and
  add a reverse-proxy rule to [docker/mudzip-proxy.conf](docker/mudzip-proxy.conf) so `/pcap2mud`
  reaches `gitmud:8000` — identical pattern to the existing `/mudzip`
  proxy.

### A2. Front-end

Promote the existing "Upload PCAP" control from a passive blob-stuffer
into an active generator:

- Add a button next to the upload input on the Publish tab labelled
  **"Generate MUD from PCAP"**. The existing behaviour (store base64
  in `sessionStorage` for the PR) stays intact.
- New function `generateMudFromPcap()` in
  [assets/js/mudmaker.js](assets/js/mudmaker.js) builds a `FormData`, POSTs to `/pcap2mud`, and on
  success calls `MudMakerVisualizer.initializeLoadedMudFile(mud)` (the
  same code path `loadSavedWork` already uses), then
  `openTab(.., 'viewmudfile')`.
- Failure cases (e.g.
  `could not infer device MAC: multiple MACs appear in every frame …`)
  are surfaced through a new inline `<div id="pcap-result">` area, and
  via `alert(...)` for hard errors, so the user sees the exact
  diagnostic the generator produced.
- The visualizer renders the resulting MUD without changes. The Create
  tab will show empty ACE entries for `*-network` matches until Part B
  lands, which is acceptable interim behaviour.

Minimal HTML diff in `mudmaker.html`:

```html
<tr>
  <td>
    <label for="pcapfile">Upload PCAP(s)</label>
    <input id="pcapfile" type="file" multiple
           accept=".pcap,.pcapng,application/vnd.tcpdump.pcap"
           onchange="loadPCAP(this)">
    <button type="button" onclick="generateMudFromPcap()">
      Generate MUD from PCAP
    </button>
    <input id="pcapmac" placeholder="optional MAC (aa:bb:cc:dd:ee:ff)">
    <div id="pcap-result" class="maker-live-detail-meta"></div>
  </td>
  <td>…existing copy…</td>
</tr>
```

## Part B — extend MudMaker to support RFC 8519 prefix matches

Today the visualizer renders prefixes but the Create-tab editor only
round-trips DNS-name ACEs and abstractions. To accept
`mudgen_pcap.py`'s no-PTR fallback output, the form needs first-class
IP-prefix entries.

### B1. New entry type

In `addEntry()` ([assets/js/mudmaker.js](assets/js/mudmaker.js) lines 321-360):

- Add `'net'` to the `fieldName` map. Like the existing `'cl'` entry
  (which uses one DNS-name value to emit `dst-dnsname` in the
  from-device ACL and `src-dnsname` in the to-device ACL), a single
  `net` entry round-trips a prefix in **both** directions:
  `destination-ipv4-network` / `destination-ipv6-network` in the
  from-device ACL and the matching `source-ipv4-network` /
  `source-ipv6-network` in the to-device ACL.  This mirrors what
  `mudgen_pcap.py` already emits in `build_ace()`.
- Add a `dnsorurl` value of `prefix` that uses `typefield="'text'"`,
  pattern
  `"^([0-9]{1,3}\.){3}[0-9]{1,3}/(3[0-2]|[12]?[0-9])$|^[0-9a-fA-F:]+/(12[0-8]|[1-9]?[0-9])$"`,
  placeholder `"203.0.113.7/32 or 2001:db8::/64"`.
- Auto-derive `ipv4` / `ipv6` ACL type from whether the entered prefix
  parses as IPv4 or IPv6 (small `isV6(s)` helper).

### B2. New ACE-builder block

Add a new `<details id="net">` block in `mudmaker.html`'s ACE-builder
section, mirroring the existing `cl` / `myctl` / `loc` / `mymfg`
blocks, with a heading like "Host or network address (RFC 8519)".

### B3. `reloadFields()` round-trip

In [assets/js/mudmaker.js](assets/js/mudmaker.js) lines 660-696, extend the `else` branch so when
an ACE has `source-ipv4-network` / `destination-ipv4-network` /
`source-ipv6-network` / `destination-ipv6-network` (and no
`ietf-acldns:*-dnsname`, no `ietf-mud:mud`) it calls
`findNextAce('net')` and populates the prefix value. Existing
`setProto()` already handles the L4 part untouched.

### B4. Serialization

When an entry's id is `net`, ensure the existing save pipeline writes
the field name returned by the `fieldName` map into the matches
object. Confirm by walking the save path or extend `saveMUD()` /
equivalent.

### B5. Visualizer polish

In `endpointFromDns()` ([assets/js/mudmaker-visualizer.js](assets/js/mudmaker-visualizer.js) lines 223-246),
when the chosen `name` came from a `*-network` key, label the node as
the prefix and give it a distinct `kind: "ipnet"`. Add a corresponding
case in `iconKind()` so the node renders with a different icon (reuse
the `cloud` icon for public, `enterprise` for private, decided by a
small in-JS prefix-inspection helper).

## Sequencing & risk

| Step | Risk | Mitigation |
|---|---|---|
| Bundle scapy in the `gitmud` container | Image size grows ~8 MB | Already a Python venv; one-line `requirements.txt` change. |
| Subprocess timeout on large pcaps | DoS surface | Cap upload size via Flask `MAX_CONTENT_LENGTH`; `subprocess.run(..., timeout=…)`. |
| Reverse DNS during request | Latency, leaks the user's resolver to public IPs | Default the front-end button to send `no_dns=1`; offer an explicit "resolve PTR records" checkbox. |
| Form / serializer changes for prefixes | Risk of breaking existing DNS / abstraction round-trip | Smoke tests using the existing example JSON files ([cloud-service.json](cloud-service.json), [my-controller.json](my-controller.json), [same-manufacturer.json](same-manufacturer.json)) plus a new pcap-derived sample. |

## Net outcome

After **Part A**, a user can pick one or more pcaps in the browser,
click **Generate MUD from PCAP**, and see the resulting policy rendered
in the visualizer immediately — with any diagnostics from
`mudgen_pcap.py` (including the "ambiguous MAC" error) surfaced in the
UI rather than failing silently.

After **Part B**, those generated files round-trip cleanly through the
editor even when they fall back to RFC 8519 prefix matches, so the user
can fine-tune the policy before publishing.
