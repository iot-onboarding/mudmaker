# Generating a MUD file from PCAPs over HTTP

The MudMaker web app exposes the "Generate MUD from PCAP" feature as a
plain HTTP endpoint, `POST /pcap2mud`, so you can drive it from `curl`,
CI pipelines, or any HTTP client without going through the browser UI.

Under the hood the endpoint uploads your `.pcap`/`.pcapng` files into a
temporary directory on the server and runs [`mudgen_pcap.py`](mudgen_pcap.py)
against them. The response is JSON containing the resulting MUD file
plus any human-readable notes emitted by the generator.

## Endpoint

| | |
|---|---|
| URL         | `https://mudmaker.org/pcap2mud` (production) |
| Local Docker| `http://127.0.0.1:8081/pcap2mud` |
| Method      | `POST` |
| Body        | `multipart/form-data` |
| Max size    | **20 MiB** total request body (enforced by both Apache `LimitRequestBody` and Flask `MAX_CONTENT_LENGTH`) |
| Timeout     | `mudgen_pcap.py` is killed after **60 s** |
| Auth        | None |

Requests over the size cap are rejected with `413 Payload Too Large`;
requests that exceed the generator timeout return `504` with a JSON
error body.

## Form fields

Exactly one field is required: at least one file part named `pcap`.

| Field           | Type   | Required | Notes |
|-----------------|--------|----------|-------|
| `pcap`          | file   | yes      | Repeat the field once per capture. Filename must end in `.pcap` or `.pcapng`. |
| `mac`           | text   | no       | Ethernet MAC of the device under test, colon-separated hex (e.g. `aa:bb:cc:dd:ee:ff`). If omitted, `mudgen_pcap.py` infers a MAC from the captures. |
| `mfg`           | text   | no       | Manufacturer name; passed to `mudgen_pcap.py --mfg`. |
| `model`         | text   | no       | Model name; passed to `--model`. |
| `systeminfo`    | text   | no       | Free-form description; passed to `--systeminfo`. |
| `documentation` | text   | no       | Documentation URL (`http://` or `https://`); passed to `--documentation`. |
| `mud_url`       | text   | no       | Absolute `https://` URL that will be recorded as the MUD URL; passed to `--mud-url`. |

Text fields are validated on the server:

* `mfg`, `model`, `systeminfo` may contain only
  `A-Z a-z 0-9 . _ , ( ) - <space>` and must be `<= 128` characters.
* `documentation` and `mud_url` must parse as `http(s)://` URLs and be
  `<= 512` characters.
* `mac` must match `^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$`.

Values that fail validation return `400` with an `{"error": "..."}`
body; nothing is executed.

## Success response

`HTTP 200 application/json`:

```json
{
  "mud": {
    "ietf-mud:mud": { "...": "..." },
    "ietf-access-control-list:acls": { "acl": [ /* ... */ ] }
  },
  "notes": "optional human-readable diagnostics from mudgen_pcap.py"
}
```

`mud` is the RFC 8520 MUD file exactly as `mudgen_pcap.py` would have
written to stdout. `notes`, when present, contains the generator's
stderr (for example, "inferred device MAC: ...") stripped of empty
lines.

## Error responses

All errors are JSON of the form `{"error": "message", ...}`.

| Status | Meaning |
|--------|---------|
| `400`  | No `pcap` field, non-pcap filename, invalid `mac`, or invalid text/URL field. When no files were seen the body also echoes `received_file_fields`, `received_form_fields`, `content_length`, and `content_type` to help diagnose lost uploads. |
| `400`  | `mudgen_pcap.py` exited non-zero. `error` contains the concatenated stderr (empty lines and the informational `inferred device MAC:` line filtered out). |
| `413`  | Request body exceeded 20 MiB. |
| `500`  | The server could not locate `mudgen_pcap.py`, or the generator produced non-JSON on stdout. |
| `504`  | `mudgen_pcap.py` did not finish within 60 s. |

## curl example

Single capture, no metadata:

```bash
curl -sS -X POST https://mudmaker.org/pcap2mud \
     -F "pcap=@device.pcap;type=application/vnd.tcpdump.pcap" \
     -o mud.json
```

Multiple captures with full metadata:

```bash
curl -sS -X POST https://mudmaker.org/pcap2mud \
     -F "mac=aa:bb:cc:dd:ee:ff" \
     -F "mfg=Smarter" \
     -F "model=SmarterCoffee" \
     -F "systeminfo=SmarterCoffee kitchen appliance" \
     -F "documentation=https://example.com/docs/smartercoffee" \
     -F "mud_url=https://example.com/.well-known/mud/smartercoffee" \
     -F "pcap=@boot.pcap;type=application/vnd.tcpdump.pcap" \
     -F "pcap=@brew.pcap;type=application/vnd.tcpdump.pcap" \
     -F "pcap=@idle.pcapng;type=application/vnd.tcpdump.pcap" \
     -o mud.json
```

Extract just the MUD file (drop the wrapper and `notes`):

```bash
curl -sS -X POST https://mudmaker.org/pcap2mud \
     -F "pcap=@device.pcap" \
   | jq .mud > device-mud.json
```

Fail loudly on HTTP errors and print the server's JSON error:

```bash
curl -fsS -X POST https://mudmaker.org/pcap2mud \
     -F "pcap=@device.pcap" \
     -o mud.json \
  || curl -sS -X POST https://mudmaker.org/pcap2mud \
          -F "pcap=@device.pcap" | jq .
```

## Python example

```python
import json
import requests

files = [
    ("pcap", ("boot.pcap", open("boot.pcap", "rb"),
              "application/vnd.tcpdump.pcap")),
    ("pcap", ("brew.pcap", open("brew.pcap", "rb"),
              "application/vnd.tcpdump.pcap")),
]
data = {
    "mac":   "aa:bb:cc:dd:ee:ff",
    "mfg":   "Smarter",
    "model": "SmarterCoffee",
}

resp = requests.post("https://mudmaker.org/pcap2mud",
                     files=files, data=data, timeout=90)
resp.raise_for_status()
payload = resp.json()

with open("device-mud.json", "w") as fh:
    json.dump(payload["mud"], fh, indent=2)

if payload.get("notes"):
    print(payload["notes"])
```

A ready-to-run reference client that uploads every pcap under a single
directory in one request lives at
[tests/smoke_smartercoffee.py](tests/smoke_smartercoffee.py); it uses
only the Python standard library and is a good starting point for
scripting your own uploads.

## Running the endpoint locally

The endpoint ships in the standard Docker Compose stack (see
[DOCKER.md](DOCKER.md)):

```bash
docker compose up -d
curl -sS -X POST http://127.0.0.1:8081/pcap2mud \
     -F "pcap=@device.pcap" | jq .
```

The mudmaker container's Apache proxies `/pcap2mud` to the `gitmud`
Flask app on the internal Compose network; there is no need to expose
`gitmud` directly.

## Notes and limits

* The endpoint is stateless: uploaded pcaps live in a temporary
  directory that is deleted before the response returns. Nothing is
  published to GitHub or stored on disk. To publish the resulting MUD
  file, use the separate `/gitShovel/therest` flow.
* `mudgen_pcap.py` requires that all captures in a request describe the
  **same** device (identified by MAC). Mixing captures from different
  devices will produce a MUD file for whichever MAC is inferred (or
  supplied via `mac=`).
* Only RFC 8519/8520 constructs are emitted; no reverse-PTR lookups are
  performed. See the module docstring in
  [mudgen_pcap.py](mudgen_pcap.py) for the full classification rules.
