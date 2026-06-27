## Docker

### Building:

```bash
docker compose build
```

### Running:

```bash
docker compose up -d
```

The Compose setup publishes Apache/PHP on port `8080` through the `mudmaker`
service. The `mudzipserver` service runs separately on the internal Compose
network with no published ports. Apache proxies same-origin `/mudzip` requests
to `http://mudzipserver:8085`, so the signing endpoint is reachable through
`mudmaker` rather than directly from the host.

The **Sign** action returns a zip file with a generated MUD file, detached CMS
signature, and demonstration certificates/keys. Those keys and certificates are
test material only.

Uploads to `/pcap2mud` (Generate MUD from PCAP) and `/gitShovel/therest`
(Publish) are capped at **20 MiB per request** by both Apache
(`LimitRequestBody`) and Flask (`MAX_CONTENT_LENGTH`); requests larger than
this are rejected with `413 Payload Too Large`.  Multiple pcap files can be
selected in a single Publish request, and each one becomes a separate file in
the resulting pull request under `<mfg>/<model>/<filename>`.

### Stopping:

```bash
docker compose down
```
