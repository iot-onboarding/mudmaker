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

### Stopping:

```bash
docker compose down
```
