## Docker

### Building:

```bash
docker build -t mudmaker .
```

### Running:

```bash
docker run -p 8080:8080 mudmaker
```

The image runs Apache/PHP on port `8080` and starts `mudzipserver` inside the
same container on `127.0.0.1:8085`. Apache proxies same-origin `/mudzip`
requests to that internal service, so only port `8080` should be published.

The **Sign** action returns a zip file with a generated MUD file, detached CMS
signature, and demonstration certificates/keys. Those keys and certificates are
test material only.
