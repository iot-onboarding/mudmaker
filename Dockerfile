FROM golang:1.26-bookworm AS mudcerts-builder

# Pin mudcerts to a specific commit SHA (T-28).  Bump this on every
# mudcerts release with a matching PR here.  A branch name (e.g.
# ``main``) is rejected at build time by the [ -z "$non_hex" ] check
# below so a future accidental "MUDCERTS_REF=main" cannot slip
# through -- the whole point of pinning is that ``go mod verify`` is
# only meaningful if the tree it verifies is itself immutable.
ARG MUDCERTS_REF=46fc87dae8d88b9306d03c507d54910840dc24c2

RUN case "${MUDCERTS_REF}" in \
      [0-9a-f]*) : ;; \
      *) echo "MUDCERTS_REF must be a 40-char commit SHA, got: ${MUDCERTS_REF}" >&2; exit 1 ;; \
    esac \
    && test "$(printf '%s' "${MUDCERTS_REF}" | wc -c)" = "40" \
    && git clone https://github.com/iot-onboarding/mudcerts.git /src/mudcerts \
    && cd /src/mudcerts \
    && git checkout "${MUDCERTS_REF}" \
    && test "$(git rev-parse HEAD)" = "${MUDCERTS_REF}" \
    && go mod download \
    && go mod verify \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mudzipserver ./web

FROM scratch AS mudzipserver

COPY --from=mudcerts-builder /out/mudzipserver /mudzipserver

ENTRYPOINT ["/mudzipserver"]

# ---------------------------------------------------------------------------
# gitmud: builds the Flask OAuth shovel into an isolated virtualenv that the
# runtime stage copies wholesale. Kept in its own builder stage so the final
# image carries only the venv and the runtime files, not pip caches or build
# tooling.
# ---------------------------------------------------------------------------
FROM python:3.14-slim AS gitmud-builder

WORKDIR /build
COPY gitmud/ /build/

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt gunicorn \
    && /opt/venv/bin/pip install --no-cache-dir .

FROM python:3.14-slim AS gitmud

RUN useradd --system --create-home --home-dir /var/lib/gitmud --uid 1001 gitmud \
    && mkdir -p /var/lib/gitmud /etc/gitmud \
    && chown -R gitmud:gitmud /var/lib/gitmud

COPY --from=gitmud-builder /opt/venv /opt/venv
COPY gitmud/initdb.sql /usr/local/share/gitmud/initdb.sql
COPY docker/gitmud-entrypoint.sh /usr/local/bin/gitmud-entrypoint.sh
COPY mudgen_pcap.py /usr/local/bin/mudgen_pcap.py

RUN chmod 0755 /usr/local/bin/gitmud-entrypoint.sh \
    && chmod 0755 /usr/local/bin/mudgen_pcap.py

ENV PATH="/opt/venv/bin:${PATH}" \
    GITMUD_CONFIG=/etc/gitmud/config.ini \
    GITMUD_DB_PATH=/var/lib/gitmud/mudbase.db

EXPOSE 8000
USER gitmud
ENTRYPOINT ["/usr/local/bin/gitmud-entrypoint.sh"]
# --timeout 180: the /therest publish path makes one existence-probe GET
# plus one PUT to GitHub for the MUD JSON and for every attached pcap.
# A 20-pcap upload runs ~40 sequential round-trips; the gunicorn sync
# worker's default 30 s timeout kills the request mid-stream.  Three
# minutes is a comfortable cap that still trips on a hung peer.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "180", "--graceful-timeout", "180", "--access-logfile", "-", "gitmud.app:app"]

FROM httpd:2.4

ENV APACHE_DOCUMENT_ROOT=/mudmaker

RUN sed -ri \
    -e 's!^Listen 80!Listen 8081!' \
    -e 's!^#(LoadModule proxy_module modules/mod_proxy.so)!\1!' \
    -e 's!^#(LoadModule proxy_http_module modules/mod_proxy_http.so)!\1!' \
    -e 's!DocumentRoot "/usr/local/apache2/htdocs"!DocumentRoot "/mudmaker"!' \
    -e 's!<Directory "/usr/local/apache2/htdocs">!<Directory "/mudmaker">!' \
    /usr/local/apache2/conf/httpd.conf && \
    printf '\nServerName localhost\nInclude conf/extra/mudzip-proxy.conf\n' >> /usr/local/apache2/conf/httpd.conf

COPY docker/mudzip-proxy.conf /usr/local/apache2/conf/extra/mudzip-proxy.conf

# Restrict the container's document root to only the files the site actually
# serves: HTML, JavaScript, and CSS, plus the assets they reference (images,
# fonts, the JSON examples linked from examples.html, and the shell scripts
# linked from signing.html / mudurl.html). Everything else in the repo
# (README, LICENSE, Dockerfile, docker-compose.yml, docker/, Python utilities,
# qrcodejs/, etc.) is deliberately excluded so it cannot be requested.
COPY ./*.html /mudmaker/
COPY ./sbom.js /mudmaker/
COPY ./cloud-service.json /mudmaker/
COPY ./my-controller.json /mudmaker/
COPY ./same-manufacturer.json /mudmaker/
COPY ./lldpmud.sh /mudmaker/
COPY ./signmudfile.sh /mudmaker/
COPY ./assets/ /mudmaker/assets/
COPY ./images/ /mudmaker/images/
