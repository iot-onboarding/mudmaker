FROM golang:1.24-bookworm AS mudcerts-builder

ARG MUDCERTS_REF=main

RUN git clone https://github.com/iot-onboarding/mudcerts.git /src/mudcerts && \
    cd /src/mudcerts && \
    git checkout "${MUDCERTS_REF}" && \
    go mod download && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mudzipserver ./web

FROM scratch AS mudzipserver

COPY --from=mudcerts-builder /out/mudzipserver /mudzipserver

ENTRYPOINT ["/mudzipserver"]

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

COPY . /mudmaker/
