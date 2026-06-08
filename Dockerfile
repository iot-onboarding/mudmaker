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

FROM php:7.3-apache

ENV APACHE_DOCUMENT_ROOT=/mudmaker

RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf && \
    sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf && \
    sed -ri -e 's!80!8080!g' /etc/apache2/sites-available/000-default.conf && \
    sed -ri -e 's!80!8080!g' /etc/apache2/ports.conf && \
    a2enmod proxy proxy_http

COPY docker/mudzip-proxy.conf /etc/apache2/conf-available/mudzip-proxy.conf
RUN a2enconf mudzip-proxy

COPY . /mudmaker/

ENTRYPOINT ["docker-php-entrypoint"]
CMD ["apache2-foreground"]
