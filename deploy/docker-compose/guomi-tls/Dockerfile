# syntax=docker/dockerfile:1
# W10 optional GM/T TLCP (national cryptography TLS) entry: Tengine 3.1.0 with the
# bundled ngx_tongsuo_ntls module, statically linked against Tongsuo 8.4.0.
#
# Offline build: both source tarballs are supplied as a local build context
# (release-guomi-src) and checked against the SHA-256 values below; no
# network access is needed once the base images are present.
#   docker buildx build --network=none \
#     --build-context release-guomi-src=/path/to/dir-with-tarballs \
#     --build-context release-alpine-builder=docker-image://<local alpine+toolchain image> \
#     -f deploy/docker-compose/guomi-tls/Dockerfile deploy/docker-compose/guomi-tls
ARG BUILDER_IMAGE=docker.1ms.run/library/alpine:3.20
ARG RUNTIME_IMAGE=docker.1ms.run/library/alpine:3.20

FROM ${BUILDER_IMAGE} AS build
ARG TONGSUO_VERSION=8.4.0
ARG TONGSUO_SHA256=57c2741750a699bfbdaa1bbe44a5733e9c8fc65d086c210151cfbc2bbd6fc975
ARG TENGINE_VERSION=3.1.0
ARG TENGINE_SHA256=64ed7155c0c904ce0fe7199c21b8eb6c2abfc267278fa8af832c0cb781e864dc
WORKDIR /src
COPY --from=release-guomi-src tongsuo-${TONGSUO_VERSION}.tar.gz tengine-${TENGINE_VERSION}.tar.gz ./
RUN printf '%s  %s\n%s  %s\n' \
      "$TONGSUO_SHA256" "tongsuo-${TONGSUO_VERSION}.tar.gz" \
      "$TENGINE_SHA256" "tengine-${TENGINE_VERSION}.tar.gz" | sha256sum -c - \
 && tar xzf tongsuo-${TONGSUO_VERSION}.tar.gz && tar xzf tengine-${TENGINE_VERSION}.tar.gz
# Toolchain packages must already be in the builder image (see README); this
# image never runs apk.
WORKDIR /src/tengine-${TENGINE_VERSION}
RUN ./configure \
      --prefix=/opt/guomi-tls \
      --add-module=modules/ngx_tongsuo_ntls \
      --with-openssl=/src/Tongsuo-${TONGSUO_VERSION} \
      --with-openssl-opt="enable-ntls no-shared" \
      --with-http_ssl_module --with-http_v2_module --with-http_realip_module \
      --with-stream --with-stream_ssl_module --with-stream_sni \
      --without-http_rewrite_module --without-http_gzip_module \
 && make -j"$(nproc)" && make install \
 && /opt/guomi-tls/sbin/nginx -V 2>&1 | grep -q 'ngx_tongsuo_ntls' \
 && cp /src/Tongsuo-${TONGSUO_VERSION}/apps/openssl /opt/guomi-tls/sbin/tongsuo \
 && cp /src/Tongsuo-${TONGSUO_VERSION}/apps/openssl.cnf /opt/guomi-tls/conf/tongsuo.cnf \
 && mkdir -p /opt/guomi-tls/licenses \
 && cp /src/Tongsuo-${TONGSUO_VERSION}/LICENSE.txt /opt/guomi-tls/licenses/Tongsuo-LICENSE.txt \
 && cp /src/tengine-${TENGINE_VERSION}/LICENSE /opt/guomi-tls/licenses/Tengine-LICENSE

FROM ${RUNTIME_IMAGE}
ENV OPENSSL_CONF=/opt/guomi-tls/conf/tongsuo.cnf
COPY --from=build /opt/guomi-tls /opt/guomi-tls
COPY --chmod=0755 entrypoint.sh /usr/local/bin/guomi-tls-entrypoint
COPY nginx.conf.template /etc/guomi-tls/nginx.conf.template
RUN addgroup -S guomi && adduser -S -G guomi guomi \
 && mkdir -p /var/cache/guomi-tls /var/run/guomi-tls /opt/guomi-tls/logs \
 && chown -R guomi:guomi /var/cache/guomi-tls /var/run/guomi-tls /opt/guomi-tls/logs
USER guomi
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/guomi-tls-entrypoint"]
