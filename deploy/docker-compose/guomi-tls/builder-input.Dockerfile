# Builder input for guomi-tls (prepared once while online, then docker save'd
# into the release inputs like the other *-input images). Pins the Alpine
# base by digest; the package set is the minimum Tongsuo + Tengine need.
FROM alpine:3.20
RUN apk add --no-cache build-base perl linux-headers pcre2-dev zlib-dev
