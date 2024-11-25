#!/bin/sh -e

cd "$(dirname "$0")"

PWD=$(pwd)

python -m evaluate.util.config caddy one-server |  grep "# caddy" -A 9999 > test/config-caddy
cat test/config-caddy

docker run --rm \
    -v "$PWD/testcases/certs:/certs" \
    -v "$PWD/testcases/sites:/sites" \
    -v "$PWD/test/stek48.key:/stek.key" \
    -v "$PWD/test/config-caddy:/etc/caddy/Caddyfile" \
    -p 8080:80 \
    -p 8443:443 \
    caddy
