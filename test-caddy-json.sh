#!/bin/sh -e

cd "$(dirname "$0")"

PWD=$(pwd)

# python -m evaluate.util.config caddy_json one-server |  grep "### 0" -A 9999 > test/caddy-config.json
cat test/caddy-config.json

docker run --rm \
    -v "$PWD/testcases/certs:/certs" \
    -v "$PWD/testcases/sites:/sites" \
    -v "$PWD/test/stek48.key:/stek.key" \
    -v "$PWD/test/caddy-config.json:/etc/caddy/caddy-config.json" \
    -p 8080:80 \
    -p 8443:443 \
    caddy caddy run --config /etc/caddy/caddy-config.json
