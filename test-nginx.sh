#!/bin/sh -e

cd "$(dirname "$0")"

PWD=$(pwd)

if ! [ -d test ]; then
    mkdir test
    dd if=/dev/urandom of=test/stek48.key bs=48 count=1
    dd if=/dev/urandom of=test/stek80.key bs=80 count=1
fi

python -m util.config nginx one-server |  grep "# nginx" -A 9999 > test/config-nginx

docker run --rm \
    -v "$PWD/testcases/certs:/certs" \
    -v "$PWD/testcases/sites:/sites" \
    -v "$PWD/test/stek48.key:/stek.key" \
    -v "$PWD/test/config-nginx:/etc/nginx/nginx.conf" \
    nginx
