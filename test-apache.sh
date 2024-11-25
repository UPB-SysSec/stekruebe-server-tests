#!/bin/sh -e

cd "$(dirname "$0")"

PWD=$(pwd)

if ! [ -d test ]; then
    mkdir test
    dd if=/dev/urandom of=test/stek48.key bs=48 count=1
    dd if=/dev/urandom of=test/stek80.key bs=80 count=1
fi

python -m evaluate.util.config apache one-server |  grep "# apache" -A 9999 > test/config-apache

docker run --rm \
    -v "$PWD/testcases/certs:/certs" \
    -v "$PWD/testcases/sites:/sites" \
    -v "$PWD/test/stek48.key:/stek.key" \
    -v "$PWD/test/config-apache:/usr/local/apache2/conf/httpd.conf" \
    httpd
