#!/bin/sh -e

cd "$(dirname "$0")"

mkdir -p testcases/certs
cd testcases/certs

for domain in a.com b.com c.com fallback fallback0 fallback1; do
    echo "Generating cert for $domain"
    openssl req -x509 -newkey rsa:4096 -keyout "$domain.key" -out "$domain.crt" -days 365 -nodes -subj "/C=DE/ST=NRW/L=Paderborn/O=UPB/OU=SysSec/CN=$domain"
done
