#! /bin/sh

set -e

. $(dirname $0)/lib.sh

## update-crl

pfx="crldirect"

sysca new-key ec --out tmp/${pfx}_ca.key

sysca selfsign \
  --key tmp/${pfx}_ca.key \
  --subject '/CN=crlca/' \
  --crl-url 'http://crl0.example.com , http://crl1.example.com' \
  --ocsp-url 'http://ocsp0.example.com , http://ocsp1.example.com' \
  --issuer-url 'http://ftp.example.com/ca.crt, http://ftp2.example.com/ca.crt' \
  --CA \
  --days 900 \
  --out tmp/${pfx}_ca.crt

sysca update-crl \
  --ca-key tmp/${pfx}_ca.key \
  --ca-info tmp/${pfx}_ca.crt \
  --crl-number 7 \
  --delta-crl-number 5 \
  --days 90 \
  --revoke-serial 3 \
  --out tmp/${pfx}_v1.crl

sysca update-crl \
  --ca-key tmp/${pfx}_ca.key \
  --ca-info tmp/${pfx}_ca.crt \
  --crl tmp/${pfx}_v1.crl \
  --days 90 \
  --revoke-serials 1000 2000 \
  --out tmp/${pfx}_v2.crl

# openssl crl -text -in tmp/crl-v1.crl
sysca show tmp/${pfx}_v2.crl
#openssl crl -text -in tmp/crl-v1.crl  \
#  | sed -e '/:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:/d' -e '/^----/q'
#openssl crl -text -in tmp/crl-v2.crl  \
#  | sed -e '/:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:/d' -e '/^----/q'

echo "Success."
