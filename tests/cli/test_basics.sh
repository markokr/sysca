#! /bin/sh

set -e

. $(dirname $0)/lib.sh

pfx="basics"

## Root ca

sysca new-key ec:secp384r1 --out "tmp/${pfx}_ca.key"

sysca request \
  --key tmp/${pfx}_ca.key \
  --subject 'CN=TestCA/O=testers/' \
  --CA \
  --path-length 1 \
  --out tmp/${pfx}_ca.csr

sysca sign \
  --ca-key tmp/${pfx}_ca.key \
  --ca-info tmp/${pfx}_ca.csr \
  --request tmp/${pfx}_ca.csr \
  --days 300 \
  --out tmp/${pfx}_ca.crt

## SubCA

sysca new-key > tmp/${pfx}_subca.key

sysca request \
  --key tmp/${pfx}_subca.key \
  --subject 'CN=SubCA/O=subtesters/' \
  --CA \
  --path-length 0 \
  --out tmp/${pfx}_subca.csr

sysca sign \
  --ca-key tmp/${pfx}_ca.key \
  --ca-info tmp/${pfx}_ca.crt \
  --request tmp/${pfx}_subca.csr \
  --days 300 \
  --text \
  --out tmp/${pfx}_subca.crt

## client cert

sysca new-key rsa --out tmp/${pfx}_client.key

sysca request \
  --key tmp/${pfx}_client.key \
  --subject '/CN=client/ L = Fooza 1\/2 / SA=Läft 4\\b/' \
  --san 'dns:*.example.com , ip : 127.0.0.1, ip:::1, uri:http://localhost/, email: me@qqq.com, dn:/T=mööTitle/' \
  --crl-url 'http://crl0.example.com , http://crl1.example.com' \
  --ocsp-url 'http://ocsp0.example.com , http://ocsp1.example.com' \
  --issuer-url 'http://ftp.example.com/ca.crt, http://ftp2.example.com/ca.crt' \
  --usage 'client, server, code, email, time, ocsp, any, content_commitment' \
  --ocsp-nocheck \
  --ocsp-must-staple \
  --ocsp-must-staple-v2 \
  --out tmp/${pfx}_client.csr

sysca sign \
  --ca-key tmp/${pfx}_subca.key \
  --ca-info tmp/${pfx}_subca.crt \
  --request tmp/${pfx}_client.csr \
  --days 300 \
  --out tmp/${pfx}_client.crt

sysca show tmp/${pfx}_client.crt \
  | sed -e '/:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:/d' -e '/^----/q'

sysca sign \
  --ca-key tmp/${pfx}_subca.key \
  --ca-info tmp/${pfx}_subca.crt \
  --request tmp/${pfx}_client.csr \
  --days 300 \
  --out tmp/${pfx}_client2.crt \
  --subject '/CN=overwritten/' \
  --san 'dns:*.overwritten.com' \
  --reset

sysca show tmp/${pfx}_client2.crt \
  | sed -e '/:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:/d' -e '/^----/q'

