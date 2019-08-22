#! /bin/sh

set -e

. $(dirname $0)/lib.sh

## selfsign

pfx="selfsigned"

sysca new-key rsa --out tmp/${pfx}_ca.key

sysca selfsign \
  --key tmp/${pfx}_ca.key \
  --subject '/CN=client/ L = Fooza 1\/2 / SA=Läft 4\\b/ BC=bc1 / BC=bc2 /' \
  --san 'dns:*.example.com , ip : 127.0.0.1, ip:::1, uri:http://localhost/, email: me@qqq.com, dn:/T=mööTitle/' \
  --crl-url 'http://crl0.example.com , http://crl1.example.com' \
  --ocsp-url 'http://ocsp0.example.com , http://ocsp1.example.com' \
  --issuer-url 'http://ftp.example.com/ca.crt, http://ftp2.example.com/ca.crt' \
  --usage 'client, server, code, email, time, ocsp, any, content_commitment' \
  --ocsp-nocheck \
  --ocsp-must-staple \
  --ocsp-must-staple-v2 \
  --inhibit-any 5 \
  --require-explicit-policy=3 \
  --inhibit-policy-mapping=2 \
  --add-policy '1.2.3.4:P=localhost,P=internal' \
  --add-policy '2.3.4.5:O=org|N=1:2:3|T=words,T=more,O=only,N=1' \
  --add-policy '2.5.29.32.0' \
  --CA \
  --days 900 \
  --out tmp/${pfx}_ca.crt

sysca show tmp/${pfx}_ca.crt \
  | sed -e '/:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:/d' -e '/^----/q'

