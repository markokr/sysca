#! /bin/sh

set -e

# some pgp key that works
pgp_me=$(sed -n -e '/^default-key /s/^[^ ]* //p' $HOME/.gnupg/gpg.conf)

sysca='python3 sysca.py'

## init temp dir

mkdir -p tmp
rm -f tmp/ca.* tmp/client.* tmp/password.*
echo "passWD" | gpg -aes -r "$pgp_me" --batch > tmp/password.txt.gpg

## Root ca

$sysca new-key ec:secp384r1 \
  --password-file tmp/password.txt.gpg \
  | gpg -aes -r "$pgp_me" --batch \
  > tmp/ca.key.gpg

$sysca request \
  --password-file tmp/password.txt.gpg \
  --key tmp/ca.key.gpg \
  --subject 'CN=TestCA/O=testers/' \
  --CA \
  --path-length 1 \
  --out tmp/ca.csr

$sysca sign \
  --password-file tmp/password.txt.gpg \
  --ca-key tmp/ca.key.gpg \
  --ca-info tmp/ca.csr \
  --request tmp/ca.csr \
  --days 300 \
  --out tmp/ca.crt

## SubCA

$sysca new-key \
  | gpg -aes -r "$pgp_me" --batch \
  > tmp/subca.key.gpg

$sysca request \
  --key tmp/subca.key.gpg \
  --subject 'CN=SubCA/O=subtesters/' \
  --CA \
  --path-length 0 \
  --out tmp/subca.csr

$sysca sign \
  --password-file tmp/password.txt.gpg \
  --ca-key tmp/ca.key.gpg \
  --ca-info tmp/ca.crt \
  --request tmp/subca.csr \
  --days 300 \
  --text \
  --out tmp/subca.crt

## client cert

$sysca new-key rsa --out tmp/client.key

$sysca request \
  --key tmp/client.key \
  --subject '/CN=client/ L = Fooza 1\/2 / SA=Läft 4\\b/' \
  --san 'dns:*.example.com , ip : 127.0.0.1, ip:::1, uri:http://localhost/, email: me@qqq.com, dn:/T=mööTitle/' \
  --crl-url 'http://crl0.example.com , http://crl1.example.com' \
  --ocsp-url 'http://ocsp0.example.com , http://ocsp1.example.com' \
  --issuer-url 'http://ftp.example.com/ca.crt, http://ftp2.example.com/ca.crt' \
  --usage 'client, server, code, email, time, ocsp, any, content_commitment' \
  --ocsp-nocheck \
  --ocsp-must-staple \
  --ocsp-must-staple-v2 \
  --out tmp/client.csr

$sysca sign \
  --ca-key tmp/subca.key.gpg \
  --ca-info tmp/subca.crt \
  --request tmp/client.csr \
  --days 300 \
  --out tmp/client.crt

$sysca show tmp/client.crt \
  | sed -e '/:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:/d' -e '/^----/q'

$sysca sign \
  --ca-key tmp/subca.key.gpg \
  --ca-info tmp/subca.crt \
  --request tmp/client.csr \
  --days 300 \
  --out tmp/client2.crt \
  --subject '/CN=overwritten/' \
  --san 'dns:*.overwritten.com' \
  --reset

$sysca show tmp/client2.crt \
  | sed -e '/:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:/d' -e '/^----/q'

## selfsign

$sysca new-key rsa:4096 --out tmp/selfsigned.key

$sysca selfsign \
  --key tmp/selfsigned.key \
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
  --CA \
  --days 900 \
  --out tmp/selfsigned.crt

$sysca show tmp/selfsigned.crt \
  | sed -e '/:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:/d' -e '/^----/q'

## update-crl

$sysca new-key ec:secp521r1 --out tmp/crlca.key

$sysca selfsign \
  --key tmp/crlca.key \
  --subject '/CN=crlca/' \
  --crl-url 'http://crl0.example.com , http://crl1.example.com' \
  --ocsp-url 'http://ocsp0.example.com , http://ocsp1.example.com' \
  --issuer-url 'http://ftp.example.com/ca.crt, http://ftp2.example.com/ca.crt' \
  --CA \
  --days 900 \
  --out tmp/crlca.crt

$sysca update-crl \
  --ca-key tmp/crlca.key \
  --ca-info tmp/crlca.crt \
  --crl-number 7 \
  --delta-crl-number 5 \
  --ocsp-url 'http://ocsp0.example.com , http://ocsp1.example.com' \
  --issuer-url 'http://ftp.example.com/ca.crt, http://ftp2.example.com/ca.crt' \
  --days 90 \
  --out tmp/crl-v1.crl

$sysca update-crl \
  --crl tmp/crl-v1.crl \
  --ca-key tmp/crlca.key \
  --ca-info tmp/crlca.crt \
  --crl-number 8 \
  --delta-crl-number 7 \
  --days 90 \
  --revoke-serials 1000 2000 \
  --out tmp/crl-v2.crl

# openssl crl -text -in tmp/crl-v1.crl
#$sysca show tmp/crl-v1.crl
$sysca show tmp/crl-v2.crl
#openssl crl -text -in tmp/crl-v1.crl  \
#  | sed -e '/:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:/d' -e '/^----/q'
#openssl crl -text -in tmp/crl-v2.crl  \
#  | sed -e '/:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:/d' -e '/^----/q'

echo "Success."
