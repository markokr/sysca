#! /bin/sh

set -e

# some pgp key that works
pgp_me=$(sed -n -e '/^default-key /s/^[^ ]* //p' $HOME/.gnupg/gpg.conf)

# both py2 and py3 should work
sysca='python2 sysca.py'
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
  --days 900 \
  --out tmp/selfsigned.crt

$sysca show tmp/selfsigned.crt \
  | sed -e '/:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:/d' -e '/^----/q'

echo "Success."
