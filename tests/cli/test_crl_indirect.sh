#! /bin/sh

set -e

. $(dirname $0)/lib.sh

## update-crl

pfx="crlindirect"

sysca new-key ec --out tmp/${pfx}_ca.key
sysca selfsign \
  --key tmp/${pfx}_ca.key \
  --subject '/CN=ca/' \
  --san 'dns:main.ca, dn:/CN=ca.com/' \
  --crl-url 'http://crl0.example.com , http://crl1.example.com' \
  --issuer-url 'http://ftp.example.com/ca.crt, http://ftp2.example.com/ca.crt' \
  --CA \
  --days 900 \
  --out tmp/${pfx}_ca.crt

# subcas

for ca in subca1 subca2; do
  sysca new-key ec --out tmp/${pfx}_${ca}.key
  sysca request \
    --subject "/CN=${ca}/" \
    --san "dn:/CN=${ca}.ca/" \
    --CA \
    --days 900 \
    --key tmp/${pfx}_${ca}.key \
    --out tmp/${pfx}_${ca}.csr

  sysca sign \
    --ca-key tmp/${pfx}_ca.key \
    --ca-info tmp/${pfx}_ca.crt \
    --CA \
    --days 900 \
    --request tmp/${pfx}_${ca}.csr \
    --out tmp/${pfx}_${ca}.crt
done

# users

for ca in ca subca1 subca2; do
  for user in user1 user2; do
    capfx="tmp/${pfx}_${ca}"
    userpfx="tmp/${pfx}_${ca}_${user}"
    sysca new-key ec --out "${userpfx}.key"
    sysca request \
      --subject "/CN=${ca}_${user}/" \
      --days 900 \
      --key "${userpfx}.key" \
      --out "${userpfx}.csr"

    sysca sign \
      --ca-key "${capfx}.key" \
      --ca-info "${capfx}.crt" \
      --days 900 \
      --request "${userpfx}.csr" \
      --out "${userpfx}.crt"
  done 
done

# add certs
sysca update-crl \
  --ca-key tmp/${pfx}_ca.key \
  --ca-info tmp/${pfx}_ca.crt \
  --crl-number 1 \
  --days 90 \
  --indirect-crl \
  --crl-reasons 'key_compromise, ca_compromise' \
  --out tmp/${pfx}_v1.crl \
  --revoke-certs \
    tmp/${pfx}_ca_user1.crt \
    tmp/${pfx}_ca_user2.crt \
    tmp/${pfx}_subca1_user1.crt \
    tmp/${pfx}_subca1_user2.crt \
    tmp/${pfx}_subca2_user1.crt \
    tmp/${pfx}_subca2_user2.crt

# update existing
sysca update-crl \
  --ca-key tmp/${pfx}_ca.key \
  --ca-info tmp/${pfx}_ca.crt \
  --crl tmp/${pfx}_v1.crl \
  --days 90 \
  --out tmp/${pfx}_v2.crl \
  --revoke-serials 7 8

# openssl crl -text -in tmp/crl-v1.crl
sysca show tmp/${pfx}_v2.crl
#openssl crl -text -in tmp/crl-v1.crl  \
#  | sed -e '/:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:/d' -e '/^----/q'
#openssl crl -text -in tmp/crl-v2.crl  \
#  | sed -e '/:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:/d' -e '/^----/q'

echo "Success."
