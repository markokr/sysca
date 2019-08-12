#! /bin/sh

set -e

. $(dirname $0)/lib.sh

# some pgp key that works
pgp_me=$(sed -n -e '/^default-key /s/^[^ ]* //p' $HOME/.gnupg/gpg.conf)

pfx="gpg"

echo "passWD" | gpg -aes -r "$pgp_me" --batch > tmp/${pfx}_password.txt.gpg


## Root ca

sysca new-key ec:secp384r1 \
  --password-file tmp/password.txt.gpg \
  | gpg -aes -r "$pgp_me" --batch \
  > tmp/${pfx}_ca.key.gpg

sysca request \
  --password-file tmp/${pfx}_password.txt.gpg \
  --key tmp/${pfx}_ca.key.gpg \
  --subject 'CN=TestCA/O=testers/' \
  --CA \
  --path-length 1 \
  --out tmp/${pfx}_ca.csr

sysca sign \
  --password-file tmp/${pfx}_password.txt.gpg \
  --ca-key tmp/${pfx}_ca.key.gpg \
  --ca-info tmp/${pfx}_ca.csr \
  --request tmp/${pfx}_ca.csr \
  --days 300 \
  --out tmp/${pfx}_ca.crt

