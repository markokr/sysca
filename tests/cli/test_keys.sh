#! /bin/sh

set -e

. $(dirname $0)/lib.sh

ec_list=""
for curve in $(sysca show-curves); do
  ec_list="${ec_list} ec:${curve}"
done

for ktype in ${ec_list} rsa:2048 rsa:3072 rsa:4096 dsa:2048 dsa:3072; do
  pfx="keys_${ktype}"
  echo "## ${ktype} ##"
  sysca new-key "${ktype}" --out "tmp/${pfx}_ca.key"

  sysca request \
    --key tmp/${pfx}_ca.key \
    --CA \
    --out tmp/${pfx}_ca.csr

  sysca sign \
    --ca-key tmp/${pfx}_ca.key \
    --ca-info tmp/${pfx}_ca.csr \
    --request tmp/${pfx}_ca.csr \
    --days 300 \
    --out tmp/${pfx}_ca.crt

  sysca update-crl \
    --ca-key tmp/${pfx}_ca.key \
    --ca-info tmp/${pfx}_ca.crt \
    --days 300 \
    --crl-number 1 \
    --revoke-serials 9 \
    --out tmp/${pfx}_crl.crl

  #sysca --text show tmp/${pfx}_crl.crl
done

