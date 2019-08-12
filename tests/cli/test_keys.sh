#! /bin/sh

set -e

. $(dirname $0)/lib.sh

for ktype in rsa:2048 rsa:3072 dsa:2048 dsa:3072 ec:secp256r1 ec:secp384r1 ec:secp521r1; do
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

done

