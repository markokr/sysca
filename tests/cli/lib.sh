#! /bin/sh

set -e

sysca_py=$(dirname $0)/../../sysca.py

sysca() {
  python3 ${sysca_py} "$@"
}

## init temp dir

mkdir -p tmp

