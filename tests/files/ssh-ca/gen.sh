#! /bin/sh

set -e

PATH=/opt/apps/openssh/bin:$PATH
export PATH

rm -f *.key *.pub

dogen() {
    prefix="$1"
    genargs="$2"
    sigargs="$3"
    ca_fn="${prefix}-ca.key"
    user_fn="${prefix}-user.key"
    set -x
    ssh-keygen -q -o ${genargs} -f "${ca_fn}" -C "${ca_fn}" -N ''
    ssh-keygen -q -o ${genargs} -f "${user_fn}" -C "${user_fn}" -N ''
    ssh-keygen -q ${sigargs} -s "${ca_fn}" -I "username" "${user_fn}.pub"
    set +x
}

rm -f *.pub *.key

dogen ecdsa "-t ecdsa" "-z 1 -V 20100101123000:21090101123000"
dogen dsa "-t dsa" "-z 2 -n user1,user2"
dogen rsa-sha1 "-t rsa -b 2048" "-t ssh-rsa -O clear"
dogen rsa-sha256 "-t rsa" "-t rsa-sha2-256 -h -n domain1,domain2"
dogen rsa-sha512 "-t rsa -b 4096" "-t rsa-sha2-512 -O no-port-forwarding"
dogen ed25519 "-t ed25519" ""

