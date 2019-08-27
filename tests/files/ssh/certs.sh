#! /bin/sh

# generate public key files with certificate
ssh-keygen -q -s "new-dsa-nopsw.key" -I "name" \
    -z 1 -V 20100101123000:21090101123000 \
    "new-dsa-nopsw.key.pub"
ssh-keygen -q -s "new-rsa-nopsw.key" -I "name" \
    -z 2 -n user1,user2 -t rsa-sha2-512 \
    "new-rsa-nopsw.key.pub"
ssh-keygen -q -s "new-ecdsa-nopsw.key" -I "name" \
    -h -n domain1,domain2 \
    "new-ecdsa-nopsw.key.pub"
ssh-keygen -q -s "new-ed25519-nopsw.key" -I "name" \
    -O no-port-forwarding \
    "new-ed25519-nopsw.key.pub"

