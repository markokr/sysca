#! /bin/sh

set -e

#exit 0

sysca() {
    python3 ../../local.py "$@"
}

sysca new-key ec --out ec2.key

bigsubj='
CN=commonName /
C=US / L=Locality / ST=State/

O=org /
OU=unit1of2 / OU=unit2of2 /
SA=streetAddr_1of3 / SA=Fooza 1\/2 / SA=Läft 4\\b/
PA=post1 / PA=post2 /
BC=bzcat1 / BC=bzcat2 /
DC=dom1 / DC=dom2 /

SN=surname / GN=givenName / T=title / P=pseudo /
GQ=genq / DQ=dnQ /
UID=uid / XUID=x500uid / EMAIL=e@ma.il / SERIAL=xserial /
PC=postCode /
JC=US / JL=jLocal / JST=jState /
'

sysca request \
  --key ec2.key \
  --subject "${bigsubj}" \
  --san 'dns:*.example.com , ip:127.0.0.1, ip:8000::1, net:10.0.0.0/8, net:ff80::/64, uri:http://local/, email: me@qqq.com, dn:/T=Lęt/' \
  --crl-urls 'http://crl0.example.com , http://crl1.example.com' \
  --ocsp-urls 'http://ocsp0.example.com , http://ocsp1.example.com' \
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
  --path-length 0 \
  --out ec2-rich.csr

sysca sign \
  --ca-key ec2.key \
  --ca-info ec2-rich.csr \
  --request ec2-rich.csr \
  --out ec2-rich.crt \
  --not-valid-before '1995-12-24' \
  --not-valid-after '2195-12-24' \
  --serial-number 255

sysca show ec2-rich.csr > ec2-rich.csr.out
sysca show ec2-rich.crt > ec2-rich.crt.out


sysca new-key --out autogen_ca/CA1_2020.key
sysca new-key --out autogen_ca/CA2_2020.key
sysca new-key --out autogen_ca/CA3_2020.key

sysca selfsign --key autogen_ca/CA1_2020.key --days 15000 --CA --subject '/CN=CA1/' --out autogen_ca/CA1_2020.crt
sysca selfsign --key autogen_ca/CA2_2020.key --days 15000 --CA --subject '/CN=CA2/' --out autogen_ca/CA2_2020.crt
sysca selfsign --key autogen_ca/CA3_2020.key --days 15000 --CA --subject '/CN=CA3/' --out autogen_ca/CA3_2020.crt

