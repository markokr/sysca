
import re

import sysca


def zfilter(ln):
    ln = re.sub(r'\d\d\d\d-\d\d-\d\d.*', 'DT', ln)
    return ln

def test_crl_passthrough():
    # create ca key and cert
    ca_key = sysca.new_ec_key()
    ca_pub_key = ca_key.public_key()
    ca_pre_info = sysca.CertInfo(subject={'CN': 'CrlCA'}, ca=True)
    ca_cert = sysca.create_x509_cert(ca_key, ca_pub_key, ca_pre_info, ca_pre_info, 365)
    ca_info = sysca.CertInfo(load=ca_cert)

    # srv key
    srv_key = sysca.new_rsa_key()
    srv_info = sysca.CertInfo(subject={'CN': 'CrlServer1'}, usage='server')
    srv_req = sysca.create_x509_req(srv_key, srv_info)

    # ca signs
    srv_info2 = sysca.CertInfo(load=srv_req)
    srv_certobj = sysca.create_x509_cert(ca_key, srv_req.public_key(), srv_info2, ca_info, 365)
    srv_cert = sysca.CertInfo(load=srv_certobj)
    assert 'server' in srv_cert.usage

    crl = sysca.CRLInfo()
    crl.delta_crl_number = 9
    crl.crl_number = 10
    crl.issuer_urls.append('http://issuer_urls')
    #crl.freshest_urls.append('http://freshest_urls')

    crlobj = crl.generate_crl(ca_key, ca_info, days=30)

    crl2 = sysca.CRLInfo(load=crlobj)
    crl2obj = crl2.generate_crl(ca_key, ca_info, days=30)
    crl3 = sysca.CRLInfo(load=crl2obj)

    lst1 = []
    lst2 = []
    crl2.show(lst1.append)
    crl3.show(lst2.append)

    lst1 = [zfilter(e) for e in lst1]
    lst2 = [zfilter(e) for e in lst2]
    assert lst1 == lst2
    assert lst1 == [
        'Issuer Name: /CN=CrlCA/',
        'CRL Scope: all',
        'CRL Number: 0a',
        'Delta CRL Number: 09',
        'Last update: DT',
        'Next update: DT',
        'Issuer URLs: http://issuer_urls',
    ]


