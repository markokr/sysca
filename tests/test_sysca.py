
import tempfile
import os
import re
import collections
import pytest

import sysca


def test_sysca():
    # create ca key and cert
    ca_key = sysca.new_ec_key()
    ca_pub_key = ca_key.public_key()
    ca_info = sysca.CertInfo(subject={'CN': 'TestCA'}, ca=True)
    ca_cert = sysca.create_x509_cert(ca_key, ca_pub_key, ca_info, ca_info, 365)

    # srv key
    srv_key = sysca.new_rsa_key()
    srv_info = sysca.CertInfo(subject={'CN': 'Server1'})
    srv_req = sysca.create_x509_req(srv_key, srv_info)

    # ca signs
    srv_info2 = sysca.CertInfo(load=srv_req)
    srv_cert = sysca.create_x509_cert(ca_key, srv_req.public_key(), srv_info2, ca_info, 365)


def test_same_pubkey():
    k1 = sysca.new_ec_key()
    k2 = sysca.new_ec_key()
    k3 = sysca.new_rsa_key()
    k4 = sysca.new_rsa_key()
    assert sysca.same_pubkey(k1, k1)
    assert sysca.same_pubkey(k2, k2)
    assert sysca.same_pubkey(k3, k3)
    assert sysca.same_pubkey(k4, k4)
    assert not sysca.same_pubkey(k1, k2)
    assert not sysca.same_pubkey(k1, k3)
    assert not sysca.same_pubkey(k3, k1)
    assert not sysca.same_pubkey(k3, k4)

def test_write_key():
    fd, name = tempfile.mkstemp()
    os.close(fd)
    try:
        # ec key, unencrypted
        key = sysca.new_ec_key()
        open(name, 'wb').write(sysca.key_to_pem(key))
        key2 = sysca.load_key(name)
        assert sysca.same_pubkey(key, key2)

        # ec key, encrypted
        key = sysca.new_ec_key()
        open(name, 'wb').write(sysca.key_to_pem(key, 'password'))
        with pytest.raises(TypeError):
            sysca.load_key(name)
        with pytest.raises(ValueError):
            sysca.load_key(name, 'wrong')
        key2 = sysca.load_key(name, 'password')
        assert sysca.same_pubkey(key, key2)

        # rsa key, unencrypted
        key = sysca.new_rsa_key()
        open(name, 'wb').write(sysca.key_to_pem(key))
        key2 = sysca.load_key(name)
        assert sysca.same_pubkey(key, key2)

        # rsa key, encrypted
        key = sysca.new_rsa_key()
        open(name, 'wb').write(sysca.key_to_pem(key, 'password'))
        with pytest.raises(TypeError):
            sysca.load_key(name)
        with pytest.raises(ValueError):
            sysca.load_key(name, 'wrong')
        key2 = sysca.load_key(name, 'password')
        assert sysca.same_pubkey(key, key2)

        # dsa key, unencrypted
        key = sysca.new_dsa_key()
        open(name, 'wb').write(sysca.key_to_pem(key))
        key2 = sysca.load_key(name)
        assert sysca.same_pubkey(key, key2)

        # dsa key, encrypted
        key = sysca.new_dsa_key()
        open(name, 'wb').write(sysca.key_to_pem(key, 'password'))
        with pytest.raises(TypeError):
            sysca.load_key(name)
        with pytest.raises(ValueError):
            sysca.load_key(name, 'wrong')
        key2 = sysca.load_key(name, 'password')
        assert sysca.same_pubkey(key, key2)
    finally:
        os.unlink(name)

def test_render_name():
    d = [('CN', 'name'), ('O', 'org')]
    assert sysca.render_name(d) == '/CN=name/O=org/'

    d.append(('X', r'x\b/z'))
    w = sysca.render_name(d)
    assert w == '/CN=name/O=org/X=x\\\\b\\/z/'
    assert sysca.parse_dn(w) == d


def test_passthrough():
    key = sysca.new_ec_key()
    info = sysca.CertInfo(
        subject={
            'CN': 'Passing',
            'O': 'OrgName',
            'OU': 'OrgUnit',
            'C': 'CA',
            'L': 'Location',
            'ST': 'State',
            'SN': 'Surname',
            'GN': 'GivenName',
            'T': 'Title',
            'P': 'Pseudonym',
            'GQ': 'GEN_QUAL',
            'DQ': 'DN_QUAL',
            'UID': 'UID',
            'XUID': 'XUID',
            'EMAIL': 'e@mail',
            'SERIAL': 'EV_SERIAL',
            'SA': 'StreetAddr',
            'PA': 'PostalAddr',
            'PC': 'PostalCode',
            'JC': 'CA',
            'JL': 'JurLocation',
            'JST': 'JurState',
        },
        ca=True,
        path_length=3,
        alt_names=[
            'dns:*.www.com',
            'email:root@www.com',
            'ip:127.0.0.1',
            'uri:http://www.com',
            'dn:/CN=sub-dn/BC=foo/BC=bar/',
        ],
        usage=[
            'digital_signature',
            'content_commitment',
            'key_encipherment',
            'data_encipherment',
            'key_agreement',
            'key_cert_sign',
            'crl_sign',
            # xku
            'server',
            'client',
            'code',
            'email',
            'time',
            'ocsp',
            'any',
        ],
        inhibit_any=6,
        ocsp_must_staple=True,
        ocsp_must_staple_v2=True,
        ocsp_nocheck=True,
        ocsp_urls=['http://localhost'],
        issuer_urls=['http://localhost'],
        permit_subtrees=['dns:*.www.com'],
        exclude_subtrees=['dns:*.www.net'],
    )
    req = sysca.create_x509_req(key, info)
    info2 = sysca.CertInfo(load=req)

    lst1 = []
    lst2 = []
    info.show(lst1.append)
    info2.show(lst2.append)
    lst2.remove('Public key: ec:secp256r1')
    assert lst1 == lst2


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
    srv_info = sysca.CertInfo(subject={'CN': 'CrlServer1'})
    srv_req = sysca.create_x509_req(srv_key, srv_info)

    # ca signs
    srv_info2 = sysca.CertInfo(load=srv_req)
    srv_cert = sysca.create_x509_cert(ca_key, srv_req.public_key(), srv_info2, ca_info, 365)


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


def test_safecurves():
    if sysca.ed25519 is None:
        return

    # create ca key and cert
    ca_key = sysca.new_ec_key('ed25519')
    ca_pub_key = ca_key.public_key()
    ca_info = sysca.CertInfo(subject={'CN': 'TestCA'}, ca=True)
    ca_cert = sysca.create_x509_cert(ca_key, ca_pub_key, ca_info, ca_info, 365)

    # srv key
    srv_key = sysca.new_ec_key('ed25519')
    srv_info = sysca.CertInfo(subject={'CN': 'Server1'})
    srv_req = sysca.create_x509_req(srv_key, srv_info)

    # ca signs
    srv_info2 = sysca.CertInfo(load=srv_req)
    srv_cert = sysca.create_x509_cert(ca_key, srv_req.public_key(), srv_info2, ca_info, 365)


