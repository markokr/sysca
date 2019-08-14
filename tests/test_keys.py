
import tempfile
import os
import pytest

import sysca


EC_KEYS = ['ec'] + ['ec:' + n for n in sysca.get_ec_curves()]
RSA_KEYS = ['rsa', 'rsa:2048', 'rsa:3072', 'rsa:4096']
DSA_KEYS = ['dsa', 'dsa:2048', 'dsa:3072']

def process_write(key):
    fd, name = tempfile.mkstemp()
    os.close(fd)
    try:
        # ec key, unencrypted
        open(name, 'wb').write(sysca.key_to_pem(key))
        key2 = sysca.load_key(name)
        assert sysca.same_pubkey(key, key2)

        # ec key, encrypted
        open(name, 'wb').write(sysca.key_to_pem(key, 'password'))
        with pytest.raises(TypeError):
            sysca.load_key(name)
        with pytest.raises(ValueError):
            sysca.load_key(name, 'wrong')
        key2 = sysca.load_key(name, 'password')
        assert sysca.same_pubkey(key, key2)
    finally:
        os.unlink(name)

def process_crl(ca_key, ca_info):
    crl = sysca.CRLInfo()
    crl.delta_crl_number = 9
    crl.crl_number = 10

    crlobj = crl.generate_crl(ca_key, ca_info, days=30)

    crl2 = sysca.CRLInfo(load=crlobj)
    crl2obj = crl2.generate_crl(ca_key, ca_info, days=30)

    data = sysca.crl_to_pem(crl2obj)
    fd, name = tempfile.mkstemp()
    os.close(fd)
    try:
        # ec key, unencrypted
        open(name, 'wb').write(data)
        crlobj4 = sysca.load_crl(name)
        crl4 = sysca.CRLInfo(load=crlobj4)
        assert crl4.delta_crl_number == crl.delta_crl_number
    finally:
        os.unlink(name)


def process_ktype(ktype):
    # create ca key and cert
    ca_key = sysca.new_key(ktype)
    ca_pub_key = ca_key.public_key()
    ca_info = sysca.CertInfo(subject={'CN': 'TestCA'}, ca=True)
    ca_certobj = sysca.create_x509_cert(ca_key, ca_pub_key, ca_info, ca_info, 365)
    ca_cert = sysca.CertInfo(load=ca_certobj)

    # srv key
    srv_key = sysca.new_key(ktype)
    srv_info = sysca.CertInfo(subject={'CN': 'Server1'}, usage=['server'])
    srv_req = sysca.create_x509_req(srv_key, srv_info)

    # ca signs
    srv_info2 = sysca.CertInfo(load=srv_req)
    srv_certobj = sysca.create_x509_cert(ca_key, srv_req.public_key(), srv_info2, ca_info, 365)
    srv_cert = sysca.CertInfo(load=srv_certobj)
    assert 'server' in srv_cert.usage

    # test same key
    assert sysca.same_pubkey(ca_key, ca_key)
    assert not sysca.same_pubkey(ca_key, srv_key)

    process_write(ca_key)

    process_crl(ca_key, ca_cert)


def test_rsa():
    for ktype in RSA_KEYS:
        process_ktype(ktype)


def test_dsa():
    for ktype in DSA_KEYS:
        process_ktype(ktype)


def test_ec():
    for ktype in EC_KEYS:
        process_ktype(ktype)

