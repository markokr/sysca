
import tempfile
import os
import collections

from nose.tools import *

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
    eq_(1, 1)

def test_same_pubkey():
    k1 = sysca.new_ec_key()
    k2 = sysca.new_ec_key()
    k3 = sysca.new_rsa_key()
    k4 = sysca.new_rsa_key()
    assert_true(sysca.same_pubkey(k1, k1))
    assert_true(sysca.same_pubkey(k2, k2))
    assert_true(sysca.same_pubkey(k3, k3))
    assert_true(sysca.same_pubkey(k4, k4))
    assert_false(sysca.same_pubkey(k1, k2))
    assert_false(sysca.same_pubkey(k1, k3))
    assert_false(sysca.same_pubkey(k3, k1))
    assert_false(sysca.same_pubkey(k3, k4))

def test_write_key():
    fd, name = tempfile.mkstemp()
    os.close(fd)
    try:
        # ec key, unencrypted
        key = sysca.new_ec_key()
        open(name, 'wb').write(sysca.key_to_pem(key))
        key2 = sysca.load_key(name)
        assert_true(sysca.same_pubkey(key, key2))

        # ec key, encrypted
        key = sysca.new_ec_key()
        open(name, 'wb').write(sysca.key_to_pem(key, 'password'))
        assert_raises(TypeError, sysca.load_key, name)
        assert_raises(ValueError, sysca.load_key, name, 'wrong')
        key2 = sysca.load_key(name, 'password')
        assert_true(sysca.same_pubkey(key, key2))

        # rsa key, unencrypted
        key = sysca.new_rsa_key()
        open(name, 'wb').write(sysca.key_to_pem(key))
        key2 = sysca.load_key(name)
        assert_true(sysca.same_pubkey(key, key2))

        # rsa key, encrypted
        key = sysca.new_rsa_key()
        open(name, 'wb').write(sysca.key_to_pem(key, 'password'))
        assert_raises(TypeError, sysca.load_key, name)
        assert_raises(ValueError, sysca.load_key, name, 'wrong')
        key2 = sysca.load_key(name, 'password')
        assert_true(sysca.same_pubkey(key, key2))
    finally:
        os.unlink(name)

def test_render_name():
    d = collections.OrderedDict()
    d['CN'] = 'name'
    d['O'] = 'org'
    eq_(sysca.render_name(d), '/CN=name/O=org/')

    d['X'] = r'x\b/z'
    w = sysca.render_name(d)
    eq_(w, '/CN=name/O=org/X=x\\\\b\\/z/')
    eq_(sysca.parse_dn(w), d)


def test_passthrough():
    key = sysca.new_ec_key()
    info = sysca.CertInfo(
        subject={'CN': 'Passing'},
        ca=True,
        path_length=3,
        alt_names=[
            'dns:*.www.com',
            'email:root@www.com',
            'ip:127.0.0.1',
            'uri:http://www.com',
            'dn:/CN=sub-dn/',
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
    eq_(lst1, lst2)


