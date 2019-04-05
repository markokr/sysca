
import tempfile
import os
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
    assert lst1 == lst2


