from datetime import datetime, timedelta

import pytest

import sysca.api as sysca

from sysca.files import autodetect_data, autodetect_filename, autodetect_file

from helpers import demo_fn, demo_data, new_root


def dump(obj):
    if not isinstance(obj, sysca.CertInfo):
        obj = sysca.CertInfo(load=obj)
    lst = []
    obj.show(lst.append)
    return "\n".join(lst) + "\n"


def test_sysca():
    # create ca key and cert
    ca_key, ca_certobj = new_root(subject={"CN": "TestCA"})
    ca_cert = sysca.CertInfo(load=ca_certobj)
    assert ca_cert.ca

    # srv key
    srv_key = sysca.new_rsa_key()
    srv_info = sysca.CertInfo(subject={"CN": "Server1"})
    srv_req = sysca.create_x509_req(srv_key, srv_info)

    # ca signs
    srv_info2 = sysca.CertInfo(load=srv_req)
    srv_certobj = sysca.create_x509_cert(ca_key, srv_req.public_key(), srv_info2, ca_cert, 365)
    srv_cert = sysca.CertInfo(load=srv_certobj)
    assert not srv_cert.ca


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


def test_render_name():
    d = (("CN", "name"), ("O", "org"))
    assert sysca.render_name(d, "/") == "/CN=name/O=org/"
    assert sysca.parse_dn(r"/ CN =name / / O = \6Frg ") == d

    with pytest.raises(ValueError, match="Need"):
        sysca.parse_dn(r"/CN/")

    d += (("X", r"x\b/z"),)
    w = sysca.render_name(d, "/")
    assert w == "/CN=name/O=org/X=x\\\\b\\/z/"
    assert sysca.parse_dn(w) == d

    d = (("CN", "na,/\\"), ("O", "o\x00\x09"))
    w = sysca.render_name(d, "/")
    assert w == r"/CN=na,\/\\/O=o\00\09/"


def test_passthrough():
    key = sysca.new_rsa_key()
    info = sysca.CertInfo(
        subject={
            "CN": "Passing",
            "O": "OrgName",
            "OU": "OrgUnit",
            "C": "CA",
            "L": "Location",
            "ST": "State",
            "SN": "Surname",
            "GN": "GivenName",
            "T": "Title",
            "P": "Pseudonym",
            "GQ": "GEN_QUAL",
            "DQ": "DN_QUAL",
            "UID": "UID",
            "XUID": "XUID",
            "EMAIL": "e@mail",
            "SERIAL": "EV_SERIAL",
            "STREET": "StreetAddr",
            "PA": "PostalAddr",
            "PC": "PostalCode",
            "JC": "CA",
            "JL": "JurLocation",
            "JST": "JurState",
        },
        ca=True,
        path_length=3,
        alt_names=[
            "dns:*.www.com",
            "email:root@www.com",
            "ip:127.0.0.1",
            "ip:ff80::1",
            "net:10.0.0.0/8",
            "net:ff80::/64",
            "uri:http://www.com",
            "dn:/CN=sub-dn/BC=foo/BC=bar/",
        ],
        usage=[
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
            # xku
            "server",
            "client",
            "code",
            "email",
            "time",
            "ocsp",
            "any",
        ],
        inhibit_any=6,
        require_explicit_policy=2,
        inhibit_policy_mapping=3,
        ocsp_must_staple=True,
        ocsp_must_staple_v2=True,
        ocsp_nocheck=True,
        ocsp_urls=["http://ocsp_urls"],
        issuer_urls=["http://issuer_urls"],
        crl_urls=["http://crl_urls"],
        delta_crl_urls=["http://delta_crl_urls"],
        permit_subtrees=["dns:*.www.com"],
        exclude_subtrees=["dns:*.www.net"],
        certificate_policies=[
            "1.1.1",
            "1.1.2:|P=link|",
            "1.1.3:|P=link2|,|P=link3|",
            "1.1.4:|O=org|,|N=1|,|T=txt|",
            "1.1.5:|O=org|N=2:3|T=txt2|",
        ],
    )
    req = sysca.create_x509_req(key, info)
    info2 = sysca.CertInfo(load=req)

    assert info2.inhibit_any == 6
    assert info2.path_length == 3
    assert info2.require_explicit_policy == 2
    assert info2.inhibit_policy_mapping == 3
    assert info2.ocsp_must_staple and info2.ocsp_must_staple_v2
    assert info2.ca and info2.ocsp_nocheck

    lst1 = []
    lst2 = []
    info.show(lst1.append)
    info2.show(lst2.append)
    lst2 = [ln for ln in lst2 if not (
        ln.startswith("Public key:") or ln.startswith("Subject Key Identifier:")
    )]
    assert lst1 == lst2


def test_file_show():
    certs = (
        "letsencrypt-org.crt", "letsencrypt-x3.crt",
        "ec-p256-ca.crt",
    )
    for fn in certs:
        cert = sysca.load_cert(demo_fn(fn))
        out = demo_data(fn + ".out", "r")
        assert dump(cert) == out


def test_autodetect():
    ftypes = (
        ("ec-p256-ca.crt", "crt"),
        ("ec-p256-ca.csr", "csr"),
        ("ec-p256-ca.crl", "crl"),
        ("ec-p256.key", "key"),
        ("ec-p256.psw.key", "key"),
        ("ec-p256.pub", "pub"),
        ("password.txt", None),
    )
    for fn, t in ftypes:
        assert autodetect_data(demo_data(fn)) == t
        assert autodetect_filename(demo_fn(fn)) == t
        assert autodetect_file(demo_fn(fn)) == t

    assert autodetect_data(b"\x01\x02asdadsasdasd") is None

    other = (b"-----BEGIN GPG-----\n"
             b"113414241424\n"
             b"-----END GPG-----\n")
    assert autodetect_data(other) is None
    assert autodetect_data(other.replace(b"END ", b"END X ")) is None
    assert autodetect_data(other.replace(b"END ", b"X ")) is None


SAMPLE_SET_SERIAL = """\
Version: 3
Public key: ec:secp256r1
Not Valid Before: 2010-06-22 14:00:59
Not Valid After: 2050-01-03 14:00:59
Serial: 01:e2:40
Subject: CN = set
CA: True
Usage: key_cert_sign, crl_sign
Subject Key Identifier: 0d60f448426711c74637176e19ce725470431e5f
Authority Key Identifier: 0d60f448426711c74637176e19ce725470431e5f
Issuer Name: CN = set
"""


def test_set_serial():
    key = sysca.load_key(demo_fn("ec-p256.key"))
    info = sysca.CertInfo(subject="CN=set", ca=True, load=key)
    cert = sysca.create_x509_cert(key, key.public_key(), info, info,
                                  serial_number="123456",
                                  not_valid_before="2010-06-22 14:00:59",
                                  not_valid_after=datetime(2050, 1, 3, 14, 0, 59))
    assert dump(cert) == SAMPLE_SET_SERIAL


def test_parse_timestamp():
    assert sysca.parse_timestamp("2005-01-02") == datetime(2005, 1, 2)
    assert sysca.parse_timestamp("2005-01-02 11:22") == datetime(2005, 1, 2, 11, 22)
    assert sysca.parse_timestamp("2005-01-02 11:22:33") == datetime(2005, 1, 2, 11, 22, 33)

    with pytest.raises(ValueError):
        sysca.parse_timestamp("")


def test_parse_time_period():
    d1, d2 = sysca.parse_time_period("300")
    assert d2 - d1 > timedelta(days=290)
    assert d2 - d1 < timedelta(days=310)

    d1, d2 = sysca.parse_time_period(not_valid_after="2200-01-01")
    assert d2 - d1 > timedelta(days=15 * 365)

    d1, d2 = sysca.parse_time_period(not_valid_before="1989-01-01", not_valid_after="1995-01-01")
    assert d2 - d1 > timedelta(days=5 * 365)

    d1, d2 = sysca.parse_time_period(not_valid_before=datetime(1989, 1, 1), not_valid_after=datetime(1995, 1, 1))
    assert d2 - d1 > timedelta(days=5 * 365)

    with pytest.raises(ValueError, match="days"):
        sysca.parse_time_period(not_valid_before="2001-01-01")

    with pytest.raises(ValueError, match="range"):
        sysca.parse_time_period(not_valid_before="2001-01-01", not_valid_after="2000-01-01")

    with pytest.raises(ValueError):
        sysca.parse_time_period(not_valid_before="2", not_valid_after=3)


def test_parse_number():
    assert sysca.parse_number("123456") == 123456
    assert sysca.parse_number("11:22:33") == 0x112233
    assert sysca.parse_number("11-22-33") == 0x112233

    with pytest.raises(ValueError):
        sysca.parse_number("")


def test_load_pass():
    assert sysca.load_password(demo_fn("password.txt")) == b"password1"
    assert sysca.load_password(None) is None
