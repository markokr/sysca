
import re
from datetime import datetime, timezone
from typing import List, Union

import pytest
from cryptography import x509
from cryptography.x509.oid import SignatureAlgorithmOID
from helpers import HAVE_PSS, demo_fn, new_cert, new_root

import sysca.api as sysca

HAS_DPOINT = hasattr(x509, "IssuingDistributionPoint")


def zfilter(ln: str) -> str:
    ln = re.sub(r"\d\d\d\d-\d\d-\d\d.*", "DT", ln)
    ln = re.sub(r"Serial: .*", "Serial: SN", ln)
    ln = re.sub(r"Authority Key Identifier: .*", "Authority Key Identifier: KeyID", ln)
    return ln


def dump_crl(crl: Union[sysca.CRLInfo, x509.CertificateRevocationList]) -> List[str]:
    if not isinstance(crl, sysca.CRLInfo):
        crl = sysca.CRLInfo(load=crl)
    lst: List[str] = []
    crl.show(lst.append)
    return [zfilter(e) for e in lst]


def test_crl_delta() -> None:
    ca_key, ca_cert = new_root(subject="CN=CrlCA")

    crl = sysca.CRLInfo(delta_crl_urls=["test"], crl_number=1, delta_crl_number=2)
    with pytest.raises(ValueError):
        sysca.create_x509_crl(ca_key, ca_cert, crl, 30)

    crl = sysca.CRLInfo(crl_number=2, delta_crl_number=1)
    crlobj = sysca.create_x509_crl(ca_key, sysca.CertInfo(load=ca_cert), crl, 30)
    crlobj = sysca.create_x509_crl(ca_key, ca_cert, crlobj, 30)

    assert dump_crl(crlobj) == [
        "CRL Scope: all",
        "CRL Number: 02",
        "Delta CRL Number: 01",
        "Last update: DT",
        "Next update: DT",
        "Signature: ecdsa-with-SHA256",
        "Issuer Name: CN = CrlCA",
        "Authority Key Identifier: KeyID",
    ]


def test_api_errors() -> None:
    ca_key, ca_cert = new_root(subject="/CN=CrlCA/")

    crl = sysca.CRLInfo(crl_number=1)
    with pytest.raises(TypeError):
        sysca.create_x509_crl({}, ca_cert, crl, 30)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        sysca.create_x509_crl(ca_key, {}, crl, 30)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        sysca.create_x509_crl(ca_key, ca_cert, {}, 30)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        crl.add_certificate({})  # type: ignore[arg-type]


def test_crl_passthrough() -> None:
    # create ca key and cert
    ca_key, ca_cert = new_root(subject="CN=CrlCA", alt_names=["dn:/CN=CaCrl/"])

    # srv key
    srv_key, src_cert = new_cert(ca_key, ca_cert, subject={"CN": "CrlServer1"}, usage="server")

    crl = sysca.CRLInfo()
    crl.crl_number = 10
    crl.issuer_urls.append("http://issuer_urls")
    crl.ocsp_urls.append("http://ocsp_urls")
    crl.delta_crl_urls.append("http://freshest_urls")

    crlobj = sysca.create_x509_crl(ca_key, ca_cert, crl, 30)

    crl2 = sysca.CRLInfo(load=crlobj)
    crl2obj = sysca.create_x509_crl(ca_key, ca_cert, crl2, 30)
    crl3 = sysca.CRLInfo(load=crl2obj)

    lst1 = dump_crl(crl2)
    lst2 = dump_crl(crl3)
    assert lst1 == lst2
    assert lst1 == [
        "CRL Scope: all",
        "CRL Number: 0a",
        "Last update: DT",
        "Next update: DT",
        "Signature: ecdsa-with-SHA256",
        "Issuer Name: CN = CrlCA",
        "Issuer SAN: dn:/CN=CaCrl/",
        "Authority Key Identifier: KeyID",
        "Issuer URLs: http://issuer_urls",
        "OCSP URLs: http://ocsp_urls",
        "Delta CRL URLs: http://freshest_urls",
    ]


def test_direct_items() -> None:
    # create ca key and cert
    ca_key, ca_cert = new_root(subject="CN=DirectCrlCA")

    key1, cert1 = new_cert(ca_key, ca_cert, subject={"CN": "CrlServer1"}, usage="server")
    key2, cert2 = new_cert(ca_key, ca_cert, subject={"CN": "CrlServer2"}, usage="server")
    key3, cert3 = new_cert(ca_key, ca_cert, subject={"CN": "CrlServer3"}, usage="server")

    crl = sysca.CRLInfo(crl_number=10)
    crl.add_certificate(cert1, invalidity_date=datetime(2001, 10, 18, 21, 59, 59, tzinfo=timezone.utc))
    crl.add_certificate(cert2, reason="key_compromise")
    crl.add_certificate(cert3, reason="unspecified")

    crlobj = sysca.create_x509_crl(ca_key, ca_cert, crl, 30)

    crl2 = sysca.CRLInfo(load=crlobj)
    crl2obj = sysca.create_x509_crl(ca_key, ca_cert, crl2, 30)

    lst1 = dump_crl(crl2)
    lst2 = dump_crl(crl2obj)
    assert lst1 == lst2
    assert lst1 == [
        "CRL Scope: all",
        "CRL Number: 0a",
        "Last update: DT",
        "Next update: DT",
        "Signature: ecdsa-with-SHA256",
        "Issuer Name: CN = DirectCrlCA",
        "Authority Key Identifier: KeyID",
        "Revoked certificate:",
        "  Serial: SN",
        "  Revocation Date: DT",
        "  Invalidity Date: DT",
        "  Issuer GNames: dn:/CN=DirectCrlCA/",
        "Revoked certificate:",
        "  Serial: SN",
        "  Revocation Date: DT",
        "  Reason: key_compromise",
        "  Issuer GNames: dn:/CN=DirectCrlCA/",
        "Revoked certificate:",
        "  Serial: SN",
        "  Revocation Date: DT",
        "  Issuer GNames: dn:/CN=DirectCrlCA/",
    ]


def test_indirect_items() -> None:
    if not HAS_DPOINT:
        return
    # create ca key and cert
    ca_key, ca_cert = new_root(subject="CN=IndirectCA", alt_names="dn:CN=IndAlt")
    subca1_key, subca1_cert = new_cert(ca_key, ca_cert, ca=True,
                                       subject="CN=SubCa1", alt_names="dn:CN=SubAlt1",)
    subca2_key, subca2_cert = new_cert(ca_key, ca_cert, ca=True,
                                       subject="/CN=SubCa2/", alt_names="dn:CN=SubAlt2")

    key1, cert1 = new_cert(ca_key, ca_cert, subject={"CN": "k1"})
    key2, cert2 = new_cert(subca1_key, subca1_cert, subject={"CN": "k2"})
    key3, cert3 = new_cert(subca1_key, subca1_cert, subject={"CN": "k3"})
    key4, cert4 = new_cert(subca2_key, subca2_cert, subject={"CN": "k4"})
    key5, cert5 = new_cert(subca2_key, subca2_cert, subject={"CN": "k5"})
    key6, cert6 = new_cert(ca_key, ca_cert, subject={"CN": "k6"})
    key7, cert7 = new_cert(ca_key, ca_cert, subject={"CN": "k7"})

    crl = sysca.CRLInfo(crl_number=10, indirect_crl=True)
    idate = datetime(2001, 10, 18, 21, 59, 59, tzinfo=timezone.utc)
    crl.add_certificate(cert1, reason="remove_from_crl", invalidity_date=idate)
    crl.add_certificate(cert2, reason="ca_compromise")
    crl.add_certificate(cert3, reason="certificate_hold")
    crl.add_certificate(cert4, reason="privilege_withdrawn")
    crl.add_certificate(cert5, reason="superseded")
    crl.add_certificate(cert6, reason="affiliation_changed")
    crl.add_certificate(cert7, reason="cessation_of_operation")

    crlobj = sysca.create_x509_crl(ca_key, ca_cert, crl, 30)
    crl2obj = sysca.create_x509_crl(ca_key, ca_cert, crlobj, 30)
    crl2 = sysca.CRLInfo(load=crl2obj)
    assert crl2.indirect_crl is True
    assert crl2.revoked_list[0].invalidity_date == idate
    assert crl2.revoked_list[0].serial_number == cert1.serial_number
    assert crl2.revoked_list[0].issuer_gnames == ["dn:/CN=IndirectCA/", "dn:/CN=IndAlt/"]
    assert crl2.revoked_list[1].serial_number == cert2.serial_number
    assert crl2.revoked_list[1].issuer_gnames == ["dn:/CN=SubCa1/", "dn:/CN=SubAlt1/"]
    assert crl2.revoked_list[2].serial_number == cert3.serial_number
    assert crl2.revoked_list[2].issuer_gnames == ["dn:/CN=SubCa1/", "dn:/CN=SubAlt1/"]
    assert crl2.revoked_list[3].serial_number == cert4.serial_number
    assert crl2.revoked_list[3].issuer_gnames == ["dn:/CN=SubCa2/", "dn:/CN=SubAlt2/"]
    assert crl2.revoked_list[4].serial_number == cert5.serial_number
    assert crl2.revoked_list[4].issuer_gnames == ["dn:/CN=SubCa2/", "dn:/CN=SubAlt2/"]
    assert crl2.revoked_list[5].serial_number == cert6.serial_number
    assert crl2.revoked_list[5].issuer_gnames == ["dn:/CN=IndirectCA/", "dn:/CN=IndAlt/"]
    assert crl2.revoked_list[6].serial_number == cert7.serial_number
    assert crl2.revoked_list[6].issuer_gnames == ["dn:/CN=IndirectCA/", "dn:/CN=IndAlt/"]


def test_scope_items() -> None:
    if not HAS_DPOINT:
        return
    # create ca key and cert
    ca_key, ca_cert = new_root(subject="CN=IndirectCA", alt_names="dn:CN=IndAlt")

    crl = sysca.CRLInfo(crl_number=10, crl_scope="x")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        sysca.create_x509_crl(ca_key, ca_cert, crl, 30)

    scopes: List[sysca.CRLScope] = ["ca", "user", "attr", "all"]
    for scope in scopes:
        crl = sysca.CRLInfo(crl_number=10, crl_scope=scope)
        crlobj = sysca.create_x509_crl(ca_key, ca_cert, crl, 30)
        crl2obj = sysca.create_x509_crl(ca_key, ca_cert, crlobj, 30)
        crl2 = sysca.CRLInfo(load=crl2obj)
        assert crl2.indirect_crl is False
        assert crl2.crl_scope == scope

    rs = ["ca_compromise", "key_compromise"]
    crl = sysca.CRLInfo(crl_number=10, only_some_reasons=rs)
    crlobj = sysca.create_x509_crl(ca_key, ca_cert, crl, 30)
    crl2obj = sysca.create_x509_crl(ca_key, ca_cert, crlobj, 30)
    crl2 = sysca.CRLInfo(load=crl2obj)
    assert crl2.indirect_crl is False
    assert crl2.only_some_reasons == frozenset(rs)

    urls = ["uri:http://f.co", "uri:https://s.co"]
    crl = sysca.CRLInfo(crl_number=10, full_methods=urls)
    crlobj = sysca.create_x509_crl(ca_key, ca_cert, crl, 30)
    crl2obj = sysca.create_x509_crl(ca_key, ca_cert, crlobj, 30)
    crl2 = sysca.CRLInfo(load=crl2obj)
    assert crl2.indirect_crl is False
    assert crl2.full_methods == urls


@pytest.mark.skipif(not HAVE_PSS, reason="Does not support RSA-PSS")
def test_crl_rsa_pss() -> None:
    key = sysca.valid_issuer_private_key(sysca.load_key(demo_fn("rsa1.key")))
    pss_info = sysca.CertInfo(subject="CN=pss", ca=True, rsa_pss=True, load=key)
    nopss_info = sysca.CertInfo(subject="CN=nopss", ca=True, load=key)

    pss_cert = sysca.create_x509_cert(key, key.public_key(), pss_info, pss_info, days=5)
    nopss_cert = sysca.create_x509_cert(key, key.public_key(), nopss_info, nopss_info, days=5)

    crl = sysca.CRLInfo()
    crl.add_serial_number(2)

    pss_crl = sysca.create_x509_crl(key, pss_cert, crl, 10)
    assert pss_crl.signature_algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS

    nopss_crl = sysca.create_x509_crl(key, nopss_cert, crl, 10)
    assert nopss_crl.signature_algorithm_oid != SignatureAlgorithmOID.RSASSA_PSS

    assert sysca.CRLInfo(load=pss_crl).rsa_pss
    assert not sysca.CRLInfo(load=nopss_crl).rsa_pss

