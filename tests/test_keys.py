
import os
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from helpers import demo_data, demo_fn, new_root

import sysca.api as sysca

EC_KEYS = ["ec"] + ["ec:" + n for n in sysca.get_ec_curves()]
RSA_KEYS = ["rsa", "rsa:2048"]


def process_write(key: sysca.AllPrivateKeyTypes) -> None:
    fd, name = tempfile.mkstemp()
    os.close(fd)
    try:
        # ec key, unencrypted
        with open(name, "w") as f:
            f.write(sysca.serialize(key))
        key2 = sysca.load_key(name)
        assert sysca.same_pubkey(key, key2)

        # ec key, encrypted
        with open(name, "w") as f:
            f.write(sysca.serialize(key, password="password"))
        with pytest.raises(TypeError):
            sysca.load_key(name)
        with pytest.raises(ValueError):
            sysca.load_key(name, "wrong")
        key2 = sysca.load_key(name, "password")
        assert sysca.same_pubkey(key, key2)
    finally:
        os.unlink(name)


def process_crl(ca_key: sysca.IssuerPrivateKeyTypes, ca_info: sysca.CertInfo) -> None:
    crl = sysca.CRLInfo()
    crl.delta_crl_number = 9
    crl.crl_number = 10

    crlobj = sysca.create_x509_crl(ca_key, ca_info, crl, days=30)

    crl2 = sysca.CRLInfo(load=crlobj)
    crl2obj = sysca.create_x509_crl(ca_key, ca_info, crl2, days=30)

    data = sysca.serialize(crl2obj)
    fd, name = tempfile.mkstemp()
    os.close(fd)
    try:
        # ec key, unencrypted
        with open(name, "w") as f:
            f.write(data)
        crlobj4 = sysca.load_crl(name)
        crl4 = sysca.CRLInfo(load=crlobj4)
        assert crl4.delta_crl_number == crl.delta_crl_number
    finally:
        os.unlink(name)


def process_ktype(ktype: str) -> None:
    # create ca key and cert
    ca_key = sysca.new_key(ktype)
    ca_pub_key = ca_key.public_key()
    ca_info = sysca.CertInfo(subject={"CN": "TestCA"}, ca=True)
    ca_csrobj = sysca.create_x509_req(ca_key, ca_info)
    ca_certobj = sysca.create_x509_cert(ca_key, ca_pub_key, ca_csrobj, ca_csrobj, 365)
    ca_cert = sysca.CertInfo(load=ca_certobj)

    # srv key
    srv_key = sysca.new_key(ktype)
    srv_info = sysca.CertInfo(subject={"CN": "Server1"}, usage=["server"])
    srv_req = sysca.create_x509_req(srv_key, srv_info)

    # ca signs
    srv_info2 = sysca.CertInfo(load=srv_req)
    srv_pub = srv_req.public_key()
    srv_certobj = sysca.create_x509_cert(ca_key, srv_pub, srv_info2, ca_cert, 365)
    srv_cert = sysca.CertInfo(load=srv_certobj)
    assert "server" in srv_cert.usage

    def drop(m: str) -> None:
        pass
    srv_cert.show(drop)

    # test same key
    assert sysca.same_pubkey(ca_key, ca_key)
    assert not sysca.same_pubkey(ca_key, srv_key)

    process_write(ca_key)

    process_crl(ca_key, ca_cert)


def test_rsa() -> None:
    for ktype in RSA_KEYS:
        process_ktype(ktype)


def test_ec() -> None:
    for ktype in EC_KEYS:
        process_ktype(ktype)


def test_unsafe() -> None:
    with pytest.raises(ValueError):
        sysca.new_ec_key("some")

    with pytest.raises(ValueError):
        sysca.new_ec_key("secp192r1")
    with pytest.raises(ValueError):
        sysca.new_rsa_key(2500)
    with pytest.raises(ValueError):
        sysca.new_dsa_key(2500)

    sysca.set_unsafe(True)
    assert sysca.new_ec_key("secp192r1") is not None
    assert sysca.new_rsa_key(2500) is not None
    sysca.set_unsafe(False)

    with pytest.raises(ValueError):
        sysca.get_curve_for_name("secp192r1")
    with pytest.raises(ValueError):
        sysca.new_rsa_key(2500)
    with pytest.raises(ValueError):
        sysca.new_dsa_key(2500)


def test_invalid_ktype() -> None:
    with pytest.raises(ValueError):
        sysca.new_key("x")
    with pytest.raises(ValueError):
        sysca.new_key("x:x")


def ssh_kformat(prefix: str, password: str, tmp_key: str) -> None:
    sfx = "nopsw"
    if password:
        sfx = "psw"
    kfn = demo_fn("%s-%s.key" % (prefix, sfx))

    # load ssh private key
    sk = sysca.valid_issuer_private_key(sysca.load_file_any(kfn, password))
    with open(kfn + ".pub", "rb") as f:
        pktxt = f.read()
    pktxt2 = sk.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    assert pktxt2 == pktxt[:len(pktxt2)]

    # serialize ssh public key
    pktxt3 = sysca.serialize(sk.public_key(), "ssh").encode("ascii").strip()
    assert pktxt2 == pktxt3

    # load ssh public key
    pkload = sysca.load_ssh_public_key(pktxt2)
    pkloadtxt = pkload.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    assert pkloadtxt == pktxt2

    # serialize ssh private key, try test autodetection
    skpem = sysca.serialize(sk, "ssh", password)
    with open(tmp_key, "w") as f:
        f.write(skpem)
    sk2 = sysca.valid_issuer_private_key(sysca.load_file_any(tmp_key, password))
    pktxt4 = sk2.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    assert pktxt4 == pktxt2

    if "ed25519" not in prefix:
        ssl_priv_pem = sysca.serialize(sk, "ssl", password)
        with open(tmp_key, "w") as f:
            f.write(ssl_priv_pem)
        ssl_sk = sysca.valid_issuer_private_key(sysca.load_file_any(tmp_key, password))
        pktxt5 = ssl_sk.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        assert pktxt5 == pktxt4
    else:
        if password:
            with pytest.raises(ValueError):
                sysca.serialize(sk, "raw", password)
            with pytest.raises(ValueError):
                sysca.serialize(sk.public_key(), "raw", password)
        else:
            raw1 = sysca.serialize(sk, "raw", password)
            assert len(raw1) == 32
            raw2 = sysca.serialize(sk.public_key(), "raw", password)
            assert len(raw2) == 32


def test_ssh_old(tmp_path: Path) -> None:
    tmp_key = str(tmp_path / "test.key")
    ssh_kformat("ssh/old-ecdsa", "", tmp_key)
    ssh_kformat("ssh/old-ecdsa", "password", tmp_key)
    ssh_kformat("ssh/old-rsa", "", tmp_key)
    ssh_kformat("ssh/old-rsa", "password", tmp_key)


def test_ssh_eddsa(tmp_path: Path) -> None:
    tmp_key = str(tmp_path / "test.key")
    ssh_kformat("ssh/new-ed25519", "", tmp_key)
    ssh_kformat("ssh/new-ed25519", "password", tmp_key)


def test_ssh_new(tmp_path: Path) -> None:
    tmp_key = str(tmp_path / "test.key")
    ssh_kformat("ssh/new-rsa", "", tmp_key)
    ssh_kformat("ssh/new-rsa", "password", tmp_key)
    ssh_kformat("ssh/new-ecdsa", "", tmp_key)
    ssh_kformat("ssh/new-ecdsa", "password", tmp_key)


def process_ssh_cert(kfn: str) -> None:
    pk = sysca.load_file_any(demo_fn(kfn + "-cert.pub"))
    pkx = sysca.valid_issuer_public_key(pk)
    pktxt = pkx.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    pktxt2 = demo_data(kfn + ".pub")
    assert pktxt == pktxt2[:len(pktxt)]


def test_ssh_certs() -> None:
    kfiles = [
        "ssh-ca/ecdsa-user.key",
        "ssh-ca/rsa-sha1-user.key",
        "ssh-ca/rsa-sha256-user.key",
        "ssh-ca/rsa-sha512-user.key",
    ]
    for kfn in kfiles:
        process_ssh_cert(kfn)


def test_ssh_certs_eddsa(tmp_path: Path) -> None:
    process_ssh_cert("ssh-ca/ed25519-user.key")


def test_serialize() -> None:
    with pytest.raises(TypeError):
        sysca.serialize(object(), "pem")  # type: ignore[call-overload]
    sk, cert = new_root(subject="CN=errtests")
    with pytest.raises(ValueError):
        sysca.serialize(sk.public_key(), "ssl")
    with pytest.raises(ValueError):
        sysca.serialize(sk, "x")  # type: ignore[call-overload]
    with pytest.raises(ValueError, match="private"):
        sysca.serialize(cert, "ssh")

