
import sys
import os.path
import binascii
from datetime import datetime

import pytest

from sysca.tool import run_sysca
from sysca.keys import set_unsafe

FDIR = os.path.join(os.path.dirname(__file__), "files")


def sysca(*args):
    try:
        try:
            run_sysca(args)
        finally:
            set_unsafe(False)
        return 0
    except SystemExit as ex:
        return int(ex.code)
    except Exception as ex:
        sys.stderr.write(str(ex) + "\n")
        return 1


def demo_fn(basename):
    return os.path.join(FDIR, basename)


def demo_data(basename, mode="rb"):
    with open(demo_fn(basename), mode) as f:
        return f.read()


def demo_raw(basename):
    return depem(demo_data(basename))


def depem(data):
    if isinstance(data, str):
        data = data.encode("ascii")
    p1 = data.find(b"-----\n") + 6
    p2 = data.find(b"\n-----", p1)
    return binascii.a2b_base64(data[p1:p2])


def test_no_command(capsys):
    assert sysca() >= 1
    res = capsys.readouterr()
    assert "command" in res.err


def test_help(capsys):
    assert sysca("--help") == 0
    res = capsys.readouterr()
    assert "optional" in res.out


def test_version(capsys):
    assert sysca("--version") == 0
    res = capsys.readouterr()
    assert "cryptography" in res.out


def test_newkey(capsys):
    assert sysca("new-key") == 0
    res = capsys.readouterr()
    assert "BEGIN PRIVATE KEY" in res.out
    assert "New" in res.err

    assert sysca("-q", "new-key", "rsa") == 0
    res = capsys.readouterr()
    assert "BEGIN PRIVATE KEY" in res.out
    assert "New" not in res.err

    assert sysca("new-key", "xx") >= 1
    res = capsys.readouterr()
    assert "BEGIN" not in res.out

    assert sysca("new-key", "ec", "rsa") >= 1
    res = capsys.readouterr()
    assert "BEGIN" not in res.out

    assert sysca("new-key", "ec:secp192r1") >= 1
    res = capsys.readouterr()
    assert "BEGIN" not in res.out


def test_newkey_openssl(capsys):
    assert sysca("new-key", "--text") == 0
    res = capsys.readouterr()
    assert "BEGIN PRIVATE KEY" in res.out

    assert sysca("export", demo_fn("ec-p256.pub"), "--text") == 0
    res = capsys.readouterr()
    assert "BEGIN PUBLIC KEY" in res.out

    assert sysca("export", "--text", demo_fn("ec-p256.pub")) == 0
    res = capsys.readouterr()
    assert "BEGIN PUBLIC KEY" in res.out


def test_list_curves(capsys):
    assert sysca("list-curves") == 0
    res = capsys.readouterr()
    assert "secp256r1" in res.out
    assert "secp192r1" not in res.out

    assert sysca("--unsafe", "list-curves") == 0
    res = capsys.readouterr()
    assert "secp256r1" in res.out
    assert "secp192r1" in res.out


def test_show(capsys):
    assert sysca("show", demo_fn("letsencrypt-org.crt")) == 0
    res = capsys.readouterr()
    assert res.out == demo_data("letsencrypt-org.crt.out", "r")

    assert sysca("show", demo_fn("password.txt")) >= 1
    capsys.readouterr()

    assert sysca("show", demo_fn("ec-p256.pub")) == 0
    capsys.readouterr()

    assert sysca("show", demo_fn("ec-p256.key")) == 0
    capsys.readouterr()

    assert sysca("show", demo_fn("ec-p256.psw.key")) >= 1
    capsys.readouterr()

    assert sysca("show", demo_fn("ec-p256.psw.key"), "--password-file", demo_fn("password.txt")) == 0
    capsys.readouterr()

    assert sysca("show", demo_fn("ec-p256-ca.crt")) == 0
    res = capsys.readouterr()
    assert res.out == demo_data("ec-p256-ca.crt.out", "r")

    assert sysca("show", demo_fn("ec-p256-ca.csr")) == 0
    res = capsys.readouterr()
    assert res.out == demo_data("ec-p256-ca.csr.out", "r")

    assert sysca("show", demo_fn("ec-p256-ca.crl")) == 0
    res = capsys.readouterr()
    assert res.out == demo_data("ec-p256-ca.crl.out", "r")


def test_request(capsys):
    assert sysca("request",
                 "--key", demo_fn("ec-p256.key"),
                 "--subject", "CN=foo") == 0
    res = capsys.readouterr()
    assert "REQUEST" in res.out

    assert sysca("request", "--key", demo_fn("ec-p256.psw.key"),
                 "--subject", "CN=foo") >= 1
    res = capsys.readouterr()
    assert "REQUEST" not in res.out

    assert sysca("request",
                 "--key", demo_fn("ec-p256.psw.key"),
                 "--password-file", demo_fn("password.txt"),
                 "--subject", "CN=foo") == 0
    res = capsys.readouterr()
    assert "REQUEST" in res.out


def test_request_openssl(capsys):
    assert sysca("request", "--text",
                 "--key", demo_fn("ec-p256.key"),
                 "--subject", "CN=foo") == 0
    res = capsys.readouterr()
    assert "REQUEST" in res.out


def test_sign(capsys):
    assert 0 == sysca("sign",
                      "--ca-key", demo_fn("ec-p256.key"),
                      "--ca-info", demo_fn("ec-p256-ca.csr"),
                      "--request", demo_fn("ec-p256-ca.csr"),
                      "--days=300",
                      ) == 0
    res = capsys.readouterr()
    assert "CERTIFICATE" in res.out


def test_sign_openssl(capsys):
    assert 0 == sysca("sign", "--text",
                      "--ca-key", demo_fn("ec-p256.key"),
                      "--ca-info", demo_fn("ec-p256-ca.csr"),
                      "--request", demo_fn("ec-p256-ca.csr"),
                      "--days=300",
                      ) == 0
    res = capsys.readouterr()
    assert "CERTIFICATE" in res.out


def test_selfsign(capsys):
    assert 0 == sysca("selfsign",
                      "--key", demo_fn("ec-p256.key"),
                      "--days", "200",
                      "--subject", "CN=foo")
    res = capsys.readouterr()
    assert "CERTIFICATE" in res.out

    assert 0 == sysca("selfsign",
                      "--key", demo_fn("ec-p256.key"),
                      "--not-valid-after", "2050-11-01",
                      "--subject", "CN=foo")
    res = capsys.readouterr()
    assert "CERTIFICATE" in res.out


def test_export(capsys):
    assert 0 == sysca("export", demo_fn("ec-p256-ca.csr"))
    res = capsys.readouterr()
    assert res.out == demo_data("ec-p256-ca.csr", "r")

    assert 0 == sysca("export", demo_fn("ec-p256-ca.crt"))
    res = capsys.readouterr()
    assert res.out == demo_data("ec-p256-ca.crt", "r")

    assert 0 == sysca("export", demo_fn("ec-p256.pub"))
    res = capsys.readouterr()
    assert res.out == demo_data("ec-p256.pub", "r")

    assert 0 == sysca("export", demo_fn("ec-p256.key"))
    res = capsys.readouterr()
    assert res.out == demo_data("ec-p256.key", "r")

    assert 0 == sysca("export", demo_fn("ec-p256-ca.crl"))
    res = capsys.readouterr()
    assert res.out == demo_data("ec-p256-ca.crl", "r")


def test_export_der(capsys, tmp_path):
    dst = str(tmp_path / "tmp.bin")
    assert 0 == sysca("export", demo_fn("ec-p256-ca.crt"), "--outform=DER", "--out", dst)
    res = capsys.readouterr()
    assert open(dst, "rb").read() == demo_raw("ec-p256-ca.crt")

    assert 0 == sysca("export", demo_fn("ec-p256-ca.csr"), "--outform=DER", "--out", dst)
    res = capsys.readouterr()
    assert "-----" not in res.out
    assert open(dst, "rb").read() == demo_raw("ec-p256-ca.csr")

    assert 0 == sysca("export", "--outform=DER", demo_fn("ec-p256-ca.crl"), "--out", dst)
    res = capsys.readouterr()
    assert open(dst, "rb").read() == demo_raw("ec-p256-ca.crl")

    assert 1 <= sysca("export", "--outform=DER", demo_fn("ec-p256-ca.crl"), "--text")
    res = capsys.readouterr()


def test_export_pubkey(capsys):
    assert 0 == sysca("export-pubkey", demo_fn("ec-p256-ca.csr"))
    res = capsys.readouterr()
    assert res.out == demo_data("ec-p256.pub", "r")

    assert 0 == sysca("export-pubkey", demo_fn("ec-p256-ca.crt"))
    res = capsys.readouterr()
    assert res.out == demo_data("ec-p256.pub", "r")

    assert 0 == sysca("export-pubkey", demo_fn("ec-p256.pub"))
    res = capsys.readouterr()
    assert res.out == demo_data("ec-p256.pub", "r")

    assert 0 == sysca("export-pubkey", demo_fn("ec-p256.key"))
    res = capsys.readouterr()
    assert res.out == demo_data("ec-p256.pub", "r")

    assert 0 != sysca("export-pubkey", demo_fn("ec-p256-ca.crl"))
    res = capsys.readouterr()

    assert 0 != sysca("export-pubkey", demo_fn("password.txt"))
    res = capsys.readouterr()


def test_update_crl(capsys):
    assert 0 == sysca("update-crl",
                      "--ca-key", demo_fn("ec-p256.key"),
                      "--ca-info", demo_fn("ec-p256-ca.crt"),
                      "--crl-number", "2",
                      "--delta-crl-number", "2",
                      "--days", "20",
                      "--revoke-serials", "33")
    res = capsys.readouterr()
    assert "CRL" in res.out

    assert 0 == sysca("update-crl",
                      "--ca-key", demo_fn("ec-p256.key"),
                      "--ca-info", demo_fn("ec-p256-ca.crt"),
                      "--crl-number=2",
                      "--last-update", "2005-01-01",
                      "--next-update", "2050-03-03",
                      "--issuer-urls", "http://issuer-url",
                      "--delta-crl-urls", "http://delta-url",
                      "--reason=aa_compromise",
                      "--revoke-certs", demo_fn("ec-p256-ca.crt"))
    res = capsys.readouterr()
    assert "CRL" in res.out

    assert 0 == sysca("update-crl",
                      "--crl", demo_fn("ec-p256-ca.crl"),
                      "--ca-key", demo_fn("ec-p256.key"),
                      "--ca-info", demo_fn("ec-p256-ca.crt"),
                      "--crl-number=3",
                      "--last-update", "2005-01-01",
                      "--next-update", "2050-03-03",
                      "--issuer-urls", "http://issuer-url",
                      "--delta-crl-urls", "http://delta-url",
                      "--reason=aa_compromise",
                      "--revoke-certs", demo_fn("ec-p256-ca.crt"))
    res = capsys.readouterr()
    assert "CRL" in res.out


def test_update_crl_openssl(capsys):
    assert 0 == sysca("update-crl", "--text",
                      "--ca-key", demo_fn("ec-p256.key"),
                      "--ca-info", demo_fn("ec-p256-ca.crt"),
                      "--crl-number", "2",
                      "--delta-crl-number", "2",
                      "--days", "20",
                      "--revoke-serials", "33")
    res = capsys.readouterr()
    assert "X509 CRL" in res.out


def test_show_openssl(capsys):
    assert 0 == sysca("show", demo_fn("ec-p256-ca.csr"), "--text")
    res = capsys.readouterr()
    assert "REQUEST" in res.out

    assert 0 == sysca("show", demo_fn("ec-p256-ca.crt"), "--text")
    res = capsys.readouterr()
    assert "CERTIFICATE" in res.out

    assert 0 == sysca("show", demo_fn("ec-p256-ca.crl"), "--text")
    res = capsys.readouterr()
    assert "X509 CRL" in res.out
