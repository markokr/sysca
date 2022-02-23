
import sys
import os.path

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from sysca.tool import run_sysca
from sysca.api import set_unsafe, CertInfo
from sysca.ssh import HAVE_SSH

from helpers import demo_fn, demo_raw, demo_data


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


def test_no_command(capsys):
    assert sysca() >= 1
    res = capsys.readouterr()
    assert "command" in res.err


def test_help(capsys):
    assert sysca("--help") == 0
    res = capsys.readouterr()
    assert "unsafe" in res.out


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
    assert sysca("list", "ec-curves") == 0
    res = capsys.readouterr()
    assert "secp256r1" in res.out
    assert "secp192r1" not in res.out

    assert sysca("--unsafe", "list", "ec-curves") == 0
    res = capsys.readouterr()
    assert "secp256r1" in res.out
    assert "secp192r1" in res.out


def test_show(capsys):
    files = [
        "ec-p256-ca.crt", "ec-p256-ca.csr", "ec-p256-ca.crl",
        "letsencrypt-org.crt", "ec2-rich.csr", "ec2-rich.crt",
    ]
    for fn in files:
        assert sysca("show", demo_fn(fn)) == 0
        res = capsys.readouterr()
        assert res.out == demo_data(fn + ".out", "r")

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

    assert sysca("request", "--CA", "--usage=client",
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


def test_sign_reset(capsys):
    assert 0 == sysca("sign",
                      "--ca-key", demo_fn("ec-p256.key"),
                      "--ca-info", demo_fn("ec-p256-ca.crt"),
                      "--request", demo_fn("ec-p256-ca.csr"),
                      "--serial-number=2",
                      "--days=300",
                      ) == 0
    res = capsys.readouterr()
    assert "CERTIFICATE" in res.out
    cert1 = res.out.encode("utf8")

    assert 0 == sysca("sign", "--reset",
                      "--usage=client", "--subject=/CN=override/",
                      "--ca-key", demo_fn("ec-p256.key"),
                      "--ca-info", demo_fn("ec-p256-ca.crt"),
                      "--request", demo_fn("ec-p256-ca.csr"),
                      "--serial-number=3",
                      "--days=10",
                      ) == 0
    res = capsys.readouterr()
    assert "CERTIFICATE" in res.out
    cert2 = res.out.encode("utf8")

    obj1 = x509.load_pem_x509_certificate(cert1, default_backend())
    obj2 = x509.load_pem_x509_certificate(cert2, default_backend())
    info1 = CertInfo(load=obj1)
    info2 = CertInfo(load=obj2)
    assert info1.ca is True
    assert info2.ca is False
    assert info1.serial_number == 2 and info2.serial_number == 3
    assert info1.subject == (("CN", "ecreq"),)
    assert info2.subject == (("CN", "override"),)
    assert "key_cert_sign" in info1.usage and "key_cert_sign" not in info2.usage
    assert "client" in info2.usage and "client" not in info1.usage


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

    assert 0 == sysca("selfsign",
                      "--key", demo_fn("ec-p256.key"),
                      "--days", "2050",
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

    assert 0 == sysca("export", demo_fn("ec-p256.key"), "--outform=ssl")
    res = capsys.readouterr()
    assert " EC PRIVATE " in res.out

    assert 0 == sysca("export", demo_fn("rsa1.key"), "--outform=ssl")
    res = capsys.readouterr()
    assert " RSA PRIVATE " in res.out

    if HAVE_SSH:
        assert 0 == sysca("export", demo_fn("ec-p256.key"), "--outform=ssh")
        res = capsys.readouterr()
        assert " OPENSSH PRIVATE " in res.out

        assert 0 == sysca("export", demo_fn("rsa1.key"), "--outform=ssh")
        res = capsys.readouterr()
        assert " OPENSSH PRIVATE " in res.out


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


def test_export_pub(capsys):
    assert 0 == sysca("export-pub", demo_fn("ec-p256-ca.csr"))
    res = capsys.readouterr()
    assert res.out == demo_data("ec-p256.pub", "r")

    assert 0 == sysca("export-pub", demo_fn("ec-p256-ca.crt"))
    res = capsys.readouterr()
    assert res.out == demo_data("ec-p256.pub", "r")

    assert 0 == sysca("export-pub", demo_fn("ec-p256.pub"))
    res = capsys.readouterr()
    assert res.out == demo_data("ec-p256.pub", "r")

    if HAVE_SSH:
        assert 0 == sysca("export-pub", demo_fn("ec-p256.pub"), "--outform=ssh")
        res = capsys.readouterr()
        assert "ecdsa-sha2-nistp256" in res.out

    assert 0 == sysca("export-pub", demo_fn("ec-p256.key"))
    res = capsys.readouterr()
    assert res.out == demo_data("ec-p256.pub", "r")

    assert 0 != sysca("export-pub", demo_fn("ec-p256-ca.crl"))
    res = capsys.readouterr()

    assert 0 != sysca("export-pub", demo_fn("password.txt"))
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


def test_autogen(capsys, tmp_path):
    dst = str(tmp_path)
    err = sysca("autogen", "--text",
                "--ca-dir", demo_fn("autogen"),
                "--out-dir", dst,
                demo_fn("autogen/autogen.ini"))
    res = capsys.readouterr()
    assert err == 0
    assert res
    assert os.path.isfile(os.path.join(dst, "client_minimal.key"))
    assert os.path.isfile(os.path.join(dst, "client_minimal.crt"))
    assert os.path.isfile(os.path.join(dst, "client_standard.key"))
    assert os.path.isfile(os.path.join(dst, "client_standard.crt"))
    assert os.path.isfile(os.path.join(dst, "client_special.key"))
    assert os.path.isfile(os.path.join(dst, "client_special.crt"))

