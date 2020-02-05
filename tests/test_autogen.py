
#import pytest

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from sysca.api import autogen_config_file

from helpers import demo_fn


def test_autogen():
    def load_ca(name):
        assert name in ("CA1", "CA2")
        keyfn = demo_fn("ec-p256.key")
        crtfn = demo_fn("ec-p256-ca.crt")
        return (keyfn, crtfn)

    conf = demo_fn("autogen/autogen.ini")
    res = autogen_config_file(conf, load_ca, {})

    k0, c0 = res["client_minimal"][:2]
    assert isinstance(c0, x509.Certificate)
    assert isinstance(k0, ec.EllipticCurvePrivateKey)

    k1, c1 = res["client_standard"][:2]
    assert isinstance(c1, x509.Certificate)
    assert isinstance(k1, ec.EllipticCurvePrivateKey)

    k2, c2 = res["client_special"][:2]
    assert isinstance(c2, x509.Certificate)
    assert isinstance(k2, rsa.RSAPrivateKey)

