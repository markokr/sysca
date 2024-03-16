
import binascii
import os.path
from typing import Any, Tuple, Union

import cryptography
from cryptography import x509

from sysca import api as sysca

_FDIR = os.path.join(os.path.dirname(__file__), "files")

HAVE_PSS = int(cryptography.__version__.split(".", maxsplit=1)[0]) >= 42


def demo_fn(basename: str) -> str:
    return os.path.join(_FDIR, basename)


def demo_bytes(basename: str) -> bytes:
    with open(demo_fn(basename), "rb") as f:
        return f.read().replace(b"\r\n", b"\n")


def demo_data(basename: str) -> str:
    return demo_bytes(basename).decode()


def demo_raw(basename: str) -> bytes:
    return depem(demo_data(basename))


def depem(data: Union[str, bytes]) -> bytes:
    if isinstance(data, str):
        data = data.encode("ascii")
    p1 = data.find(b"-----\n") + 6
    p2 = data.find(b"\n-----", p1)
    return binascii.a2b_base64(data[p1:p2])


def new_root(ktype: str = "ec", **kwargs: Any) -> Tuple[sysca.IssuerPrivateKeyTypes, x509.Certificate]:
    ca_key = sysca.new_key(ktype)
    ca_info = sysca.CertInfo(ca=True, load=ca_key, **kwargs)
    ca_cert = sysca.create_x509_cert(ca_key, ca_key.public_key(), ca_info, ca_info, 365)
    return ca_key, ca_cert


def new_cert(ca_key: sysca.IssuerPrivateKeyTypes,
             ca_info: Union[sysca.CertInfo, x509.Certificate],
             ktype: str = "ec",
             **kwargs: Any,
             ) -> Tuple[sysca.IssuerPrivateKeyTypes, x509.Certificate]:
    key = sysca.new_key(ktype)
    info = sysca.CertInfo(load=key.public_key(), **kwargs)
    cert = sysca.create_x509_cert(ca_key, key.public_key(), info, ca_info, 365)
    return key, cert

