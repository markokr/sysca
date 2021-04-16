
import binascii
import os.path

from sysca import api as sysca

_FDIR = os.path.join(os.path.dirname(__file__), "files")


def demo_fn(basename):
    return os.path.join(_FDIR, basename)


def demo_data(basename, mode="rb"):
    if "b" in mode:
        with open(demo_fn(basename), mode) as f:
            return f.read().replace(b"\r\n", b"\n")
    with open(demo_fn(basename), mode, encoding="utf8") as f:
        return f.read().replace("\r\n", "\n")


def demo_raw(basename):
    return depem(demo_data(basename))


def depem(data):
    if isinstance(data, str):
        data = data.encode("ascii")
    p1 = data.find(b"-----\n") + 6
    p2 = data.find(b"\n-----", p1)
    return binascii.a2b_base64(data[p1:p2])


def new_root(ktype="ec", **kwargs):
    ca_key = sysca.new_key(ktype)
    ca_info = sysca.CertInfo(ca=True, load=ca_key, **kwargs)
    ca_cert = sysca.create_x509_cert(ca_key, ca_key.public_key(), ca_info, ca_info, 365)
    return ca_key, ca_cert


def new_cert(ca_key, ca_info, ktype="ec", **kwargs):
    key = sysca.new_key(ktype)
    info = sysca.CertInfo(load=key.public_key(), **kwargs)
    cert = sysca.create_x509_cert(ca_key, key.public_key(), info, ca_info, 365)
    return key, cert
