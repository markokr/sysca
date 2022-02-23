"""File reading
"""

import os.path
import re
import subprocess
from typing import Mapping, Optional, Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key, load_der_public_key,
    load_pem_private_key, load_pem_public_key,
)

from .compat import PRIVKEY_TYPES, PUBKEY_TYPES
from .formats import as_password
from .ssh import load_ssh_private_key, load_ssh_public_key

__all__ = (
    "load_gpg_file", "load_password", "is_pem_data",
    "autodetect_data", "autodetect_filename", "autodetect_file",
    "load_file_any",
)


def load_gpg_file(fn: str, check_ext: bool = True) -> bytes:
    """Decrypt file if .gpg extension.
    """
    if check_ext:
        ext = os.path.splitext(fn)[1].lower()
        if ext not in (".gpg", ".pgp"):
            return open(fn, "rb").read()

    cmd = ["gpg", "-q", "-d", "--batch", "--no-tty", fn]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
        out, err = p.communicate()
    log = err.decode("utf8", "replace").strip()
    if p.returncode != 0:
        raise Exception("gpg failed: %s" % log)

    # cannot say "you need to check signatures" to gpg...
    # if "Good signature" not in log:
    #    msg("%s: No signature found", fn)
    #    if log:
    #        msg(log)

    return out


def load_password(fn: str) -> Optional[bytes]:
    """Read password from potentially gpg-encrypted file.
    """
    if not fn:
        return None
    return load_gpg_file(fn).strip(b"\r\n")


def load_key(fn: str, psw: Optional[bytes] = None) -> PRIVKEY_TYPES:
    """Read private key, decrypt if needed.
    """
    if psw:
        if not isinstance(psw, bytes):
            psw = psw.encode("utf8")
    data = load_gpg_file(fn)
    if is_pem_data(data):
        key = load_pem_private_key(data, password=psw, backend=default_backend())
    else:
        key = load_der_private_key(data, password=psw, backend=default_backend())
    return key


def load_pub_key(fn: str) -> PUBKEY_TYPES:
    """Read public key file.
    """
    with open(fn, "rb") as f:
        data = f.read()
    if is_pem_data(data):
        return load_pem_public_key(data, default_backend())
    return load_der_public_key(data, default_backend())


def load_req(fn: str) -> x509.CertificateSigningRequest:
    """Read CSR file.
    """
    with open(fn, "rb") as f:
        data = f.read()
    if is_pem_data(data):
        return x509.load_pem_x509_csr(data, default_backend())
    return x509.load_der_x509_csr(data, default_backend())


def load_cert(fn: str) -> x509.Certificate:
    """Read CRT file.
    """
    with open(fn, "rb") as f:
        data = f.read()
    if is_pem_data(data):
        return x509.load_pem_x509_certificate(data, default_backend())
    return x509.load_der_x509_certificate(data, default_backend())


def load_crl(fn: str) -> x509.CertificateRevocationList:
    """Read CRL file.
    """
    with open(fn, "rb") as f:
        data = f.read()
    if is_pem_data(data):
        return x509.load_pem_x509_crl(data, default_backend())
    return x509.load_der_x509_crl(data, default_backend())


_bin_rc = re.compile(b"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def is_pem_data(data: bytes) -> bool:
    """Detect if data is textual.
    """
    return not _bin_rc.search(data)


# -- X.509 formats --
# CERTIFICATE
# CERTIFICATE REQUEST
# X509 CRL
# PUBLIC KEY
# PRIVATE KEY
# ENCRYPTED PRIVATE KEY
# -- other formats --
# OPENSSH PRIVATE KEY
# RSA PRIVATE KEY
# PGP PUBLIC KEY BLOCK
# PGP PRIVATE KEY BLOCK
# PGP MESSAGE
PEM_SUFFIXES: Mapping[bytes, str] = {
    b" CERTIFICATE": "crt",
    b" CRL": "crl",
    b" REQUEST": "csr",

    b" RSA PRIVATE KEY": "key",
    b" DSA PRIVATE KEY": "key",
    b" EC PRIVATE KEY": "key",
    b" OPENSSH PRIVATE KEY": "key-ssh",
    b" ENCRYPTED PRIVATE KEY": "key",
    b" PRIVATE KEY": "key",

    b" RSA PUBLIC KEY": "pub",
    b" DSA PUBLIC KEY": "pub",
    b" EC PUBLIC KEY": "pub",
    b" PUBLIC KEY": "pub",
    b" PGP MESSAGE": "key-gpg",
}


def autodetect_data(data: bytes) -> Optional[str]:
    """Relaxed autodetect, for "show".
    """
    words = b"(?: [A-Z][A-Z0-9]*)+"
    rc1 = re.compile(b"-----BEGIN(%s)-----" % words)
    rc2 = re.compile(b"-----END(%s)-----" % words)
    if not is_pem_data(data):
        return None
    m1 = rc1.search(data)
    if m1:
        m2 = rc2.search(data, m1.end())
        if m2:
            t1 = m1.group(1)
            t2 = m2.group(1)
            if t1 == t2:
                for k in PEM_SUFFIXES:
                    if t1.endswith(k):
                        return PEM_SUFFIXES[k]
    ssh_pub_rc = re.compile(rb"\A(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp)")
    m1 = ssh_pub_rc.match(data)
    if m1:
        return "pub-ssh"
    return None


EXT_MAP = {
    ".crt": "crt",
    ".cer": "crt",
    ".csr": "csr",
    ".crl": "crl",
    ".key": "key",
    ".pub": "pub",
    ".crt.pem": "crt",
    ".cer.pem": "crt",
    ".csr.pem": "csr",
    ".crl.pem": "crl",
    ".key.pem": "key",
    ".pub.pem": "pub",
}


def autodetect_filename(fn: str) -> Optional[str]:
    """Guess based on filename.
    """
    for k in EXT_MAP:
        if fn.endswith(k):
            return EXT_MAP[k]
    return None


def autodetect_file(fn: str) -> Optional[str]:
    """Run both filename and data detection.
    """
    fmt = autodetect_filename(fn)
    if not fmt:
        with open(fn, "rb") as f:
            fmt = autodetect_data(f.read(1 * 1024 * 1024))
    return fmt


def load_file_any(fn: str, password: Optional[Union[str, bytes]] = None) -> Optional[Union[
    x509.CertificateSigningRequest,
    x509.CertificateRevocationList,
    x509.Certificate,
    PUBKEY_TYPES,
    PRIVKEY_TYPES,
]]:
    """Load any format supported
    """
    password = as_password(password)
    with open(fn, "rb") as f:
        data = f.read()
    fmt = autodetect_data(data)
    if not fmt:
        fmt = autodetect_filename(fn)
    if fmt == "csr":
        if is_pem_data(data):
            return x509.load_pem_x509_csr(data, default_backend())
        return x509.load_der_x509_csr(data, default_backend())
    elif fmt == "crt":
        if is_pem_data(data):
            return x509.load_pem_x509_certificate(data, default_backend())
        return x509.load_der_x509_certificate(data, default_backend())
    elif fmt == "crl":
        if is_pem_data(data):
            return x509.load_pem_x509_crl(data, default_backend())
        return x509.load_der_x509_crl(data, default_backend())
    elif fmt == "pub":
        if is_pem_data(data):
            return load_pem_public_key(data, default_backend())
        return load_der_public_key(data, default_backend())
    elif fmt == "key":
        return load_key(fn, password)
    elif fmt == "key-ssh":
        return load_ssh_private_key(data, password, default_backend())
    elif fmt == "pub-ssh":
        return load_ssh_public_key(data, default_backend())
    return None

