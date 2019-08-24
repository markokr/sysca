"""File reading
"""

import os.path
import re
import subprocess

__all__ = (
    "load_gpg_file", "load_password", "is_pem_data",
    "autodetect_data", "autodetect_filename", "autodetect_file",
)


def load_gpg_file(fn):
    """Decrypt file if .gpg extension.
    """
    ext = os.path.splitext(fn)[1].lower()
    if ext not in (".gpg", ".pgp"):
        return open(fn, "rb").read()

    cmd = ["gpg", "-q", "-d", "--batch", "--no-tty", fn]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    log = err.decode("utf8", "replace").strip()
    if p.returncode != 0:
        raise Exception("gpg failed: %s" % log)
        #die("%s: gpg failed: \n  %s", fn, log)

    # cannot say "you need to check signatures" to gpg...
    # if "Good signature" not in log:
    #    msg("%s: No signature found", fn)
    #    if log:
    #        msg(log)

    return out


def load_password(fn):
    """Read password from potentially gpg-encrypted file.
    """
    if not fn:
        return None
    return load_gpg_file(fn).strip(b"\n")


_bin_rc = re.compile(b"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def is_pem_data(data):
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
# PGP PUBLIC KEY BLOCK
# PGP PRIVATE KEY BLOCK
# PGP MESSAGE
PEM_SUFFIXES = {
    b" CERTIFICATE": "crt",
    b" CRL": "crl",
    b" REQUEST": "csr",
    b" PRIVATE KEY": "key",
    b" PUBLIC KEY": "pub",
}


def autodetect_data(data):
    """Relaxed autodetect, for "show".
    """
    words = b"(?: [A-Z][A-Z0-9]*)+"
    rc1 = re.compile(b"-----BEGIN(%s)-----" % words)
    rc2 = re.compile(b"-----END(%s)-----" % words)
    if not is_pem_data(data):
        return None
    m1 = rc1.search(data)
    if not m1:
        return None
    m2 = rc2.search(data, m1.end())
    if not m2:
        return None
    t1 = m1.group(1)
    t2 = m2.group(1)
    if t1 != t2:
        return None
    for k in PEM_SUFFIXES:
        if t1.endswith(k):
            return PEM_SUFFIXES[k]
    return None


EXT_MAP = {
    ".crt": "crt",
    ".cer": "crr",
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


def autodetect_filename(fn):
    """Guess based on filename.
    """
    for k in EXT_MAP:
        if fn.endswith(k):
            return EXT_MAP[k]
    return None


def autodetect_file(fn):
    """Run both filename and data detection.
    """
    fmt = autodetect_filename(fn)
    if not fmt:
        with open(fn, "rb") as f:
            fmt = autodetect_data(f.read(1 * 1024 * 1024))
    return fmt
