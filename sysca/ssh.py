"""I/O of OpenSSH private key format.
"""

from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, Encoding,
    NoEncryption, PrivateFormat, PublicFormat,
)

try:
    from cryptography.hazmat.primitives.serialization.ssh import (
        load_ssh_private_key, load_ssh_public_key,
    )
    HAVE_SSH = True
except ImportError:
    HAVE_SSH = False

    def load_ssh_public_key(data, backend=None):    # type: ignore
        raise NotImplementedError

    def load_ssh_private_key(data, password, backend=None):  # type: ignore
        raise NotImplementedError

__all__ = (
    "load_ssh_public_key",
    "load_ssh_private_key",
    "serialize_ssh_public_key",
    "serialize_ssh_private_key",
    "HAVE_SSH",
)


def serialize_ssh_public_key(public_key):
    return public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)


def serialize_ssh_private_key(private_key, password=None):
    if password is None:
        enc = NoEncryption()
    elif isinstance(password, str):
        enc = BestAvailableEncryption(password.encode())
    else:
        enc = BestAvailableEncryption(password)
    return private_key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, enc)

