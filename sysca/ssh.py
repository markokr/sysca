"""I/O of OpenSSH private key format.
"""

from typing import Optional, Union

from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, Encoding,
    NoEncryption, PrivateFormat, PublicFormat,
)
from cryptography.hazmat.primitives.serialization.ssh import (
    load_ssh_private_key, load_ssh_public_key,
)

from .compat import (
    AllPrivateKeyTypes, AllPublicKeyTypes,
    valid_issuer_private_key, valid_issuer_public_key,
)

__all__ = (
    "load_ssh_public_key",
    "load_ssh_private_key",
    "serialize_ssh_public_key",
    "serialize_ssh_private_key",
)


def serialize_ssh_public_key(public_key: AllPublicKeyTypes) -> bytes:
    key = valid_issuer_public_key(public_key)
    return key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)


def serialize_ssh_private_key(private_key: AllPrivateKeyTypes, password: Optional[Union[str, bytes]] = None) -> bytes:
    enc: Union[BestAvailableEncryption, NoEncryption]
    if password is None:
        enc = NoEncryption()
    elif isinstance(password, str):
        enc = BestAvailableEncryption(password.encode())
    else:
        enc = BestAvailableEncryption(password)
    key = valid_issuer_private_key(private_key)
    return key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, enc)

