"""Compatibility between various cryptography versions.
"""

# pylint: disable=import-outside-toplevel

from typing import Tuple, Type, Union, Optional, Any
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    dh, dsa, ec, ed448, ed25519, rsa, x448, x25519,
)

__all__ = (
    "X509_CLASSES", "PUBKEY_CLASSES", "PRIVKEY_CLASSES",
    "EDDSA_PRIVKEY_CLASSES", "EDDSA_PUBKEY_CLASSES",
    "EC_CURVES", "ed25519", "ed448",
    "get_utc_datetime", "get_utc_datetime_opt",
)


# curves that always exist
EC_CURVES = {
    "secp192r1": ec.SECP192R1,
    "secp224r1": ec.SECP224R1,
    "secp256r1": ec.SECP256R1,
    "secp384r1": ec.SECP384R1,
    "secp521r1": ec.SECP521R1,
}

# load all curves
try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurveOID, get_curve_for_oid,
    )
    EC_CURVES.update({n.lower(): get_curve_for_oid(getattr(EllipticCurveOID, n))
                      for n in dir(EllipticCurveOID) if n[0] != "_"})
except ImportError:
    pass


# collect classes for isinstance() checks
PUBKEY_CLASSES: Tuple[Type, ...] = (ec.EllipticCurvePublicKey, rsa.RSAPublicKey, dsa.DSAPublicKey)
PRIVKEY_CLASSES: Tuple[Type, ...] = (ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey, dsa.DSAPrivateKey)
EDDSA_PUBKEY_CLASSES: Tuple[Type, ...] = (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)
EDDSA_PRIVKEY_CLASSES: Tuple[Type, ...] = (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)
X_PUBKEY_CLASSES: Tuple[Type, ...] = (x25519.X25519PublicKey, x448.X448PublicKey)
X_PRIVKEY_CLASSES: Tuple[Type, ...] = (x25519.X25519PrivateKey, x448.X448PrivateKey)
PUBKEY_CLASSES += EDDSA_PUBKEY_CLASSES + X_PUBKEY_CLASSES
PRIVKEY_CLASSES += EDDSA_PRIVKEY_CLASSES + X_PRIVKEY_CLASSES
X509_CLASSES: Tuple[Type, ...] = (x509.Certificate, x509.CertificateSigningRequest, x509.CertificateRevocationList)

PRIVKEY_TYPES = Union[
    ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey, dsa.DSAPrivateKey,
    ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey,
    x25519.X25519PrivateKey, x448.X448PrivateKey,
    dh.DHPrivateKey,
]

PUBKEY_TYPES = Union[
    ec.EllipticCurvePublicKey, rsa.RSAPublicKey, dsa.DSAPublicKey,
    ed25519.Ed25519PublicKey, ed448.Ed448PublicKey,
    x25519.X25519PublicKey, x448.X448PublicKey,
    dh.DHPublicKey,
]


def get_utc_datetime_opt(obj: Any, field: str) -> Optional[datetime]:
    field_utc = field + "_utc"
    if hasattr(obj, field_utc):
        return getattr(obj, field_utc)
    dt = getattr(obj, field)
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc)


def get_utc_datetime(obj: Any, field: str) -> datetime:
    dt = get_utc_datetime_opt(obj, field)
    assert dt, "get_utc_datetime expects not-None"
    return dt

