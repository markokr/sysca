"""Compatibility between various cryptography versions.
"""

# pylint: disable=import-outside-toplevel

from typing import Type, Tuple

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa
from cryptography.hazmat.primitives.asymmetric import ed25519, ed448

__all__ = (
    "X509_CLASSES", "PUBKEY_CLASSES", "PRIVKEY_CLASSES",
    "EDDSA_PRIVKEY_CLASSES", "EDDSA_PUBKEY_CLASSES",
    "EC_CURVES", "ed25519", "ed448",
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
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurveOID, get_curve_for_oid
    EC_CURVES.update({n.lower(): get_curve_for_oid(getattr(EllipticCurveOID, n))
                      for n in dir(EllipticCurveOID) if n[0] != "_"})
except ImportError:
    pass


# collect classes for isinstance() checks
PUBKEY_CLASSES: Tuple[Type, ...] = (ec.EllipticCurvePublicKey, rsa.RSAPublicKey, dsa.DSAPublicKey)
PRIVKEY_CLASSES: Tuple[Type, ...] = (ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey, dsa.DSAPrivateKey)
EDDSA_PUBKEY_CLASSES: Tuple[Type, ...] = (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)
EDDSA_PRIVKEY_CLASSES: Tuple[Type, ...] = (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)
PUBKEY_CLASSES += EDDSA_PUBKEY_CLASSES
PRIVKEY_CLASSES += EDDSA_PRIVKEY_CLASSES
X509_CLASSES: Tuple[Type, ...] = (x509.Certificate, x509.CertificateSigningRequest, x509.CertificateRevocationList)

