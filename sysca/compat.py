"""Compatibility between various cryptography versions.
"""

from cryptography import x509
from cryptography.x509.oid import SignatureAlgorithmOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa

__all__ = (
    "X509_CLASSES", "PUBKEY_CLASSES", "PRIVKEY_CLASSES",
    "EDDSA_PRIVKEY_CLASSES", "EDDSA_PUBKEY_CLASSES",
    "EC_CURVES", "ed25519", "ed448",
)


ed25519 = ed448 = None
try:
    if hasattr(SignatureAlgorithmOID, "ED25519"):
        from cryptography.hazmat.primitives.asymmetric import ed25519
    if hasattr(SignatureAlgorithmOID, "ED448"):
        from cryptography.hazmat.primitives.asymmetric import ed448
except ImportError:
    pass

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
PUBKEY_CLASSES = [ec.EllipticCurvePublicKey, rsa.RSAPublicKey, dsa.DSAPublicKey]
PRIVKEY_CLASSES = [ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey, dsa.DSAPrivateKey]
EDDSA_PUBKEY_CLASSES = []
EDDSA_PRIVKEY_CLASSES = []
if ed25519 is not None:
    EDDSA_PUBKEY_CLASSES.append(ed25519.Ed25519PublicKey)
    EDDSA_PRIVKEY_CLASSES.append(ed25519.Ed25519PrivateKey)
if ed448 is not None:
    EDDSA_PUBKEY_CLASSES.append(ed448.Ed448PublicKey)
    EDDSA_PRIVKEY_CLASSES.append(ed448.Ed448PrivateKey)
# isinstance() needs tuples
PUBKEY_CLASSES = tuple(PUBKEY_CLASSES + EDDSA_PUBKEY_CLASSES)
PRIVKEY_CLASSES = tuple(PRIVKEY_CLASSES + EDDSA_PRIVKEY_CLASSES)
EDDSA_PUBKEY_CLASSES = tuple(EDDSA_PUBKEY_CLASSES)
EDDSA_PRIVKEY_CLASSES = tuple(EDDSA_PRIVKEY_CLASSES)
X509_CLASSES = (x509.Certificate, x509.CertificateSigningRequest, x509.CertificateRevocationList)

# workaround bug in cryptography 2.x


def _crl_fixup():
    from cryptography.hazmat.backends.openssl import encode_asn1, decode_asn1
    oid = ExtensionOID.FRESHEST_CRL
    crt_enc = getattr(encode_asn1, "_EXTENSION_ENCODE_HANDLERS", {})
    crl_enc = getattr(encode_asn1, "_CRL_EXTENSION_ENCODE_HANDLERS", {})
    if oid not in crl_enc and oid in crt_enc:
        crl_enc[oid] = crt_enc[oid]
    crt_dec = getattr(decode_asn1, "_EXTENSION_HANDLERS_NO_SCT", {})
    crl_dec = getattr(decode_asn1, "_CRL_EXTENSION_HANDLERS", {})
    if oid not in crl_dec and oid in crt_dec:
        crl_dec[oid] = crt_dec[oid]


if hasattr(ExtensionOID, "FRESHEST_CRL"):
    _crl_fixup()
