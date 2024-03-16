"""Compatibility between various cryptography versions.
"""

# pylint: disable=import-outside-toplevel

from datetime import datetime, timezone
from typing import (
    TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Type, Union, cast,
)

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    dh, dsa, ec, ed448, ed25519, padding, rsa, x448, x25519,
)

try:
    from typing import TypeAlias
except ImportError:
    if TYPE_CHECKING:
        from typing_extensions import TypeAlias
    else:
        class TypeAlias:
            pass


__all__ = (
    "AllPrivateKeyTypes", "AllPublicKeyTypes",
    "AllPrivateKeyClasses", "AllPublicKeyClasses",
    "IssuerPrivateKeyTypes", "IssuerPublicKeyTypes",
    "IssuerPrivateKeyClasses", "IssuerPublicKeyClasses",
    "SubjectPrivateKeyTypes", "SubjectPublicKeyTypes",
    "SubjectPrivateKeyClasses", "SubjectPublicKeyClasses",
    "X509Types", "X509Classes",
    "EC_CURVES",
    "get_utc_datetime", "get_utc_datetime_opt",
    "TypeAlias",
    "NameSeq", "GNameList",
    "MaybeList", "MaybeName",
    "MaybeTimestamp", "MaybeNumber",
    "SignatureParamsType",
    "valid_issuer_public_key",
    "valid_issuer_private_key",
    "valid_subject_public_key",
    "valid_subject_private_key",
)


NameSeq: TypeAlias = Tuple[Tuple[str, ...], ...]
GNameList: TypeAlias = List[str]
MaybeList: TypeAlias = Union[str, List[str]]
MaybeName: TypeAlias = Union[str, Dict[str, str], NameSeq]
MaybeTimestamp: TypeAlias = Union[str, datetime]
MaybeNumber: TypeAlias = Union[str, int]

# curves that always exist
EC_CURVES: Dict[str, Type[ec.EllipticCurve]] = {
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


IssuerPrivateKeyTypes: TypeAlias = Union[
    ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey, dsa.DSAPrivateKey,
    ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey,
]
IssuerPrivateKeyClasses: Tuple[Type[IssuerPrivateKeyTypes], ...] = (
    ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey, dsa.DSAPrivateKey,
    ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey,
)
IssuerPublicKeyTypes: TypeAlias = Union[
    ec.EllipticCurvePublicKey, rsa.RSAPublicKey, dsa.DSAPublicKey,
    ed25519.Ed25519PublicKey, ed448.Ed448PublicKey,
]
IssuerPublicKeyClasses: Tuple[Type[IssuerPublicKeyTypes], ...] = (
    ec.EllipticCurvePublicKey, rsa.RSAPublicKey, dsa.DSAPublicKey,
    ed25519.Ed25519PublicKey, ed448.Ed448PublicKey,
)

SubjectPrivateKeyTypes: TypeAlias = Union[
    IssuerPrivateKeyTypes, x25519.X25519PrivateKey, x448.X448PrivateKey
]
SubjectPrivateKeyClasses: Tuple[Type[SubjectPrivateKeyTypes], ...] = (
    IssuerPrivateKeyClasses + (x25519.X25519PrivateKey, x448.X448PrivateKey)
)
SubjectPublicKeyTypes: TypeAlias = Union[
    IssuerPublicKeyTypes, x25519.X25519PublicKey, x448.X448PublicKey
]
SubjectPublicKeyClasses: Tuple[Type[SubjectPublicKeyTypes], ...] = (
    IssuerPublicKeyClasses + (x25519.X25519PublicKey, x448.X448PublicKey)
)

AllPrivateKeyTypes: TypeAlias = Union[SubjectPrivateKeyTypes, dh.DHPrivateKey]
AllPrivateKeyClasses: Tuple[Type[AllPrivateKeyTypes], ...] = (
    SubjectPrivateKeyClasses + (dh.DHPrivateKey,)
)
AllPublicKeyTypes: TypeAlias = Union[SubjectPublicKeyTypes, dh.DHPublicKey]
AllPublicKeyClasses: Tuple[Type[AllPublicKeyTypes], ...] = (
    SubjectPublicKeyClasses + (dh.DHPublicKey,)
)

X509Types: TypeAlias = Union[
    x509.Certificate, x509.CertificateSigningRequest, x509.CertificateRevocationList,
]
X509Classes: Tuple[Type[X509Types], ...] = (
    x509.Certificate, x509.CertificateSigningRequest, x509.CertificateRevocationList,
)

AllowedHashTypes: TypeAlias = Union[
    hashes.SHA256,
    hashes.SHA384,
    hashes.SHA512,
]

SignatureParamsType: TypeAlias = Union[padding.PKCS1v15, padding.PSS, ec.ECDSA]


def get_utc_datetime_opt(obj: Any, field: str) -> Optional[datetime]:
    field_utc = field + "_utc"
    if hasattr(obj, field_utc):
        return cast(datetime, getattr(obj, field_utc))
    dt = getattr(obj, field)
    if dt is None:
        return None
    return cast(datetime, dt.replace(tzinfo=timezone.utc))


def get_utc_datetime(obj: Any, field: str) -> datetime:
    dt = get_utc_datetime_opt(obj, field)
    assert dt, "get_utc_datetime expects not-None"
    return dt


def valid_private_key(key: Any) -> AllPrivateKeyTypes:
    if isinstance(key, AllPrivateKeyClasses):
        return cast(AllPrivateKeyTypes, key)
    raise TypeError("Invalid private key type")


def valid_public_key(key: Any) -> AllPublicKeyTypes:
    if isinstance(key, AllPublicKeyClasses):
        return cast(AllPublicKeyTypes, key)
    raise TypeError("Invalid public key type")


def valid_issuer_private_key(key: Any) -> IssuerPrivateKeyTypes:
    if isinstance(key, IssuerPrivateKeyClasses):
        return cast(IssuerPrivateKeyTypes, key)
    raise TypeError("Invalid private key type for issuer")


def valid_issuer_public_key(key: Any) -> IssuerPublicKeyTypes:
    if isinstance(key, IssuerPublicKeyClasses):
        return cast(IssuerPublicKeyTypes, key)
    raise TypeError("Invalid public key type for issuer")


def valid_subject_public_key(key: Any) -> SubjectPublicKeyTypes:
    if isinstance(key, SubjectPublicKeyClasses):
        return cast(SubjectPublicKeyTypes, key)
    raise TypeError("Invalid public key type for subject")


def valid_subject_private_key(key: Any) -> SubjectPrivateKeyTypes:
    if isinstance(key, SubjectPrivateKeyClasses):
        return cast(SubjectPrivateKeyTypes, key)
    raise TypeError("Invalid public key type for subject")

