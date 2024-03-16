"""Key handling
"""

import os
from typing import List, Optional, Sequence, Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    dh, dsa, ec, ed448, ed25519, padding, rsa, utils, x448, x25519,
)
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .compat import (
    EC_CURVES, AllowedHashTypes, AllPrivateKeyClasses,
    AllPrivateKeyTypes, AllPublicKeyTypes, IssuerPrivateKeyClasses,
    IssuerPrivateKeyTypes, SignatureParamsType, SubjectPublicKeyClasses,
    SubjectPublicKeyTypes, valid_private_key, valid_public_key,
)
from .exceptions import UnsupportedParameter

__all__ = (
    "get_curve_for_name", "get_ec_curves", "get_hash_algo", "get_key_name",
    "is_safe_bits", "is_safe_curve",
    "new_dsa_key", "new_ec_key", "new_key", "new_rsa_key",
    "new_serial_number", "same_pubkey", "set_unsafe",
    "safe_subject_pubkey", "safe_issuer_privkey", "get_invalid_key_usage",
    "get_param_info",
)


#
# Key parameters
#


UNSAFE = False

# safe choices
SAFE_BITS_RSA = (2048, 3072, 4096)
SAFE_BITS_DSA = (2048, 3072)
SAFE_CURVES = ("secp256r1", "secp384r1", "secp521r1", "ed25519", "ed448",
               "brainpoolp256r1", "brainpoolp384r1", "brainpoolp512r1")


def get_curve_for_name(name: str) -> ec.EllipticCurve:
    """Lookup curve by name.
    """
    name2 = name.lower()
    if name2 not in EC_CURVES:
        raise UnsupportedParameter("Unknown curve: %s" % name)
    if not is_safe_curve(name2):
        raise UnsupportedParameter("Unsafe curve: %s" % name)
    return EC_CURVES[name2]()


def same_pubkey(o1: Union[x509.Certificate, x509.CertificateSigningRequest, AllPublicKeyTypes, AllPrivateKeyTypes],
                o2: Union[x509.Certificate, x509.CertificateSigningRequest, AllPublicKeyTypes, AllPrivateKeyTypes],
                ) -> bool:
    """Compare public keys.
    """
    k1: AllPublicKeyTypes
    k2: AllPublicKeyTypes

    if isinstance(o1, (x509.Certificate, x509.CertificateSigningRequest)):
        k1 = o1.public_key()
    elif isinstance(o1, AllPrivateKeyClasses):
        k1 = valid_private_key(o1).public_key()
    else:
        k1 = valid_public_key(o1)

    if isinstance(o2, (x509.Certificate, x509.CertificateSigningRequest)):
        k2 = o2.public_key()
    elif isinstance(o2, AllPrivateKeyClasses):
        k2 = valid_private_key(o2).public_key()
    else:
        k2 = valid_public_key(o2)
    fmt = PublicFormat.SubjectPublicKeyInfo
    p1 = k1.public_bytes(Encoding.PEM, fmt)
    p2 = k2.public_bytes(Encoding.PEM, fmt)
    return p1 == p2


def get_hash_algo(privkey: IssuerPrivateKeyTypes, ctx: str) -> Optional[AllowedHashTypes]:
    """Return signature hash algo based on privkey.
    """
    if isinstance(privkey, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return None
    elif isinstance(privkey, ec.EllipticCurvePrivateKey):
        if privkey.key_size > 500:
            return SHA512()
        if privkey.key_size > 300:
            return SHA384()
    elif isinstance(privkey, rsa.RSAPrivateKey):
        if privkey.key_size > 4000:
            return SHA512()
        if privkey.key_size > 3000:
            return SHA384()
    return SHA256()


def get_rsa_padding(privkey: IssuerPrivateKeyTypes, ctx: str) -> Optional[padding.PSS]:
    """Return signature hash algo based on privkey.
    """
    if not isinstance(privkey, rsa.RSAPrivateKey):
        return None
    algo = get_hash_algo(privkey, "PSS")
    assert algo
    return padding.PSS(padding.MGF1(algo), padding.PSS.DIGEST_LENGTH)


def get_invalid_key_usage(pubkey: SubjectPublicKeyTypes) -> Sequence[str]:
    """KeyUsage types not supported by key"""
    rsa_legacy = ("key_encipherment", "data_encipherment", "encipher_only", "decipher_only", "key_agreement")
    if UNSAFE or isinstance(pubkey, rsa.RSAPublicKey):
        return ()
    return rsa_legacy


def is_safe_bits(bits: int, bitlist: Sequence[int]) -> bool:
    """Allow bits"""
    return UNSAFE or bits in bitlist


def is_safe_curve(name: str) -> bool:
    """Allow curve"""
    return UNSAFE or name.lower() in SAFE_CURVES


def get_ec_curves() -> List[str]:
    """Return supported curve names.
    """
    lst = list(EC_CURVES.keys())
    if ed25519 is not None:
        lst.append("ed25519")
    if ed448 is not None:
        lst.append("ed448")
    return [n for n in sorted(lst) if is_safe_curve(n)]


def new_ec_key(
    name: str = "secp256r1"
) -> Union[ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey]:
    """New Elliptic Curve key
    """
    name = name.lower()
    if name == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    if name == "ed448":
        return ed448.Ed448PrivateKey.generate()
    curve = get_curve_for_name(name)
    return ec.generate_private_key(curve=curve)


def new_rsa_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    """New RSA key.
    """
    if not is_safe_bits(bits, SAFE_BITS_RSA):
        raise UnsupportedParameter("Bad value for RSA bits: %d" % bits)
    return rsa.generate_private_key(key_size=bits, public_exponent=65537)


def new_dsa_key(bits: int = 2048) -> dsa.DSAPrivateKey:
    """New DSA key.
    """
    if not is_safe_bits(bits, SAFE_BITS_DSA):
        raise UnsupportedParameter("Bad value for DSA bits: %d" % bits)
    return dsa.generate_private_key(key_size=bits)


def new_key(keydesc: str = "ec") -> IssuerPrivateKeyTypes:
    """Create new key.
    """
    short = {"ec": "ec:secp256r1", "rsa": "rsa:2048", "dsa": "dsa:2048"}
    keydesc = short.get(keydesc, keydesc)

    # create key
    tmp = keydesc.lower().split(":")
    if len(tmp) != 2:
        raise UnsupportedParameter("Bad key spec: %s" % keydesc)
    t, v = tmp
    if t == "ec":
        return new_ec_key(v)
    elif t == "rsa":
        return new_rsa_key(int(v))
    elif t == "dsa":
        return new_dsa_key(int(v))
    raise UnsupportedParameter("Bad key type: %s" % keydesc)


def safe_subject_pubkey(pubkey: AllPublicKeyTypes) -> bool:
    """Return True if usable public key.
    """
    if isinstance(pubkey, rsa.RSAPublicKey):
        return is_safe_bits(pubkey.key_size, SAFE_BITS_RSA)
    if isinstance(pubkey, dsa.DSAPublicKey):
        return is_safe_bits(pubkey.key_size, SAFE_BITS_DSA)
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        return is_safe_curve(pubkey.curve.name)
    return isinstance(pubkey, SubjectPublicKeyClasses)


def safe_issuer_privkey(privkey: AllPrivateKeyTypes) -> bool:
    """Return True if usable private key.
    """
    if isinstance(privkey, rsa.RSAPrivateKey):
        return is_safe_bits(privkey.key_size, SAFE_BITS_RSA)
    if isinstance(privkey, dsa.DSAPrivateKey):
        return is_safe_bits(privkey.key_size, SAFE_BITS_DSA)
    if isinstance(privkey, ec.EllipticCurvePrivateKey):
        return is_safe_curve(privkey.curve.name)
    return isinstance(privkey, IssuerPrivateKeyClasses)


def get_key_name(key: Union[AllPublicKeyTypes, AllPrivateKeyTypes]) -> str:
    """Return key type.
    """
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return "rsa:%d" % key.key_size
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return "dsa:%d" % key.key_size
    if isinstance(key, (dh.DHPublicKey, dh.DHPrivateKey)):
        return "dh:%d" % key.key_size
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return "ec:%s" % key.curve.name
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "ec:ed25519"
    if isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return "ec:ed448"
    if isinstance(key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)):
        return "ec:x25519"
    if isinstance(key, (x448.X448PublicKey, x448.X448PrivateKey)):
        return "ec:x448"
    return "<unknown key type>"


def set_unsafe(flag: bool) -> None:
    global UNSAFE
    UNSAFE = flag


def new_serial_number() -> int:
    """Return serial number with max allowed entropy.
    """
    # serial should have at least 20 bits of entropy and fit into 20 bytes
    seed = int.from_bytes(os.urandom(20), "big", signed=False)
    # avoid sign problems by setting highest bit
    return (seed >> 1) | (1 << 158)


def get_param_info(parm: SignatureParamsType) -> str:
    if isinstance(parm, padding.PKCS1v15):
        return "PKCS1v15"
    if isinstance(parm, ec.ECDSA):
        res = "ECDSA"
        algo = parm.algorithm
        if algo is not None:
            if isinstance(algo, utils.Prehashed):
                res += "/prehashed"
            else:
                res += "/" + algo.name
        return res
    if isinstance(parm, padding.PSS):
        res = "PSS"
        mgf = getattr(parm, "mgf")
        if mgf is not None:
            res += "/" + mgf.__class__.__name__
            mgfalgo = getattr(mgf, "_algorithm", None)
            if mgfalgo:
                res += "/" + mgfalgo.name
        salt = getattr(parm, "_salt_length", None)
        if salt is not None:
            if salt is padding.PSS.MAX_LENGTH:
                res += "/MAX_LENGTH"
            elif salt is padding.PSS.DIGEST_LENGTH:
                res += "/DIGEST_LENGTH"
            elif salt is padding.PSS.AUTO:
                res += "/AUTO"
            elif isinstance(salt, int):
                res += "/" + str(salt)
        return res
    return "<unknown>"

