"""Key handling
"""

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .compat import (
    EC_CURVES, EDDSA_PRIVKEY_CLASSES,
    PRIVKEY_CLASSES, PUBKEY_CLASSES, ed448, ed25519,
)
from .exceptions import UnsupportedParameter

__all__ = (
    "get_curve_for_name", "get_ec_curves", "get_hash_algo", "get_key_name",
    "is_safe_bits", "is_safe_curve",
    "new_dsa_key", "new_ec_key", "new_key", "new_rsa_key",
    "new_serial_number", "same_pubkey", "set_unsafe",
    "valid_privkey", "valid_pubkey", "get_invalid_key_usage",
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


def get_curve_for_name(name):
    """Lookup curve by name.
    """
    name2 = name.lower()
    if name2 not in EC_CURVES:
        raise UnsupportedParameter("Unknown curve: %s" % name)
    if not is_safe_curve(name2):
        raise UnsupportedParameter("Unsafe curve: %s" % name)
    return EC_CURVES[name2]


def same_pubkey(o1, o2):
    """Compare public keys.
    """
    k1, k2 = o1, o2
    if not isinstance(k1, PUBKEY_CLASSES):
        k1 = o1.public_key()
        if k1 is None:
            raise ValueError("object %r gave None .public_key()" % o1)
    if not isinstance(k2, PUBKEY_CLASSES):
        k2 = k2.public_key()
        if k2 is None:
            raise ValueError("object %r gave None .public_key()" % o2)
    fmt = PublicFormat.SubjectPublicKeyInfo
    p1 = k1.public_bytes(Encoding.PEM, fmt)
    p2 = k2.public_bytes(Encoding.PEM, fmt)
    return p1 == p2


def get_hash_algo(privkey, ctx):
    """Return signature hash algo based on privkey.
    """
    if isinstance(privkey, EDDSA_PRIVKEY_CLASSES):
        return None
    if isinstance(privkey, ec.EllipticCurvePrivateKey):
        if privkey.key_size > 500:
            return SHA512()
        if privkey.key_size > 300:
            return SHA384()
    return SHA256()


def get_invalid_key_usage(pubkey):
    """KeyUsage types not supported by key"""
    bad = ("key_encipherment", "data_encipherment", "encipher_only", "decipher_only", "key_agreement")

    if UNSAFE or isinstance(pubkey, rsa.RSAPublicKey) or pubkey is None:
        return ()
    return bad


def is_safe_bits(bits, bitlist):
    """Allow bits"""
    return UNSAFE or bits in bitlist


def is_safe_curve(name):
    """Allow curve"""
    return UNSAFE or name.lower() in SAFE_CURVES


def get_ec_curves():
    """Return supported curve names.
    """
    lst = list(EC_CURVES.keys())
    if ed25519 is not None:
        lst.append("ed25519")
    if ed448 is not None:
        lst.append("ed448")
    return [n for n in sorted(lst) if is_safe_curve(n)]


def new_ec_key(name="secp256r1"):
    """New Elliptic Curve key
    """
    name = name.lower()
    if name == "ed25519":
        if ed25519 is not None:
            return ed25519.Ed25519PrivateKey.generate()
        raise UnsupportedParameter("ed25519 not supported")
    if name == "ed448":
        if ed448 is not None:
            return ed448.Ed448PrivateKey.generate()
        raise UnsupportedParameter("ed448 not supported")
    curve = get_curve_for_name(name)
    return ec.generate_private_key(curve=curve, backend=default_backend())


def new_rsa_key(bits=2048):
    """New RSA key.
    """
    if not is_safe_bits(bits, SAFE_BITS_RSA):
        raise UnsupportedParameter("Bad value for RSA bits: %d" % bits)
    return rsa.generate_private_key(key_size=bits, public_exponent=65537, backend=default_backend())


def new_dsa_key(bits=2048):
    """New DSA key.
    """
    if not is_safe_bits(bits, SAFE_BITS_DSA):
        raise UnsupportedParameter("Bad value for DSA bits: %d" % bits)
    return dsa.generate_private_key(key_size=bits, backend=default_backend())


def new_key(keydesc="ec"):
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


def valid_pubkey(pubkey):
    """Return True if usable public key.
    """
    if isinstance(pubkey, rsa.RSAPublicKey):
        return is_safe_bits(pubkey.key_size, SAFE_BITS_RSA)
    if isinstance(pubkey, dsa.DSAPublicKey):
        return is_safe_bits(pubkey.key_size, SAFE_BITS_DSA)
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        return is_safe_curve(pubkey.curve.name)
    return isinstance(pubkey, PUBKEY_CLASSES)


def valid_privkey(privkey):
    """Return True if usable private key.
    """
    if isinstance(privkey, rsa.RSAPrivateKey):
        return is_safe_bits(privkey.key_size, SAFE_BITS_RSA)
    if isinstance(privkey, dsa.DSAPrivateKey):
        return is_safe_bits(privkey.key_size, SAFE_BITS_DSA)
    if isinstance(privkey, ec.EllipticCurvePrivateKey):
        return is_safe_curve(privkey.curve.name)
    return isinstance(privkey, PRIVKEY_CLASSES)


def get_key_name(key):
    """Return key type.
    """
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return "rsa:%d" % key.key_size
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return "dsa:%d" % key.key_size
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return "ec:%s" % key.curve.name
    if ed25519 is not None and isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "ec:ed25519"
    if ed448 is not None and isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return "ec:ed448"
    return "<unknown key type>"


def set_unsafe(flag):
    global UNSAFE
    UNSAFE = flag


def new_serial_number():
    """Return serial number with max allowed entropy.
    """
    # serial should have at least 20 bits of entropy and fit into 20 bytes
    seed = int.from_bytes(os.urandom(20), "big", signed=False)
    # avoid sign problems by setting highest bit
    return (seed >> 1) | (1 << 158)

