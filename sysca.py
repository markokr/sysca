#! /usr/bin/env python3

"""Certificate tool for sysadmins.

Mostly follows RFC5280 profile.
"""

import argparse
import ipaddress
import os.path
import re
import subprocess
import sys

from datetime import datetime, timedelta

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat,
    BestAvailableEncryption, NoEncryption, load_pem_private_key)

from cryptography import x509
from cryptography import __version__ as crypto_version
from cryptography.x509.oid import (
    NameOID, ExtendedKeyUsageOID, CRLEntryExtensionOID,
    ExtensionOID, AuthorityInformationAccessOID, SignatureAlgorithmOID)

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519, ed448
    if not hasattr(SignatureAlgorithmOID, 'ED25519'):
        ed25519 = None
    if not hasattr(SignatureAlgorithmOID, 'ED448'):
        ed448 = None
except ImportError:
    ed25519 = ed448 = None


__version__ = '1.3'

__all__ = [
    'CertInfo', 'RevCertInfo', 'CRLInfo',
    'InvalidCertificate',
    'load_key', 'load_req', 'load_cert', 'load_crl',
    'key_to_pem', 'cert_to_pem', 'req_to_pem', 'crl_to_pem',
    'new_ec_key', 'new_rsa_key',
    'load_gpg_file', 'load_password',
    'create_x509_req', 'create_x509_cert', 'create_x509_crl',
    'run_sysca'
]

class InvalidCertificate(ValueError):
    """Invalid input for certificate."""

#
# Key parameters
#

MIN_RSA_BITS = 1536
MAX_RSA_BITS = 6144

EC_CURVES = {
    'secp192r1': ec.SECP192R1,
    'secp224r1': ec.SECP224R1,
    'secp256r1': ec.SECP256R1,
    'secp384r1': ec.SECP384R1,
    'secp521r1': ec.SECP521R1,
    # aliases
    'prime256v1': ec.SECP256R1,
}

# load all curves
try:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurveOID, get_curve_for_oid
    EC_CURVES.update({n.lower(): get_curve_for_oid(getattr(EllipticCurveOID, n)) for n in dir(EllipticCurveOID) if n[0] != '_'})
except ImportError:
    pass

def get_curve_for_name(name):
    """Lookup curve by name.
    """
    return EC_CURVES[name.lower()]

#
# Shortcut maps
#

DN_CODE_TO_OID = {
    'CN': NameOID.COMMON_NAME,

    'O': NameOID.ORGANIZATION_NAME,
    'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,     # multi

    'C': NameOID.COUNTRY_NAME,
    'L': NameOID.LOCALITY_NAME,
    'ST': NameOID.STATE_OR_PROVINCE_NAME,

    'SN': NameOID.SURNAME,
    'GN': NameOID.GIVEN_NAME,
    'T': NameOID.TITLE,
    'P': NameOID.PSEUDONYM,

    'GQ': NameOID.GENERATION_QUALIFIER,
    'DQ': NameOID.DN_QUALIFIER,

    'UID': NameOID.USER_ID,
    'XUID': NameOID.X500_UNIQUE_IDENTIFIER,
    'EMAIL': NameOID.EMAIL_ADDRESS,
    'SERIAL': NameOID.SERIAL_NUMBER,
    'SA': NameOID.STREET_ADDRESS,       # multi
    'PA': NameOID.POSTAL_ADDRESS,       # multi
    'PC': NameOID.POSTAL_CODE,

    'JC': NameOID.JURISDICTION_COUNTRY_NAME,
    'JL': NameOID.JURISDICTION_LOCALITY_NAME,
    'JST': NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME,

    'BC': NameOID.BUSINESS_CATEGORY,    # multi
    'DC': NameOID.DOMAIN_COMPONENT,     # multi
}

DN_ALLOW_MULTIPLE = set(['STREET', 'BC', 'DC', 'OU', 'SA', 'PA'])

KU_FIELDS = [
    'digital_signature',    # non-CA signatures
    'content_commitment',   # weird signatures.  old alias: non_repudiation
    'key_encipherment',     # SSL-RSA key exchange
    'data_encipherment',    # Historical.
    'key_agreement',        # Historical?
    'key_cert_sign',        # CA
    'crl_sign',             # CA
    'encipher_only',        # option for key_agreement
    'decipher_only',        # option for key_agreement
]

XKU_CODE_TO_OID = {
    'any': ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
    'server': ExtendedKeyUsageOID.SERVER_AUTH,
    'client': ExtendedKeyUsageOID.CLIENT_AUTH,
    'code': ExtendedKeyUsageOID.CODE_SIGNING,
    'email': ExtendedKeyUsageOID.EMAIL_PROTECTION,
    'time': ExtendedKeyUsageOID.TIME_STAMPING,
    'ocsp': ExtendedKeyUsageOID.OCSP_SIGNING,
}

# minimal KeyUsage defaults to add when ExtendedKeyUsage is given
XKU_DEFAULTS = {
    'any': ['digital_signature', 'key_encipherment', 'key_agreement', 'content_commitment', 'data_encipherment', 'key_cert_sign', 'crl_sign'],
    'server': ['digital_signature'], # key_agreement, key_encipherment
    'client': ['digital_signature'], # key_agreement
    'code': ['digital_signature'], # -
    'email': ['digital_signature'], # content_commitment, key_agreement, key_encipherment
    'time': ['digital_signature'], # content_commitment
    'ocsp': ['digital_signature'], # content_commitment

    'encipher_only': ['key_agreement'],
    'decipher_only': ['key_agreement'],
}

# required for CA
CA_DEFAULTS = {
    'key_cert_sign': True,
    'crl_sign': True,
}

# when usage not set
NONCA_DEFAULTS = {
    'digital_signature': True,
}

# CRL reason
CRL_REASON = {
    'unspecified': x509.ReasonFlags.unspecified,
    'key_compromise': x509.ReasonFlags.key_compromise,
    'ca_compromise': x509.ReasonFlags.ca_compromise,
    'affiliation_changed': x509.ReasonFlags.affiliation_changed,
    'superseded': x509.ReasonFlags.superseded,
    'cessation_of_operation': x509.ReasonFlags.cessation_of_operation,
    'certificate_hold': x509.ReasonFlags.certificate_hold,
    'privilege_withdrawn': x509.ReasonFlags.privilege_withdrawn,
    'aa_compromise': x509.ReasonFlags.aa_compromise,
    'remove_from_crl': x509.ReasonFlags.remove_from_crl,
}

CRL_REASON_MAP = {v: k for k, v in CRL_REASON.items()}

QUIET = False


def as_bytes(s):
    """Return byte-string.
    """
    if not isinstance(s, bytes):
        return s.encode('utf8')
    return s


def as_unicode(s, errs='strict'):
    """Return unicode-string.
    """
    if not isinstance(s, bytes):
        return s
    return s.decode('utf8', errs)


def serial_str(snum):
    """Format certificate serial number as string.
    """
    s = '%x' % snum
    s = '0'*(len(s)&1) + s
    s = re.sub(r'..', r':\g<0>', s).strip(':')
    return s


def load_number(sval):
    """Parse number from command line.
    """
    if re.match(r'^[0-9a-f]+(:[0-9a-f]+)+$', sval, re.I):
        return int(sval.replace(':', ''), 16)
    if re.match(r'^[0-9a-f]+(-[0-9a-f]+)+$', sval, re.I):
        return int(sval.replace('-', ''), 16)
    if re.match(r'^[0-9]+$', sval):
        return int(sval, 10)
    raise ValueError("Invalid number: %r" % sval)


def load_date(sval):
    """Parse date from command line.
    """
    if re.match(r'^\d\d\d\d-\d\d-\d\d$', sval):
        return datetime.strptime(sval, '%Y-%m-%d')
    raise ValueError("Invalid date: %r" % sval)


def _escape_char(m):
    """Backslash-escape.
    """
    c = m.group(0)
    if c in (',', '\\', '/'):
        return '\\' + c
    return '\\x%02x' % ord(c)


def dn_escape(s):
    """DistinguishedName backslash-escape"""
    return re.sub(r'[\\/\x00-\x1F]', _escape_char, s)


def list_escape(s):
    """Escape value for comma-separated list
    """
    return re.sub(r'[\\,]', _escape_char, s)


def show_list(desc, lst, writeln):
    """Print out list field.
    """
    if not lst:
        return
    val = ', '.join([list_escape(v) for v in lst])
    writeln("%s: %s" % (desc, val))


def _unescape_char(m):
    """Unescape helper
    """
    xmap = {',': ',', '/': '/', '\\': '\\', 't': '\t'}
    c = m.group(1)
    if len(c) > 1:
        if c[0] == 'x':
            return chr(int(c[1:], 16))
    return xmap[c]


def unescape(s):
    """Remove backslash escapes.
    """
    return re.sub(r'\\(x[0-9a-fA-F][0-9a-fA-F]|.)', _unescape_char, s)


def render_name(name_att_list):
    """Convert DistinguishedName dict to '/'-separated string.
    """
    res = ['']
    for k, v in name_att_list:
        v = dn_escape(v)
        res.append("%s=%s" % (k, v))
    res.append('')
    return '/'.join(res)


def maybe_parse(val, parse_func):
    """Parse argument value with function if string.
    """
    if val is None:
        return []
    if isinstance(val, (bytes, str)):
        return parse_func(val)
    if isinstance(val, dict):
        return list(val.items())
    if isinstance(val, (list, tuple)):
        return list(val)
    return val


def loop_escaped(val, c):
    """Parse list of strings, separated by c.
    """
    if not val:
        val = ''
    val = as_unicode(val)
    rc = re.compile(r'([^%s\\]|\\.)*' % re.escape(c))
    pos = 0
    while pos < len(val):
        if val[pos] == c:
            pos += 1
            continue
        m = rc.match(val, pos)
        if not m:
            raise Exception('rx bug')
        pos = m.end()
        yield unescape(m.group(0))


def parse_list(slist):
    """Parse comma-separated list to strings.
    """
    res = []
    for v in loop_escaped(slist, ','):
        v = v.strip()
        if v:
            res.append(v)
    return res


def parse_dn(dnstr):
    """Parse openssl-style /-separated list to dict.
    """
    res = []
    for part in loop_escaped(dnstr, '/'):
        part = part.strip()
        if not part:
            continue
        if '=' not in part:
            raise InvalidCertificate("Need k=v in Name string")
        k, v = part.split('=', 1)
        res.append((k.strip(), v.strip()))
    return res


def same_pubkey(o1, o2):
    """Compare public keys.
    """
    fmt = PublicFormat.SubjectPublicKeyInfo
    p1 = o1.public_key().public_bytes(Encoding.PEM, fmt)
    p2 = o2.public_key().public_bytes(Encoding.PEM, fmt)
    return p1 == p2


def get_backend():
    """Returns backend to use.
    """
    return default_backend()


def get_hash_algo(privkey, ctx):
    """Return signature hash algo based on privkey.
    """
    if ed25519 is not None and isinstance(privkey, ed25519.Ed25519PrivateKey):
        return None
    if ed448 is not None and isinstance(privkey, ed448.Ed448PrivateKey):
        return None
    if isinstance(privkey, ec.EllipticCurvePrivateKey):
        if privkey.key_size > 500:
            return SHA512()
        if privkey.key_size > 300:
            return SHA384()
    return SHA256()


def new_ec_key(name='secp256r1'):
    """New Elliptic Curve key
    """
    name = name.lower()
    if name == 'ed25519':
        if ed25519 is not None:
            return ed25519.Ed25519PrivateKey.generate()
        raise ValueError('ed25519 not supported')
    if name == 'ed448':
        if ed448 is not None:
            return ed448.Ed448PrivateKey.generate()
        raise ValueError('ed448 not supported')
    return ec.generate_private_key(curve=get_curve_for_name(name), backend=get_backend())


def new_rsa_key(bits=2048):
    """New RSA key.
    """
    if bits < MIN_RSA_BITS or bits > MAX_RSA_BITS:
        raise ValueError('Bad value for bits')
    return rsa.generate_private_key(key_size=bits, public_exponent=65537, backend=get_backend())


def new_dsa_key(bits=2048):
    """New DSA key.
    """
    if bits < MIN_RSA_BITS or bits > MAX_RSA_BITS:
        raise ValueError('Bad value for bits')
    return dsa.generate_private_key(key_size=bits, backend=get_backend())


def valid_pubkey(pubkey):
    """Return True if usable public key.
    """
    if isinstance(pubkey, rsa.RSAPublicKey):
        return pubkey.key_size >= MIN_RSA_BITS and pubkey.key_size <= MAX_RSA_BITS
    if isinstance(pubkey, dsa.DSAPublicKey):
        return pubkey.key_size >= MIN_RSA_BITS and pubkey.key_size <= MAX_RSA_BITS
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        return True
    if ed25519 is not None and isinstance(pubkey, ed25519.Ed25519PublicKey):
        return True
    if ed448 is not None and isinstance(pubkey, ed448.Ed448PublicKey):
        return True
    return False


def valid_privkey(privkey):
    """Return True if usable private key.
    """
    if isinstance(privkey, rsa.RSAPrivateKey):
        return privkey.key_size >= MIN_RSA_BITS and privkey.key_size <= MAX_RSA_BITS
    if isinstance(privkey, dsa.DSAPrivateKey):
        return privkey.key_size >= MIN_RSA_BITS and privkey.key_size <= MAX_RSA_BITS
    if isinstance(privkey, ec.EllipticCurvePrivateKey):
        return True
    if ed25519 is not None and isinstance(privkey, ed25519.Ed25519PrivateKey):
        return True
    if ed448 is not None and isinstance(privkey, ed448.Ed448PrivateKey):
        return True
    return False


def get_key_name(key):
    """Return key type.
    """
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return 'rsa:%d' % key.key_size
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return 'dsa:%d' % key.key_size
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return 'ec:%s' % key.curve.name
    if ed25519 is not None and isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return 'ec:ed25519'
    if ed448 is not None and isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return 'ec:ed448'
    return '<unknown key type>'


def new_serial_number():
    """Return serial number with max allowed entropy.
    """
    # serial should have at least 20 bits of entropy and fit into 20 bytes
    seed = int.from_bytes(os.urandom(20), "big", signed=False)
    # avoid sign problems by setting highest bit
    return (seed >> 1) | (1 << 158)


#
# Converters
#

def extract_name(name):
    """Convert Name object to shortcut-dict.
    """
    if name is None:
        return None
    name_oid2code_map = {v: k for k, v in DN_CODE_TO_OID.items()}
    res = []
    for att in name:
        if att.oid not in name_oid2code_map:
            raise InvalidCertificate("Unsupported RDN: %s" % (att,))
        desc = name_oid2code_map[att.oid]
        val = as_unicode(att.value)
        res.append((desc, val))
    return res


def extract_gnames(ext_name_list):
    """Convert list of GeneralNames to list of prefixed strings.
    """
    if ext_name_list is None:
        return None
    res = []
    for gn in ext_name_list:
        if isinstance(gn, x509.RFC822Name):
            res.append('email:' + as_unicode(gn.value))
        elif isinstance(gn, x509.DNSName):
            res.append('dns:' + as_unicode(gn.value))
        elif isinstance(gn, x509.UniformResourceIdentifier):
            res.append('uri:' + as_unicode(gn.value))
        elif isinstance(gn, x509.IPAddress):
            res.append('ip:' + str(gn.value))
        elif isinstance(gn, x509.DirectoryName):
            val = extract_name(gn.value)
            res.append('dn:' + render_name(val))
        else:
            raise InvalidCertificate("Unsupported subjectAltName type: %s" % (gn,))
    return res


def load_name(name_att_list):
    """Create Name object from subject's DistinguishedName.
    """
    attlist = []
    got = set()
    for k, v in name_att_list:
        if k in got and k not in DN_ALLOW_MULTIPLE:
            raise InvalidCertificate("Multiple Name keys not allowed: %s" % (k,))
        oid = DN_CODE_TO_OID[k]
        n = x509.NameAttribute(oid, as_unicode(v))
        attlist.append(n)
    return x509.Name(attlist)


def load_rel_name(name_att_list):
    """Create Name object from subject's DistinguishedName.
    """
    attlist = []
    got = set()
    for k, v in name_att_list:
        if k in got and k not in DN_ALLOW_MULTIPLE:
            raise InvalidCertificate("Multiple Name keys not allowed: %s" % (k,))
        oid = DN_CODE_TO_OID[k]
        n = x509.NameAttribute(oid, as_unicode(v))
        attlist.append(n)
    return x509.RelativeDistinguishedName(attlist)


def load_gnames(gname_list):
    """Converts list of prefixed strings to GeneralName list.
    """
    gnames = []
    for alt in gname_list:
        if ':' not in alt:
            raise InvalidCertificate("Invalid gname: %s" % (alt,))
        t, val = alt.split(':', 1)
        t = t.lower().strip()
        val = val.strip()
        if t == 'dn':
            gn = x509.DirectoryName(load_name(parse_dn(val)))
        elif t == 'dns':
            gn = x509.DNSName(val)
        elif t == 'email':
            gn = x509.RFC822Name(val)
        elif t == 'uri':
            gn = x509.UniformResourceIdentifier(val)
        elif t == 'ip':
            if val.find(':') >= 0:
                gn = x509.IPAddress(ipaddress.IPv6Address(val))
            else:
                gn = x509.IPAddress(ipaddress.IPv4Address(val))
        elif t == 'dn':
            gn = x509.DirectoryName(load_name(parse_dn(val)))
        elif t == 'net':
            if val.find(':') >= 0:
                gn = x509.IPAddress(ipaddress.IPv6Network(val))
            else:
                gn = x509.IPAddress(ipaddress.IPv4Network(val))
        else:
            raise InvalidCertificate('Invalid GeneralName: ' + alt)
        gnames.append(gn)
    return gnames


def make_key_usage(digital_signature=False, content_commitment=False, key_encipherment=False,
                  data_encipherment=False, key_agreement=False, key_cert_sign=False,
                  crl_sign=False, encipher_only=False, decipher_only=False):
    """Default arguments for KeyUsage.
    """
    return x509.KeyUsage(digital_signature=digital_signature, content_commitment=content_commitment,
            key_encipherment=key_encipherment, data_encipherment=data_encipherment,
            key_agreement=key_agreement, key_cert_sign=key_cert_sign, crl_sign=crl_sign,
            encipher_only=encipher_only, decipher_only=decipher_only)



def key_to_pem(key, password=None):
    """Serialize key in PEM format, optionally encrypted.
    """
    if password:
        enc = BestAvailableEncryption(as_bytes(password))
    else:
        enc = NoEncryption()
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc)


def cert_to_pem(cert):
    """Serialize certificate in PEM format.
    """
    return cert.public_bytes(Encoding.PEM)


def req_to_pem(req):
    """Serialize certificate request in PEM format.
    """
    return req.public_bytes(Encoding.PEM)


def crl_to_pem(crl):
    """Serialize certificate revocation list in PEM format.
    """
    return crl.public_bytes(Encoding.PEM)


def convert_urls_to_gnames(url_list):
    """Return urls as GeneralNames
    """
    urls = ['uri:' + u for u in url_list]
    return load_gnames(urls)


def make_issuer_gnames(subject, san):
    """Issuer GeneralNames for CRL usage.
    """
    gnames = []
    if subject:
        gnames.append('dn:' + render_name(subject))
    if san:
        gnames.extend(san)
    return gnames

#
# Info objects
#

class CertInfo:
    """Container for certificate fields.
    """
    def __init__(self, subject=None, alt_names=None, ca=False, path_length=None,
                 usage=None, ocsp_urls=None, crl_urls=None, issuer_urls=None,
                 ocsp_nocheck=False, ocsp_must_staple=False, ocsp_must_staple_v2=False,
                 permit_subtrees=None, exclude_subtrees=None, inhibit_any=None,
                 load=None):
        """Initialize info object.

        Arguments:

            subject
                dict if strings.

            alt_names
                list of GeneralName strings

            ca
                boolean, isCA

            path_length
                max depth for CA's

            usage
                list of keywords (KU_FIELDS, XKU_CODE_TO_OID).

            ocsp_urls
                list of urls

            crl_urls
                list of urls

            issuer_urls
                list of urls

            ocsp_nocheck
                mark as not to be checked via OCSP

            ocsp_must_staple
                mark that OCSP status_request is required

            ocsp_must_staple_v2
                mark that OCSP status_request_v2 is required

            permit_subtrees
                list of GeneralNames for permitted subtrees

            exclude_subtrees
                list of GeneralNames for excluded subtrees

            load
                object to extract from (cert or cert request)

        """
        self.ca = ca
        self.path_length = path_length
        self.subject = maybe_parse(subject, parse_dn)
        self.san = maybe_parse(alt_names, parse_list)
        self.issuer_name = None
        self.issuer_san = None
        self.usage = maybe_parse(usage, parse_list)
        self.ocsp_urls = maybe_parse(ocsp_urls, parse_list)
        self.crl_urls = maybe_parse(crl_urls, parse_list)
        self.issuer_urls = maybe_parse(issuer_urls, parse_list)
        self.exclude_subtrees = maybe_parse(exclude_subtrees, parse_list)
        self.permit_subtrees = maybe_parse(permit_subtrees, parse_list)
        self.ocsp_nocheck = ocsp_nocheck
        self.ocsp_must_staple = ocsp_must_staple
        self.ocsp_must_staple_v2 = ocsp_must_staple_v2
        self.version = None
        self.serial_number = None
        self.inhibit_any = inhibit_any

        if self.path_length is not None and self.path_length < 0:
            self.path_length = None

        self.public_key_info = None
        if load is not None:
            self.load_from_existing(load)

    def load_from_existing(self, obj):
        """Load certificate info from existing certificate or certificate request.
        """
        if isinstance(obj, x509.Certificate):
            self.serial_number = obj.serial_number
            if obj.version == x509.Version.v1:
                self.version = 1
            elif obj.version == x509.Version.v3:
                self.version = 3
            else:
                raise InvalidCertificate('Unsupported certificate version')
            self.issuer_name = extract_name(obj.issuer)
        elif isinstance(obj, x509.CertificateSigningRequest):
            self.serial_number = None
            self.version = None
            self.issuer_name = None
        else:
            raise InvalidCertificate('Invalid obj type: %s' % type(obj))
        self.public_key_info = get_key_name(obj.public_key())

        self.subject = extract_name(obj.subject)

        for ext in obj.extensions:
            crit = ext.critical
            extobj = ext.value
            if ext.oid == ExtensionOID.BASIC_CONSTRAINTS:
                if not crit:
                    raise InvalidCertificate("BASIC_CONSTRAINTS must be critical")
                self.ca = extobj.ca
                self.path_length = None
                if self.ca:
                    self.path_length = extobj.path_length
            elif ext.oid == ExtensionOID.KEY_USAGE:
                if not crit:
                    raise InvalidCertificate("KEY_USAGE must be critical")
                self.usage += self.extract_key_usage(extobj)
            elif ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                self.san = extract_gnames(extobj)
            elif ext.oid == ExtensionOID.ISSUER_ALTERNATIVE_NAME:
                self.issuer_san = extract_gnames(extobj)
            elif ext.oid == ExtensionOID.EXTENDED_KEY_USAGE:
                self.usage += self.extract_xkey_usage(extobj)
            elif ext.oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                for ad in extobj:
                    if not isinstance(ad.access_location, x509.UniformResourceIdentifier):
                        raise InvalidCertificate("Unsupported access_location: %s" % (ad.access_location,))
                    url = as_unicode(ad.access_location.value)

                    if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                        self.issuer_urls.append(url)
                    elif ad.access_method == AuthorityInformationAccessOID.OCSP:
                        self.ocsp_urls.append(url)
                    else:
                        raise InvalidCertificate("Unsupported access_method: %s" % (ad.access_method,))
            elif ext.oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
                for dp in extobj:
                    if dp.relative_name:
                        raise InvalidCertificate("DistributionPoint.relative_name not supported")
                    if dp.crl_issuer:
                        raise InvalidCertificate("DistributionPoint.crl_issuer not supported")
                    if dp.reasons:
                        raise InvalidCertificate("DistributionPoint.reasons not supported")

                    for gn in extract_gnames(dp.full_name):
                        if gn.startswith('uri:'):
                            self.crl_urls.append(gn[4:])
                        else:
                            raise InvalidCertificate("Unsupported DistributionPoint: %s" % (gn,))
            elif ext.oid == ExtensionOID.NAME_CONSTRAINTS:
                self.permit_subtrees = extract_gnames(extobj.permitted_subtrees)
                self.exclude_subtrees = extract_gnames(extobj.excluded_subtrees)
            elif ext.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                pass
            elif ext.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                pass
            elif ext.oid == ExtensionOID.OCSP_NO_CHECK:
                self.ocsp_nocheck = True
            elif ext.oid == ExtensionOID.TLS_FEATURE:
                for tls_feature_code in extobj:
                    if tls_feature_code == x509.TLSFeatureType.status_request:
                        self.ocsp_must_staple = True
                    elif tls_feature_code == x509.TLSFeatureType.status_request_v2:
                        self.ocsp_must_staple_v2 = True
                    else:
                        raise InvalidCertificate("Unsupported TLSFeature: %r" % (tls_feature_code,))
            elif ext.oid == ExtensionOID.INHIBIT_ANY_POLICY:
                self.inhibit_any = extobj.skip_certs
            else:
                raise InvalidCertificate("Unsupported extension in CSR: %s" % (ext,))

    def extract_xkey_usage(self, ext):
        """Walk oid list, return keywords.
        """
        oidmap = {v: k for k, v in XKU_CODE_TO_OID.items()}
        res = []
        for oid in ext:
            if oid in oidmap:
                res.append(oidmap[oid])
            else:
                raise InvalidCertificate("Unsupported ExtendedKeyUsage oid: %s" % (oid,))
        return res

    def extract_key_usage(self, ext):
        """Extract list of tags from KeyUsage extension.
        """
        res = []
        fields = KU_FIELDS[:]

        # "error-on-access", real funny
        if not ext.key_agreement:
            fields.remove('encipher_only')
            fields.remove('decipher_only')

        for k in fields:
            val = getattr(ext, k, False)
            if val:
                res.append(k)
        return res

    def get_name(self):
        """Create Name object from subject's DistinguishedName.
        """
        return load_name(self.subject)

    def get_san_gnames(self):
        """Return SubjectAltNames as GeneralNames
        """
        return load_gnames(self.san)

    def get_tls_features(self):
        """Return TLS Feature list
        """
        tls_features = []
        if self.ocsp_must_staple:
            tls_features.append(x509.TLSFeatureType.status_request)
        if self.ocsp_must_staple_v2:
            tls_features.append(x509.TLSFeatureType.status_request_v2)
        return tls_features

    def install_extensions(self, builder):
        """Add common extensions to Cert- or CSR builder.
        """

        # BasicConstraints, critical
        if self.ca:
            ext = x509.BasicConstraints(ca=True, path_length=self.path_length)
        else:
            ext = x509.BasicConstraints(ca=False, path_length=None)
        builder = builder.add_extension(ext, critical=True)

        # KeyUsage, critical
        ku_args = {k: k in self.usage for k in KU_FIELDS}
        if self.ca:
            ku_args.update(CA_DEFAULTS)
        elif not self.usage:
            ku_args.update(NONCA_DEFAULTS)
        for k in XKU_DEFAULTS:
            if k in self.usage:
                for k2 in XKU_DEFAULTS[k]:
                    ku_args[k2] = True
        ext = make_key_usage(**ku_args)
        builder = builder.add_extension(ext, critical=True)

        # ExtendedKeyUsage, critical
        xku = [x for x in self.usage if x not in KU_FIELDS]
        xku_bad = [x for x in xku if x not in XKU_CODE_TO_OID]
        if xku_bad:
            raise InvalidCertificate("Unknown usage keywords: %s" % (','.join(xku_bad),))
        if xku:
            xku_oids = [XKU_CODE_TO_OID[x] for x in xku]
            ext = x509.ExtendedKeyUsage(xku_oids)
            builder = builder.add_extension(ext, critical=True)

        # NameConstraints, critical
        if self.exclude_subtrees or self.permit_subtrees:
            if not self.ca:
                raise InvalidCertificate("NameConstraints applies only to CA certificates")
            allow = load_gnames(self.permit_subtrees) or None
            disallow = load_gnames(self.exclude_subtrees) or None
            ext = x509.NameConstraints(allow, disallow)
            builder = builder.add_extension(ext, critical=True)

        # SubjectAlternativeName
        if self.san:
            ext = x509.SubjectAlternativeName(self.get_san_gnames())
            builder = builder.add_extension(ext, critical=False)

        # CRLDistributionPoints
        if self.crl_urls:
            full_names = convert_urls_to_gnames(self.crl_urls)
            reasons = None
            crl_issuer = None
            point = x509.DistributionPoint(full_names, None, reasons, crl_issuer)
            ext = x509.CRLDistributionPoints([point])
            builder = builder.add_extension(ext, critical=False)

        # AuthorityInformationAccess
        if self.ocsp_urls or self.issuer_urls:
            oid = AuthorityInformationAccessOID.OCSP
            ocsp_list = [x509.AccessDescription(oid, gn) for gn in convert_urls_to_gnames(self.ocsp_urls)]
            oid = AuthorityInformationAccessOID.CA_ISSUERS
            ca_list = [x509.AccessDescription(oid, gn) for gn in convert_urls_to_gnames(self.issuer_urls)]
            ext = x509.AuthorityInformationAccess(ocsp_list + ca_list)
            builder = builder.add_extension(ext, critical=False)

        # OCSPNoCheck
        if self.ocsp_nocheck:
            ext = x509.OCSPNoCheck()
            builder = builder.add_extension(ext, critical=False)

        # TLSFeature: status_request, status_request_v2
        tls_features = self.get_tls_features()
        if tls_features:
            ext = x509.TLSFeature(tls_features)
            builder = builder.add_extension(ext, critical=False)

        # InhibitAnyPolicy
        if self.inhibit_any is not None:
            if not self.ca:
                raise InvalidCertificate("InhibitAnyPolicy applies only to CA certificates")
            ext = x509.InhibitAnyPolicy(self.inhibit_any)
            builder = builder.add_extension(ext, critical=True)

        # configured builder
        return builder

    def generate_request(self, privkey):
        """Create x509.CertificateSigningRequest based on current info.
        """
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(self.get_name())
        builder = self.install_extensions(builder)

        # create final request
        req = builder.sign(private_key=privkey, algorithm=get_hash_algo(privkey, 'CSR'), backend=get_backend())
        return req

    def generate_certificate(self, subject_pubkey, issuer_info, issuer_privkey, days):
        """Create x509.Certificate based on current info.
        """
        dt_now = datetime.utcnow()
        dt_start = dt_now - timedelta(hours=1)
        dt_end = dt_now + timedelta(days=days)

        self.serial_number = new_serial_number()

        builder = (x509.CertificateBuilder()
            .subject_name(self.get_name())
            .issuer_name(issuer_info.get_name())
            .not_valid_before(dt_start)
            .not_valid_after(dt_end)
            .serial_number(self.serial_number)
            .public_key(subject_pubkey))

        builder = self.install_extensions(builder)

        # SubjectKeyIdentifier
        ext = x509.SubjectKeyIdentifier.from_public_key(subject_pubkey)
        builder = builder.add_extension(ext, critical=False)

        # AuthorityKeyIdentifier
        ext = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_privkey.public_key())
        builder = builder.add_extension(ext, critical=False)

        # IssuerAlternativeName
        if issuer_info.san:
            ext = x509.IssuerAlternativeName(issuer_info.get_san_gnames())
            builder = builder.add_extension(ext, critical=False)

        # final cert
        cert = builder.sign(private_key=issuer_privkey, algorithm=get_hash_algo(issuer_privkey, 'CRT'), backend=get_backend())
        return cert

    def show(self, writeln):
        """Print out details.
        """
        if self.version is not None:
            writeln('Version: %s' % self.version)
        if self.serial_number is not None:
            writeln('Serial: %s' % serial_str(self.serial_number))
        if self.public_key_info:
            writeln('Public key: %s' % self.public_key_info)
        if self.subject:
            writeln('Subject: %s' % render_name(self.subject))
        show_list('SAN', self.san, writeln)
        show_list('Usage', self.usage, writeln)
        show_list('OCSP URLs', self.ocsp_urls, writeln)
        if self.issuer_name:
            writeln('Issuer Name: %s' % render_name(self.issuer_name))
        show_list('Issuer SAN', self.issuer_san, writeln)
        show_list('Issuer URLs', self.issuer_urls, writeln)
        show_list('CRL URLs', self.crl_urls, writeln)
        show_list('Permit', self.permit_subtrees, writeln)
        show_list('Exclude', self.exclude_subtrees, writeln)
        if self.ocsp_nocheck:
            show_list('OCSP NoCheck', ['True'], writeln)

        tls_features = []
        if self.ocsp_must_staple:
            tls_features.append('status_request')
        if self.ocsp_must_staple_v2:
            tls_features.append('status_request_v2')
        show_list('TLS Features', tls_features, writeln)
        if self.inhibit_any is not None:
            writeln('Inhibit ANY policy: skip_certs=%r' % self.inhibit_any)


class RevCertInfo:
    """Container for revoced certificate info.
    """
    def __init__(self, serial_number=None, reason=None, revocation_date=None,
                 invalidity_date=None, issuer_gnames=None, load=None):
        self.revocation_date = None
        self.serial_number = None
        self.reason = None              # CRLReason / ReasonFlags
        self.invalidity_date = None     # InvalidityDate
        self.issuer_gnames = None       # CertificateIssuer

        if load is None:
            self.serial_number = serial_number
            self.reason = reason
            self.revocation_date = revocation_date
            self.invalidity_date = invalidity_date
            self.issuer_gnames = issuer_gnames
        else:
            self.load_from_existing(load)
            if not self.issuer_gnames:
                self.issuer_gnames = issuer_gnames

    def generate_rcert(self, indirect_crl, cur_gnames):
        """Return x509.RevokedCertificate
        """
        if self.revocation_date is None:
            self.revocation_date = datetime.utcnow()

        builder = x509.RevokedCertificateBuilder()
        builder = builder.serial_number(self.serial_number)
        builder = builder.revocation_date(self.revocation_date)
        builder = self.install_extensions(builder, indirect_crl, cur_gnames)
        return builder.build(get_backend())

    def install_extensions(self, builder, indirect_crl, cur_gnames):
        """Install additional extensions to builder.
        """
        if self.reason is not None:
            code = CRL_REASON[self.reason]
            if code != x509.ReasonFlags.unspecified:
                ext = x509.CRLReason(code)
                builder = builder.add_extension(ext, critical=False)

        if self.invalidity_date is not None:
            ext = x509.InvalidityDate(self.invalidity_date)
            builder = builder.add_extension(ext, critical=False)

        if indirect_crl and self.issuer_gnames:
            if self.issuer_gnames != cur_gnames:
                glist = load_gnames(self.issuer_gnames)
                ext = x509.CertificateIssuer(glist)
                builder = builder.add_extension(ext, critical=True)
        elif indirect_crl and not self.issuer_gnames:
            raise InvalidCertificate("Indirect CRL requires issuer_gnames")

        return builder

    def load_from_existing(self, obj):
        """Load data from x509.RevokedCertificate
        """
        if not isinstance(obj, x509.RevokedCertificate):
            raise InvalidCertificate("Expect RevokedCertificate, got %s" % type(obj))

        self.serial_number = obj.serial_number
        self.revocation_date = obj.revocation_date

        for ext in obj.extensions:
            crit = ext.critical
            extobj = ext.value
            if ext.oid == CRLEntryExtensionOID.CRL_REASON:
                self.reason = CRL_REASON_MAP.get(extobj.reason)
            elif ext.oid == CRLEntryExtensionOID.INVALIDITY_DATE:
                self.invalidity_date = extobj.invalidity_date
            elif ext.oid == CRLEntryExtensionOID.CERTIFICATE_ISSUER:
                self.issuer_gnames = extract_gnames(extobj)
            else:
                raise InvalidCertificate("Unsupported extension in CRL: %s" % (ext,))

    def show(self, writeln):
        """Print info.
        """
        writeln('Revoked certificate:')
        if self.serial_number is not None:
            writeln('  Serial: %s' % serial_str(self.serial_number))
        if self.revocation_date is not None:
            writeln('  Revocation Date: %s' % self.revocation_date.isoformat(' '))
        if self.invalidity_date is not None:
            writeln('  Invalidity Date: %s' % self.invalidity_date.isoformat(' '))
        if self.reason is not None:
            writeln('  Reason: %s' % self.reason)
        show_list('  Issuer GNames', self.issuer_gnames, writeln)


class CRLInfo:
    """Container for certificate revocation object info.
    """
    def __init__(self, revoked_list=None,
                 next_update=None, last_update=None, crl_number=None, delta_crl_number=None,
                 crl_scope='all', indirect_crl=False, only_some_reasons=None, full_methods=None, relative_methods=None,
                 issuer_urls=None, ocsp_urls=None, freshest_urls=None,
                 load=None):
        """Initialize info object.
        """
        self.revoked_list = revoked_list or []
        self.issuer_name = None
        self.issuer_san = None
        self.auth_key_id = None
        self.next_update = next_update
        self.last_update = last_update
        self.crl_number = crl_number
        self.delta_crl_number = delta_crl_number

        # IssuingDistributionPoint
        self.crl_scope = crl_scope      # all,user,ca,attr
        self.indirect_crl = indirect_crl
        self.only_some_reasons = only_some_reasons or set()
        self.full_methods = full_methods
        self.relative_methods = relative_methods

        # AuthorityInformationAccess
        self.issuer_urls = maybe_parse(issuer_urls, parse_list)

        # Freshest CRL (a.k.a. Delta CRL Distribution Point)
        self.freshest_urls = maybe_parse(freshest_urls, parse_list)

        if load is not None:
            self.load_from_existing(load)

    def load_from_existing(self, obj):
        """Load certificate info from existing CRL.
        """
        if not isinstance(obj, x509.CertificateRevocationList):
            raise TypeError("Expect CertificateRevocationList")
        self.issuer_name = extract_name(obj.issuer)
        self.next_update = obj.next_update
        self.last_update = obj.last_update

        for ext in obj.extensions:
            crit = ext.critical
            extobj = ext.value
            if ext.oid == ExtensionOID.CRL_NUMBER:
                self.crl_number = extobj.crl_number
            elif ext.oid == ExtensionOID.DELTA_CRL_INDICATOR:
                self.delta_crl_number = extobj.crl_number
            elif ext.oid == ExtensionOID.ISSUER_ALTERNATIVE_NAME:
                self.issuer_san = extract_gnames(extobj)
            elif ext.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                self.authority_key_identifier = extobj.key_identifier
                self.authority_cert_issuer = extract_name(extobj.authority_cert_issuer)
                self.authority_cert_serial_number = extobj.authority_cert_serial_number
            elif ext.oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                # list of AccessDescription
                for ad in extobj:
                    if not isinstance(ad.access_location, x509.UniformResourceIdentifier):
                        raise InvalidCertificate("Unsupported access_location: %s" % (ad.access_location,))
                    url = as_unicode(ad.access_location.value)

                    if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                        self.issuer_urls.append(url)
                    else:
                        raise InvalidCertificate("Unsupported access_method: %s" % (ad.access_method,))
            elif ext.oid == ExtensionOID.FRESHEST_CRL:
                # list of DistributionPoint
                for dp in extobj:
                    if dp.relative_name:
                        raise InvalidCertificate("DistributionPoint.relative_name not supported")
                    if dp.crl_issuer:
                        raise InvalidCertificate("DistributionPoint.crl_issuer not supported")
                    if dp.reasons:
                        raise InvalidCertificate("DistributionPoint.reasons not supported")

                    for gn in extract_gnames(dp.full_name):
                        if gn.startswith('uri:'):
                            self.freshest_urls.append(gn[4:])
                        else:
                            raise InvalidCertificate("Unsupported DistributionPoint: %s" % (gn,))
            elif ext.oid == ExtensionOID.ISSUING_DISTRIBUTION_POINT:
                # IssuingDistributionPoint
                if extobj.only_contains_user_certs:
                    self.crl_scope = 'user'
                elif extobj.only_contains_ca_certs:
                    self.crl_scope = 'ca'
                elif extobj.only_contains_attribute_certs:
                    self.crl_scope = 'attr'
                else:
                    self.crl_scope = 'all'

                self.indirect_crl = extobj.indirect_crl
                self.full_methods = extract_gnames(extobj.full_name)
                self.relative_methods = extract_gnames(extobj.relative_name)
                if extobj.only_some_reasons:
                    self.only_some_reasons = set(CRL_REASON_MAP[f] for f in extobj.only_some_reasons)
            else:
                raise InvalidCertificate("Unsupported extension in CRL: %s" % (ext,))

        # load revoked certs
        cur_gnames = make_issuer_gnames(self.issuer_name, self.issuer_san)
        for r_cert_obj in obj:
            r_cert = RevCertInfo(load=r_cert_obj, issuer_gnames=cur_gnames)
            cur_gnames = r_cert.issuer_gnames
            self.revoked_list.append(r_cert)

    def install_extensions(self, builder):
        """Add common extensions to CRL builder.
        """
        # CRLNumber
        if self.crl_number is not None:
            ext = x509.CRLNumber(self.crl_number)
            builder = builder.add_extension(ext, critical=False)

        # DeltaCRLIndicator
        if self.delta_crl_number is not None:
            ext = x509.DeltaCRLIndicator(self.delta_crl_number)
            builder = builder.add_extension(ext, critical=True)

        # IssuingDistributionPoint
        args = {
            'full_name': None, 'relative_name': None,
            'only_contains_user_certs': False,
            'only_contains_ca_certs': False,
            'only_some_reasons': None, 'indirect_crl': False,
            'only_contains_attribute_certs': False}

        if self.crl_scope == 'ca':
            args['only_contains_ca_certs'] = True
        elif self.crl_scope == 'user':
            args['only_contains_user_certs'] = True
        elif self.crl_scope == 'attr':
            args['only_contains_attribute_certs'] = True
        elif self.crl_scope != 'all':
            raise ValueError('invalid scope: %r' % self.crl_scope)

        if self.indirect_crl:
            args['indirect_crl'] = True

        if self.only_some_reasons:
            args['only_some_reasons'] = frozenset([CRL_REASON[r] for r in self.only_some_reasons])

        if self.full_methods is not None:
            args['full_name'] = load_gnames(self.full_methods)
        elif self.relative_methods is not None:
            args['relative_name'] = load_gnames(self.relative_methods)

        if any(args.values()):
            ext = x509.IssuingDistributionPoint(**args)
            builder = builder.add_extension(ext, critical=True)

        # AuthorityInformationAccess
        if self.issuer_urls:
            oid = AuthorityInformationAccessOID.CA_ISSUERS
            ca_list = [x509.AccessDescription(oid, gn) for gn in convert_urls_to_gnames(self.issuer_urls)]
            ext = x509.AuthorityInformationAccess(ca_list)
            builder = builder.add_extension(ext, critical=False)

        # FreshestCRL
        if self.freshest_urls:
            full_names = convert_urls_to_gnames(self.freshest_urls)
            point = x509.DistributionPoint(full_names, None, None, None)
            ext = x509.FreshestCRL([point])
            builder = builder.add_extension(ext, critical=False)

        return builder

    def generate_crl(self, issuer_privkey, issuer_info, days):
        """Return x509.CertificateRevocationList.
        """
        if 'crl_sign' not in issuer_info.usage:
            raise InvalidCertificate("CA cert needs to have 'crl_sign' usage set.")

        dt_now = datetime.utcnow()
        dt_next = dt_now + timedelta(days=days)

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(issuer_info.get_name())
        builder = builder.last_update(dt_now)
        builder = builder.next_update(dt_next)
        builder = self.install_extensions(builder)

        # IssuerAlternativeName
        if issuer_info.san:
            ext = x509.IssuerAlternativeName(issuer_info.get_san_gnames())
            builder = builder.add_extension(ext, critical=False)

        # AuthorityKeyIdentifier
        ext = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_privkey.public_key())
        builder = builder.add_extension(ext, critical=False)

        # add revoked certs
        cur_gnames = make_issuer_gnames(issuer_info.subject, issuer_info.san)
        for rev_cert in self.revoked_list:
            rcert = rev_cert.generate_rcert(self.indirect_crl, cur_gnames)
            builder = builder.add_revoked_certificate(rcert)
            cur_gnames = rev_cert.issuer_gnames

        crl = builder.sign(private_key=issuer_privkey, algorithm=get_hash_algo(issuer_privkey, 'CRL'), backend=get_backend())
        return crl

    def show(self, writeln):
        """Print out details.
        """
        if self.issuer_name:
            writeln('Issuer Name: %s' % render_name(self.issuer_name))
        show_list('Issuer SAN', self.issuer_san, writeln)
        writeln('CRL Scope: %s' % self.crl_scope)
        if self.crl_number is not None:
            writeln('CRL Number: %s' % serial_str(self.crl_number))
        if self.delta_crl_number is not None:
            writeln('Delta CRL Number: %s' % serial_str(self.delta_crl_number))
        if self.last_update:
            writeln('Last update: %s' % self.last_update.isoformat(' '))
        if self.next_update:
            writeln('Next update: %s' % self.next_update.isoformat(' '))
        if self.indirect_crl:
            writeln('Indirect CRL: True')
        if self.only_some_reasons:
            show_list('OnlySomeReasons', list(sorted(self.only_some_reasons)), writeln)
        show_list('Full Methods', self.full_methods, writeln)
        show_list('Relative Methods', self.relative_methods, writeln)
        show_list('Issuer URLs', self.issuer_urls, writeln)
        show_list('FreshestCRL URLs', self.freshest_urls, writeln)

        for rcert in self.revoked_list:
            rcert.show(writeln)


def create_x509_req(privkey, subject_info):
    """Create x509.CertificateSigningRequest.
    """
    if not valid_privkey(privkey):
        raise ValueError("Invalid private key")
    if isinstance(subject_info, (x509.Certificate, x509.CertificateSigningRequest)):
        subject_info = CertInfo(load=subject_info)
    elif not isinstance(subject_info, CertInfo):
        raise ValueError("Expect certinfo")
    return subject_info.generate_request(privkey)


def create_x509_cert(issuer_privkey, subject_pubkey, subject_info, issuer_info, days):
    """Create x509.Certificate
    """
    if not valid_privkey(issuer_privkey):
        raise ValueError("Invalid issuer private key")
    if not valid_pubkey(subject_pubkey):
        raise ValueError("Invalid subject public key")

    if isinstance(subject_info, x509.CertificateSigningRequest):
        subject_info = CertInfo(load=subject_info)
    elif not isinstance(subject_info, CertInfo):
        raise ValueError("Expect subject_info to be CertInfo or x509.CertificateSigningRequest")

    if isinstance(issuer_info, x509.Certificate):
        issuer_info = CertInfo(load=issuer_info)
    elif not isinstance(issuer_info, CertInfo):
        raise ValueError("Expect issuer_info to be CertInfo or x509.Certificate")

    return subject_info.generate_certificate(subject_pubkey, issuer_info, issuer_privkey, days)


def create_x509_crl(issuer_privkey, issuer_info, crl_info, days):
    """Create x509.CertificateRevocationList
    """
    if not valid_privkey(issuer_privkey):
        raise ValueError("Invalid issuer private key")
    if isinstance(issuer_info, (x509.Certificate, x509.CertificateSigningRequest)):
        issuer_info = CertInfo(load=issuer_info)
    elif not isinstance(issuer_info, CertInfo):
        raise ValueError("Expect issuer_info to be CertInfo or x509.Certificate")

    if not isinstance(issuer_info, CertInfo):
        issuer_info = CertInfo(load=issuer_info)
    if not isinstance(crl_info, CRLInfo):
        crl_info = CRLInfo(load=crl_info)

    return crl_info.generate_crl(issuer_privkey, issuer_info, days)

#
# Command-line UI
#

def load_gpg_file(fn):
    """Decrypt file.
    """
    ext = os.path.splitext(fn)[1].lower()
    if ext not in ('.gpg', '.pgp'):
        return open(fn, 'rb').read()

    cmd = ['gpg', '-q', '-d', '--batch', '--no-tty', fn]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    log = as_unicode(err, 'replace').strip()
    if p.returncode != 0:
        die("%s: gpg failed: \n  %s", fn, log)

    # cannot say "you need to check signatures" to gpg...
    if "Good signature" not in log:
        msg("%s: No signature found", fn)
        if log:
            msg(log)

    return out


def load_key(fn, psw=None):
    """Read private key, decrypt if needed.
    """
    if not fn:
        die("Need private key")
    if psw:
        psw = as_bytes(psw)
    data = load_gpg_file(fn)
    key = load_pem_private_key(data, password=psw, backend=get_backend())
    return key


def load_req(fn):
    """Read CSR file.
    """
    data = open(fn, 'rb').read()
    req = x509.load_pem_x509_csr(data, get_backend())
    return req


def load_cert(fn):
    """Read CRT file.
    """
    data = open(fn, 'rb').read()
    crt = x509.load_pem_x509_certificate(data, get_backend())
    return crt


def load_crl(fn):
    """Read CRL file.
    """
    data = open(fn, 'rb').read()
    crl = x509.load_pem_x509_crl(data, get_backend())
    return crl


def load_password(fn):
    """Read password from potentially gpg-encrypted file.
    """
    if not fn:
        return None
    data = load_gpg_file(fn)
    data = data.strip(b'\n')
    return data


def die(txt, *args):
    """Print message and exit.
    """
    if args:
        txt = txt % args
    sys.stderr.write(txt + '\n')
    sys.exit(1)


def msg(txt, *args):
    """Print message to stderr.
    """
    if QUIET:
        return
    if args:
        txt = txt % args
    sys.stderr.write(txt + '\n')


def do_output(data, args, cmd):
    """Output X509 structure
    """
    if args.text:
        cmd = ['openssl', cmd, '-text']
        if args.out:
            cmd.extend(['-out', args.out])
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        p.communicate(data)
    elif args.out:
        with open(args.out, 'wb') as f:
            f.write(as_bytes(data))
    else:
        sys.stdout.write(as_unicode(data))
        sys.stdout.flush()


def newkey_command(args):
    """Create new key.
    """
    # parse key-type argument
    short = {'ec': 'ec:secp256r1', 'rsa': 'rsa:2048', 'dsa': 'dsa:2048'}
    if len(args.files) > 1:
        die("Unexpected positional arguments")
    if args.files:
        keydesc = args.files[0]
    else:
        keydesc = 'ec'
    keydesc = short.get(keydesc, keydesc)

    # create key
    tmp = keydesc.lower().split(':')
    if len(tmp) != 2:
        die("Bad key spec: %s", keydesc)
    t, v = tmp
    if t == 'ec':
        try:
            k = new_ec_key(v)
        except (ValueError, KeyError):
            die("Invalid curve: %s", v)
    elif t == 'rsa':
        try:
            k = new_rsa_key(int(v))
        except ValueError:
            die("Invalid value for RSA bits: %s", v)
    elif t == 'dsa':
        try:
            k = new_dsa_key(int(v))
        except ValueError:
            die("Invalid value for RSA bits: %s", v)
    else:
        die('Bad key type: %s', t)
    msg("New key: %s", keydesc)

    # Output with optional encryption
    psw = load_password(args.password_file)
    pem = key_to_pem(k, psw)
    do_output(pem, args, t)


def info_from_args(args):
    """Collect command-line arguments into CertInfo.
    """
    return CertInfo(
        subject=parse_dn(args.subject),
        usage=parse_list(args.usage),
        alt_names=parse_list(args.san),
        ocsp_nocheck=args.ocsp_nocheck,
        ocsp_must_staple=args.ocsp_must_staple,
        ocsp_must_staple_v2=args.ocsp_must_staple_v2,
        ocsp_urls=parse_list(args.ocsp_urls),
        crl_urls=parse_list(args.crl_urls),
        issuer_urls=parse_list(args.issuer_urls),
        permit_subtrees=parse_list(args.permit_subtrees),
        exclude_subtrees=parse_list(args.exclude_subtrees),
        ca=args.CA,
        inhibit_any=args.inhibit_any,
        path_length=args.path_length)


def msg_show(ln):
    """Show indented line.
    """
    msg('  %s', ln)


def do_sign(subject_csr, issuer_obj, issuer_key, days, path_length, reqInfo, reset_info=None):
    """Sign with already loaded parameters.
    """
    # Certificate duration
    if days is None:
        die("Need --days")
    if days <= 0:
        die("Invalid --days")

    # Load CA info
    issuer_info = CertInfo(load=issuer_obj)

    # Load certificate request
    subject_info = CertInfo(load=subject_csr)
    if reset_info:
        subject_info = reset_info

    # Check CA parameters
    if not same_pubkey(subject_csr, issuer_obj):
        if not issuer_info.ca:
            die("Issuer must be CA.")
        if 'key_cert_sign' not in issuer_info.usage:
            die("Issuer CA is not allowed to sign certs.")
    if subject_info.ca:
        if not same_pubkey(subject_csr, issuer_obj):
            # not self-signing, check depth
            if issuer_info.path_length is None:
                pass
            elif issuer_info.path_length == 0:
                die("Issuer cannot sign sub-CAs")
            elif path_length is None:
                subject_info.path_length = issuer_info.path_length - 1
            elif issuer_info.path_length - 1 < path_length:
                die("--path-length not allowed by issuer")

    # Load subject's public key, check sanity
    pkey = subject_csr.public_key()
    if not valid_pubkey(pkey):
        die("Invalid public key")

    # Report
    if subject_info.ca:
        msg('Signing CA cert [%s] - %s', get_key_name(pkey), reqInfo)
    else:
        msg('Signing end-entity cert [%s] - %s', get_key_name(pkey), reqInfo)
    msg('Issuer name: %s', render_name(issuer_info.subject))
    msg('Subject:')
    subject_info.show(msg_show)

    # Load CA private key
    if not same_pubkey(issuer_key, issuer_obj):
        die("--ca-private-key does not match --ca-info data")

    # Stamp request
    cert = create_x509_cert(issuer_key, subject_csr.public_key(), subject_info, issuer_info, days=days)
    msg('Serial: %s', serial_str(subject_info.serial_number))
    return cert


def req_command(args):
    """Load command-line arguments, create Certificate Signing Request (CSR).
    """
    if args.files:
        die("Unexpected positional arguments")

    subject_info = info_from_args(args)

    if subject_info.ca:
        msg('Request for CA cert')
    else:
        msg('Request for end-entity cert')
    subject_info.show(msg_show)

    # Load private key, create signing request
    key = load_key(args.key, load_password(args.password_file))
    req = create_x509_req(key, subject_info)
    do_output(req_to_pem(req), args, 'req')


def sign_command(args):
    """Load command-line arguments, output cert.
    """
    if args.files:
        die("Unexpected positional arguments")

    # Load certificate request
    if not args.request:
        die("Need --request")
    subject_csr = load_req(args.request)

    reset_info = None
    if args.reset:
        reset_info = info_from_args(args)

    # Load CA info
    if not args.ca_info:
        die("Need --ca-info")
    if args.ca_info.endswith('.csr'):
        issuer_obj = load_req(args.ca_info)
    else:
        issuer_obj = load_cert(args.ca_info)

    # Load CA private key
    issuer_key = load_key(args.ca_key, load_password(args.password_file))
    if not same_pubkey(issuer_key, issuer_obj):
        die("--ca-private-key does not match --ca-info data")

    # Certificate generation
    cert = do_sign(subject_csr, issuer_obj, issuer_key, args.days, args.path_length, args.request, reset_info=reset_info)

    # Write certificate
    do_output(cert_to_pem(cert), args, 'x509')


def selfsign_command(args):
    """Load command-line arguments, create self-signed CRT.
    """
    if args.files:
        die("Unexpected positional arguments")

    subject_info = info_from_args(args)

    if subject_info.ca:
        msg('Selfsigning CA cert')
    else:
        msg('Selfsigning end-entity cert')
    subject_info.show(msg_show)

    # Load private key, create signing request
    key = load_key(args.key, load_password(args.password_file))
    subject_csr = create_x509_req(key, subject_info)

    # sign created request
    cert = do_sign(subject_csr, subject_csr, key, args.days, args.path_length, '<selfsign>')
    do_output(cert_to_pem(cert), args, 'x509')


def update_crl_command(args):
    """Load command-line arguments, output new CRL.
    """
    if args.files:
        die("Unexpected positional arguments")

    if not args.ca_info or not args.ca_key or not args.days:
        die("need --ca-key, --ca-info, --days")

    # Load CA info
    issuer_obj = load_cert(args.ca_info)
    issuer_info = CertInfo(load=issuer_obj)

    # Load CA private key
    issuer_key = load_key(args.ca_key, load_password(args.password_file))
    if not same_pubkey(issuer_key, issuer_obj):
        die("--ca-key does not match --ca-info data")

    if args.crl:
        crl_info = CRLInfo(load=load_crl(args.crl))
    else:
        crl_info = CRLInfo()
        crl_info.issuer_urls = issuer_info.issuer_urls

    if args.crl_number:
        crl_info.crl_number = load_number(args.crl_number)
    if args.delta_crl_number:
        crl_info.delta_crl_number = load_number(args.delta_crl_number)
    if args.indirect_crl:
        crl_info.indirect_crl = True
    if args.crl_reasons:
        crl_info.only_some_reasons = set(parse_list(args.crl_reasons))

    reason = None
    if args.reason:
        reason = CRL_REASON[args.reason]

    invalidity_date = None
    if args.invalidity_date:
        invalidity_date = load_date(args.invalidity_date)

    revocation_date = datetime.utcnow()

    if args.issuer_urls:
        crl_info.issuer_urls = parse_list(args.issuer_urls)

    if args.freshest_urls:
        crl_info.freshest_urls = parse_list(args.freshest_urls)

    for crt_fn in (args.revoke_certs or []):
        cert_obj = load_cert(crt_fn)
        cert = CertInfo(load=cert_obj)
        rcert = RevCertInfo(serial_number=cert.serial_number, reason=reason,
                            issuer_gnames=make_issuer_gnames(cert.issuer_name, cert.issuer_san),
                            revocation_date=revocation_date,
                            invalidity_date=invalidity_date)
        crl_info.revoked_list.append(rcert)

    for crt_serial in (args.revoke_serials or []):
        serial_number = load_number(crt_serial)
        rcert = RevCertInfo(serial_number=serial_number, reason=reason,
                            issuer_gnames=make_issuer_gnames(issuer_info.subject, issuer_info.san),
                            revocation_date=revocation_date,
                            invalidity_date=invalidity_date)
        crl_info.revoked_list.append(rcert)

    res = create_x509_crl(issuer_key, issuer_info, crl_info, args.days)
    do_output(crl_to_pem(res), args, 'crl')


def show_command_sysca(args):
    """Dump .crt and .csr files.
    """
    for fn in args.files:
        ext = os.path.splitext(fn)[1].lower()
        if ext == '.csr':
            req = CertInfo(load=load_req(fn))
            req.show(msg_show)
        elif ext == '.crt':
            crt = CertInfo(load=load_cert(fn))
            crt.show(msg_show)
        elif ext == '.crl':
            crl = CRLInfo(load=load_crl(fn))
            crl.show(msg_show)
        else:
            die("Unsupported file: %s", fn)


def show_command_openssl(args):
    """Dump .crt and .csr files via openssl tool.
    """
    for fn in args.files:
        ext = os.path.splitext(fn)[1].lower()
        if ext == '.csr':
            cmd = ['openssl', 'req', '-in', fn, '-text']
        elif ext == '.crt':
            cmd = ['openssl', 'x509', '-in', fn, '-text']
        elif ext == '.crl':
            cmd = ['openssl', 'crl', '-in', fn, '-text']
        else:
            die("Unsupported file: %s", fn)
        subprocess.check_call(cmd)


def show_command(args):
    """Dump using either internal code or openssl tool.
    """
    if args.text:
        show_command_openssl(args)
    else:
        show_command_sysca(args)


def version_info():
    """Info string for --version.
    """
    b = default_backend()
    bver = b.name
    if hasattr(b, 'openssl_version_text'):
        bver = b.openssl_version_text()
    return '%s %s (cryptography %s, %s)' % ('%(prog)s', __version__, crypto_version, bver)


def setup_args():
    """Create ArgumentParser
    """
    p = argparse.ArgumentParser(description=__doc__.strip(), fromfile_prefix_chars='@',
                                usage="%(prog)s --help | --version\n" +
                                "       %(prog)s new-key [KEY_TYPE] [--password-file FN] [--out FN]\n" +
                                "       %(prog)s request --key KEY_FILE [--subject DN] [--san ALT] [...]\n" +
                                "       %(prog)s selfsign --key KEY_FILE --days N [--subject DN] [--san ALT] [...]\n" +
                                "       %(prog)s sign --request FN --ca-key FN --ca-info FN --days N [--reset] [...]\n" +
                                "       %(prog)s update-crl --ca-key FN --ca-info FN [--crl FN] [...]\n" +
                                "       %(prog)s show FILE")
    p.add_argument('--version', help='show version and exit', action='version', version=version_info())
    p.add_argument('--password-file', help='File to load password from', metavar='FN')
    p.add_argument('--text', help='Add human-readable text about output', action='store_true')
    p.add_argument('--out', help='File to write output to, instead stdout', metavar='FN')
    p.add_argument('--quiet', '-q', help='Be quiet', action='store_true')
    p.add_argument('command', help=argparse.SUPPRESS)

    p.add_argument_group('Command "new-key"',
                         "Generate new EC, RSA or DSA key.  Key type can be either ec:<curve>, "
                         "rsa:<bits> or dsa:<bits>.  Default: ec:secp256r1.")

    g2 = p.add_argument_group('Command "request" and "selfsign"',
                              "Create certificate request or selfsigned certificate for private key")
    g2.add_argument('--key', help='Private key file', metavar='FN')

    g2 = p.add_argument_group("Certificate fields")
    g2.add_argument('--subject', help='Subject Distinguished Name - /CN=foo/O=Org/OU=Web/')
    g2.add_argument('--san',
                    help='SubjectAltNames - dns:hostname, email:addrspec, ip:ipaddr, uri:url, dn:DirName.',
                    metavar='GNAMES')
    g2.add_argument('--CA', help='Request CA cert.  Default: not set.', action='store_true')
    g2.add_argument('--path-length',
                    help='Max levels of sub-CAs.  Default: 0',
                    type=int, default=None, metavar='DEPTH')
    g2.add_argument('--usage', help='Keywords: client, server, code, email, time, ocsp.')
    g2.add_argument('--ocsp-urls', help='URLs for OCSP info.', metavar='URLS')
    g2.add_argument('--ocsp-nocheck', help='Disable OCSP check.', action='store_true')
    g2.add_argument('--ocsp-must-staple', help='OCSP Must-Staple.', action='store_true')
    g2.add_argument('--ocsp-must-staple-v2', help='OCSP Must-Staple V2.', action='store_true')
    g2.add_argument('--crl-urls', help='URLs URL for CRL data.', metavar='URLS')
    g2.add_argument('--issuer-urls', help='URLs for issuer cert.', metavar='URLS')
    g2.add_argument('--permit-subtrees', help='Allowed NameConstraints.', metavar='GNAMES')
    g2.add_argument('--exclude-subtrees', help='Disallowed NameConstraints.', metavar='GNAMES')
    g2.add_argument('--inhibit-any', help='Number of levels after which "any" policy is ignored.', metavar='N', type=int)

    g3 = p.add_argument_group('Command "sign"',
                              "Create certificate for key in certificate request.  "
                              "All metadata is taken from certificate request file.")
    g3.add_argument('--request', help='Filename of certificate request (CSR) to be signed.', metavar='FN')
    g3.add_argument('--reset', help='Rewrite all info fields.  Default: no.', action='store_true')
    g3.add_argument('--ca-key', help='Private key file.', metavar='FN')
    g3.add_argument('--ca-info', help='Filename of CA details (CRT or CSR).', metavar='FN')
    g3.add_argument('--days', help='Certificate lifetime in days', type=int)

    g4 = p.add_argument_group('Command "update-crl"',
                              "Create/update certificate revocation list.  "
                              "CA key is given by: --ca-key, --ca-info.  Lifetime by --days."
                              )
    g4.add_argument('--crl', help='Filename of certificate revocation list (CRL) to be updated.', metavar='FN')
    g4.add_argument('--crl-number', help='Version number for main CRL', metavar='VER')
    g4.add_argument('--delta-crl-number', help='Version number for parent CRL', metavar='VER')
    g4.add_argument('--revoke-certs', help='Certificate files to add', metavar='FN', nargs='+')
    g4.add_argument('--revoke-serials', help='Certificate serial numbers to add', metavar='NUM', nargs='+')
    g4.add_argument('--reason', help='Reason for revocation')
    g4.add_argument('--invalidity-date', help='Consider certificate invalid from date', metavar='DATE')
    g4.add_argument('--crl-scope', help='CRL scope, one of: all, user, ca, attr.  Default: all', metavar='SCOPE')
    g4.add_argument('--crl-reasons', help='Limit CRL scope to only list of reasons', metavar='REASONS')
    g4.add_argument('--freshest-urls', help='Freshest CRL URLs', metavar='URLS')
    g4.add_argument('--indirect-crl', help='Set Indirect-CRL flag', action='store_true')

    g5 = p.add_argument_group('Command "show"',
                              "Show CSR or CRT file contents.  Takes .crt or .csr filenames as arguments.")
    g5.add_argument('files', help=argparse.SUPPRESS, nargs='*')

    return p


def run_sysca(argv):
    """Load arguments, select and run command.
    """
    global QUIET

    ap = setup_args()
    args = ap.parse_args(argv)
    if args.quiet:
        QUIET = True
    if args.command == 'new-key':
        newkey_command(args)
    elif args.command == 'request':
        req_command(args)
    elif args.command == 'sign':
        sign_command(args)
    elif args.command == 'selfsign':
        selfsign_command(args)
    elif args.command == 'update-crl':
        update_crl_command(args)
    elif args.command == 'show':
        show_command(args)
    else:
        die("Unknown command: %s", args.command)


def main():
    """Command-line application entry point.
    """
    try:
        return run_sysca(sys.argv[1:])
    except InvalidCertificate as ex:
        die(str(ex))


if __name__ == '__main__':
    main()

