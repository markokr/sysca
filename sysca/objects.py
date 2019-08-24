"""Python objects <> cryptography objects.
"""

import ipaddress

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier, NameOID, AuthorityInformationAccessOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat,
    BestAvailableEncryption, NoEncryption,
    load_pem_private_key, load_der_private_key,
    load_pem_public_key, load_der_public_key,
)

from .compat import PUBKEY_CLASSES, PRIVKEY_CLASSES, X509_CLASSES
from .exceptions import InvalidCertificate
from .files import load_gpg_file, is_pem_data
from .formats import (
    as_bytes, as_unicode,
    parse_list, parse_dn,
    list_escape, render_name,
)

__all__ = (
    "extract_name", "extract_gnames", "extract_policy",
    "extract_distribution_point_urls", "extract_auth_access",
    "make_policy", "make_name", "make_gnames", "make_key_usage",
    "serialize", "convert_urls_to_gnames",
    "load_key", "load_pub_key", "load_req", "load_cert", "load_crl",
)


DN_CODE_TO_OID = {
    "CN": NameOID.COMMON_NAME,

    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,     # multi

    "C": NameOID.COUNTRY_NAME,
    "L": NameOID.LOCALITY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,

    "SN": NameOID.SURNAME,
    "GN": NameOID.GIVEN_NAME,
    "T": NameOID.TITLE,
    "P": NameOID.PSEUDONYM,

    "GQ": NameOID.GENERATION_QUALIFIER,
    "DQ": NameOID.DN_QUALIFIER,

    "UID": NameOID.USER_ID,
    "XUID": NameOID.X500_UNIQUE_IDENTIFIER,
    "EMAIL": NameOID.EMAIL_ADDRESS,
    "SERIAL": NameOID.SERIAL_NUMBER,
    "SA": NameOID.STREET_ADDRESS,       # multi
    "PA": NameOID.POSTAL_ADDRESS,       # multi
    "PC": NameOID.POSTAL_CODE,

    "JC": NameOID.JURISDICTION_COUNTRY_NAME,
    "JL": NameOID.JURISDICTION_LOCALITY_NAME,
    "JST": NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME,

    "BC": NameOID.BUSINESS_CATEGORY,    # multi
    "DC": NameOID.DOMAIN_COMPONENT,     # multi
}

DN_ALLOW_MULTIPLE = set(["STREET", "BC", "DC", "OU", "SA", "PA"])

#
# Converters
#


def extract_name(name):
    """Convert Name object to shortcut-dict.
    """
    if name is None:
        return None
    if not isinstance(name, x509.Name):
        raise TypeError("Expect x509.Name")
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
    if not isinstance(ext_name_list, (list, x509.CertificateIssuer,
                                      x509.SubjectAlternativeName, x509.IssuerAlternativeName)):
        raise TypeError("unexpected type: %r" % ext_name_list)
    res = []
    for gn in ext_name_list:
        if isinstance(gn, x509.RFC822Name):
            res.append("email:" + as_unicode(gn.value))
        elif isinstance(gn, x509.DNSName):
            res.append("dns:" + as_unicode(gn.value))
        elif isinstance(gn, x509.UniformResourceIdentifier):
            res.append("uri:" + as_unicode(gn.value))
        elif isinstance(gn, x509.IPAddress):
            if isinstance(gn.value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                res.append("net:" + str(gn.value))
            else:
                res.append("ip:" + str(gn.value))
        elif isinstance(gn, x509.DirectoryName):
            val = extract_name(gn.value)
            res.append("dn:" + render_name(val))
        else:
            raise InvalidCertificate("Unsupported subjectAltName type: %s" % (gn,))
    return res


def extract_policy(pol):
    """Convert PolicyInformation into string format used by --add-policy
    """
    if not isinstance(pol, x509.PolicyInformation):
        raise TypeError("Expect x509.PolicyInformation")
    pol_oid = pol.policy_identifier.dotted_string
    if not pol.policy_qualifiers:
        return pol_oid
    policy_qualifiers = []
    for q in pol.policy_qualifiers:
        qual = {}
        if isinstance(q, str):
            qual["P"] = q
        else:
            if q.notice_reference is not None:
                if q.notice_reference.organization:
                    qual["O"] = q.notice_reference.organization
                if q.notice_reference.notice_numbers:
                    qual["N"] = ":".join([str(n) for n in q.notice_reference.notice_numbers])
            if q.explicit_text:
                qual["T"] = q.explicit_text
        policy_qualifiers.append(list_escape(render_name(qual.items(), "|")))
    return "%s:%s" % (pol_oid, ",".join(policy_qualifiers))


def make_policy(txt):
    """Create PolicyInformation from --add-policy value
    """
    tmp = txt.split(":", 1)
    pol_oid = ObjectIdentifier(tmp[0])
    quals = None
    if len(tmp) > 1:
        quals = []
        for elem in parse_list(tmp[1]):
            d = dict(parse_dn(elem, "|"))
            klist = list(d.keys())
            if d.get("P"):
                quals.append(d.get("P"))
                if klist != ["P"]:
                    raise InvalidCertificate("Bad policy spec: P must be alone")
                continue
            klist = [k for k in klist if k not in ("T", "N", "O")]
            if klist:
                raise InvalidCertificate("Bad policy spec: unknown fields: %r" % klist)
            ref = None
            nums = None
            if d.get("N"):
                nums = [int(n) for n in d.get("N").split(":")]
            if d.get("O") or nums:
                ref = x509.NoticeReference(d.get("O", ""), nums or [])
            quals.append(x509.UserNotice(ref, d.get("T")))
    return x509.PolicyInformation(pol_oid, quals)


def make_name(name_att_list):
    """Create Name object from list of tuples.
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


def make_gnames(gname_list):
    """Converts list of prefixed strings to GeneralName list.
    """
    gnames = []
    for alt in gname_list:
        if ":" not in alt:
            raise InvalidCertificate("Invalid gname: %s" % (alt,))
        t, val = alt.split(":", 1)
        t = t.lower().strip()
        val = val.strip()
        if t == "dn":
            gn = x509.DirectoryName(make_name(parse_dn(val)))
        elif t == "dns":
            gn = x509.DNSName(val)
        elif t == "email":
            gn = x509.RFC822Name(val)
        elif t == "uri":
            gn = x509.UniformResourceIdentifier(val)
        elif t == "ip":
            if val.find(":") >= 0:
                gn = x509.IPAddress(ipaddress.IPv6Address(val))
            else:
                gn = x509.IPAddress(ipaddress.IPv4Address(val))
        elif t == "net":
            if val.find(":") >= 0:
                gn = x509.IPAddress(ipaddress.IPv6Network(val))
            else:
                gn = x509.IPAddress(ipaddress.IPv4Network(val))
        else:
            raise InvalidCertificate("Invalid GeneralName: " + alt)
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


def serialize(obj, encoding="pem", password=None):
    """Returns standard serialization for object.

    Supports: certificate, certificate request, CRL, public and private keys.

    Standard formats for all types:
        pem - textual format
        der - binary format

    Experimental formats for public and private keys:
        ssh - compatible with openssh
        raw - eddsa keys

    Returns string value for textual formats, bytes otherwise.
    """
    ENCMAP = {"pem": Encoding.PEM, "der": Encoding.DER, "ssh": Encoding.OpenSSH}
    if hasattr(Encoding, "Raw"):
        ENCMAP["raw"] = getattr(Encoding, "Raw")
    if encoding not in ENCMAP:
        raise ValueError("Unsupported output format: %s" % encoding)

    enc = ENCMAP[encoding]
    res = None
    if isinstance(obj, PRIVKEY_CLASSES):
        fmt = PrivateFormat.PKCS8
        hide = NoEncryption()
        if encoding == "raw":
            if password:
                raise ValueError("Raw format does not support password")
            fmt = getattr(PrivateFormat, "Raw")
        elif password:
            hide = BestAvailableEncryption(as_bytes(password))
        if encoding == "ssh":
            fmt = PrivateFormat.TraditionalOpenSSL
        res = obj.private_bytes(enc, fmt, hide)
    elif password is not None:
        raise ValueError("Only private keys can have password protection")
    elif isinstance(obj, PUBKEY_CLASSES):
        fmt = PublicFormat.SubjectPublicKeyInfo
        if encoding == "ssh":
            fmt = PublicFormat.OpenSSH
        elif encoding == "raw":
            fmt = getattr(PublicFormat, "Raw")
        res = obj.public_bytes(enc, fmt)
    elif isinstance(obj, X509_CLASSES):
        res = obj.public_bytes(enc)
    else:
        raise TypeError("Unsupported type for serialize()")

    if enc in (Encoding.PEM, Encoding.OpenSSH):
        txt = res.decode("utf8")
        if txt[-1] != "\n":
            return txt + "\n"
        return txt
    return res


def convert_urls_to_gnames(url_list):
    """Return urls as GeneralNames
    """
    urls = ["uri:" + u for u in url_list]
    return make_gnames(urls)


def extract_distribution_point_urls(extobj):
    if not isinstance(extobj, (x509.CRLDistributionPoints, x509.FreshestCRL)):
        raise TypeError("Expect CRLDistributionPoints or FreshestCRL")
    urls = []
    for dp in extobj:
        if dp.relative_name:
            raise InvalidCertificate("DistributionPoint.relative_name not supported")
        if dp.crl_issuer:
            raise InvalidCertificate("DistributionPoint.crl_issuer not supported")
        if dp.reasons:
            raise InvalidCertificate("DistributionPoint.reasons not supported")

        for gn in extract_gnames(dp.full_name):
            if gn.startswith("uri:"):
                urls.append(gn[4:])
            else:
                raise InvalidCertificate("Unsupported DistributionPoint: %s" % (gn,))
    return urls


def extract_auth_access(extobj):
    if not isinstance(extobj, (x509.AuthorityInformationAccess)):
        raise TypeError("Unexpected type: %r" % extobj)
    issuer_urls, ocsp_urls = [], []
    for ad in extobj:
        if not isinstance(ad.access_location, x509.UniformResourceIdentifier):
            raise InvalidCertificate("Unsupported access_location: %s" % (ad.access_location,))
        url = as_unicode(ad.access_location.value)

        if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            issuer_urls.append(url)
        elif ad.access_method == AuthorityInformationAccessOID.OCSP:
            ocsp_urls.append(url)
        else:
            raise InvalidCertificate("Unsupported access_method: %s" % (ad.access_method,))
    return issuer_urls, ocsp_urls


def load_key(fn, psw=None):
    """Read private key, decrypt if needed.
    """
    if psw:
        psw = as_bytes(psw)
    data = load_gpg_file(fn)
    if is_pem_data(data):
        key = load_pem_private_key(data, password=psw, backend=default_backend())
    else:
        key = load_der_private_key(data, password=psw, backend=default_backend())
    return key


def load_pub_key(fn):
    """Read public key file.
    """
    data = open(fn, "rb").read()
    if is_pem_data(data):
        return load_pem_public_key(data, default_backend())
    return load_der_public_key(data, default_backend())


def load_req(fn):
    """Read CSR file.
    """
    data = open(fn, "rb").read()
    if is_pem_data(data):
        return x509.load_pem_x509_csr(data, default_backend())
    return x509.load_der_x509_csr(data, default_backend())


def load_cert(fn):
    """Read CRT file.
    """
    data = open(fn, "rb").read()
    if is_pem_data(data):
        return x509.load_pem_x509_certificate(data, default_backend())
    return x509.load_der_x509_certificate(data, default_backend())


def load_crl(fn):
    """Read CRL file.
    """
    data = open(fn, "rb").read()
    if is_pem_data(data):
        return x509.load_pem_x509_crl(data, default_backend())
    return x509.load_der_x509_crl(data, default_backend())
