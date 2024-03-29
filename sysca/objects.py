"""Python objects <> cryptography objects.
"""

import ipaddress
from typing import (
    Dict, List, Literal, Optional, Sequence, Tuple, Union, cast, overload,
)

from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, Encoding,
    NoEncryption, PrivateFormat, PublicFormat,
)
from cryptography.x509.oid import (
    AuthorityInformationAccessOID, NameOID, ObjectIdentifier,
)

from .compat import (
    AllPrivateKeyClasses, AllPrivateKeyTypes, AllPublicKeyClasses,
    AllPublicKeyTypes, GNameList, NameSeq, TypeAlias, X509Classes,
    X509Types, valid_private_key, valid_public_key,
)
from .exceptions import InvalidCertificate
from .formats import (
    as_password, list_escape, parse_dn, parse_list, render_name,
)
from .ssh import serialize_ssh_private_key, serialize_ssh_public_key

__all__ = (
    "extract_name", "extract_gnames", "extract_policy",
    "extract_distribution_point_urls", "extract_auth_access",
    "make_policy", "make_name", "make_gnames", "make_key_usage",
    "serialize", "convert_urls_to_gnames",
)


DN_CODE_TO_OID = {
    # common
    "CN": NameOID.COMMON_NAME,
    "commonName": NameOID.COMMON_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "organizationName": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "organizationalUnitName": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "C": NameOID.COUNTRY_NAME,
    "countryName": NameOID.COUNTRY_NAME,
    "L": NameOID.LOCALITY_NAME,
    "localityName": NameOID.LOCALITY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "stateOrProvinceName": NameOID.STATE_OR_PROVINCE_NAME,
    "STREET": NameOID.STREET_ADDRESS,
    "streetAddress": NameOID.STREET_ADDRESS,

    # X.520 name
    "SN": NameOID.SURNAME,
    "surname": NameOID.SURNAME,
    "GN": NameOID.GIVEN_NAME,
    "givenName": NameOID.GIVEN_NAME,
    "GQ": NameOID.GENERATION_QUALIFIER,
    "generationQualifier": NameOID.GENERATION_QUALIFIER,
    "P": NameOID.PSEUDONYM,
    "pseudonym": NameOID.PSEUDONYM,
    "T": NameOID.TITLE,
    "title": NameOID.TITLE,

    # LDAP/X.500 (rfc4519)
    "BC": NameOID.BUSINESS_CATEGORY,
    "businessCategory": NameOID.BUSINESS_CATEGORY,
    "DC": NameOID.DOMAIN_COMPONENT,
    "domainComponent": NameOID.DOMAIN_COMPONENT,
    "DQ": NameOID.DN_QUALIFIER,
    "dnQualifier": NameOID.DN_QUALIFIER,
    "PA": NameOID.POSTAL_ADDRESS,
    "postalAddress": NameOID.POSTAL_ADDRESS,
    "PC": NameOID.POSTAL_CODE,
    "postalCode": NameOID.POSTAL_CODE,
    "SERIAL": NameOID.SERIAL_NUMBER,
    "serialNumber": NameOID.SERIAL_NUMBER,

    "UID": NameOID.USER_ID,
    "userid": NameOID.USER_ID,
    "XUID": NameOID.X500_UNIQUE_IDENTIFIER,
    "x500UniqueIdentifier": NameOID.X500_UNIQUE_IDENTIFIER,

    # nonstring: name, member, owner, roleOccupant, seeAlso, uniqueMember
    # weird: telex*, teletex*, userPassword
    "description": ObjectIdentifier("2.5.4.13"),
    "destinationIndicator": ObjectIdentifier("2.5.4.27"),
    "enhancedSearchGuide": ObjectIdentifier("2.5.4.47"),
    "facsimileTelephoneNumber": ObjectIdentifier("2.5.4.23"),
    "houseIdentifier": ObjectIdentifier("2.5.4.51"),
    "initials": ObjectIdentifier("2.5.4.43"),
    "internationalISDNNumber": ObjectIdentifier("2.5.4.25"),
    "physicalDeliveryOfficeName": ObjectIdentifier("2.5.4.19"),
    "postOfficeBox": ObjectIdentifier("2.5.4.18"),
    "preferredDeliveryMethod": ObjectIdentifier("2.5.4.28"),
    "registeredAddress": ObjectIdentifier("2.5.4.26"),
    "searchGuide": ObjectIdentifier("2.5.4.14"),
    "telephoneNumber": ObjectIdentifier("2.5.4.20"),

    # used in RSA PKCS#9, replaced by SAN
    "EMAIL": NameOID.EMAIL_ADDRESS,
    "emailAddress": NameOID.EMAIL_ADDRESS,

    # used in Extended Validation Certificates
    "JC": NameOID.JURISDICTION_COUNTRY_NAME,
    "jurisdictionOfIncorporationCountryName": NameOID.JURISDICTION_COUNTRY_NAME,
    "JL": NameOID.JURISDICTION_LOCALITY_NAME,
    "jurisdictionOfIncorporationLocalityName": NameOID.JURISDICTION_LOCALITY_NAME,
    "JST": NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME,
    "jurisdictionOfIncorporationStateOrProvinceName": NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME,
}

DN_OID_TO_CODE = {v: k for k, v in sorted(DN_CODE_TO_OID.items(), reverse=True)}


#
# Converters
#


def extract_name(name: Optional[x509.Name]) -> NameSeq:
    """Convert Name object to shortcut-dict.
    """
    if name is None:
        return ()
    if not isinstance(name, x509.Name):
        raise TypeError("Expect x509.Name")
    rdns = []
    for rdn in name.rdns:
        pairs = []
        for att in rdn:
            if isinstance(att.value, bytes):
                raise TypeError("Expect str value")
            rname = DN_OID_TO_CODE.get(att.oid, att.oid.dotted_string)
            pairs.append(rname)
            pairs.append(att.value)
        rdns.append(tuple(pairs))
    return tuple(rdns)


def extract_gnames(
    ext_name_list: Optional[Union[
        List[x509.GeneralName],
        x509.CertificateIssuer,
        x509.SubjectAlternativeName,
        x509.IssuerAlternativeName
    ]]
) -> GNameList:
    """Convert list of GeneralNames to list of prefixed strings.
    """
    if ext_name_list is None:
        return []
    if not isinstance(ext_name_list, (list, x509.CertificateIssuer,
                                      x509.SubjectAlternativeName, x509.IssuerAlternativeName)):
        raise TypeError("unexpected type: %r" % ext_name_list)
    res: List[str] = []
    for gn in ext_name_list:
        if isinstance(gn, x509.RFC822Name):
            res.append("email:" + gn.value)
        elif isinstance(gn, x509.DNSName):
            res.append("dns:" + gn.value)
        elif isinstance(gn, x509.UniformResourceIdentifier):
            res.append("uri:" + gn.value)
        elif isinstance(gn, x509.IPAddress):
            if isinstance(gn.value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                res.append("net:" + str(gn.value))
            else:
                res.append("ip:" + str(gn.value))
        elif isinstance(gn, x509.DirectoryName):
            val = extract_name(gn.value)
            if val:
                res.append("dn:" + render_name(val, "/"))
        else:
            raise InvalidCertificate("Unsupported subjectAltName type: %s" % (gn,))
    return res


def extract_policy(pol: x509.PolicyInformation) -> str:
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


def make_policy(txt: str) -> x509.PolicyInformation:
    """Create PolicyInformation from --add-policy value
    """
    tmp = txt.split(":", 1)
    pol_oid = ObjectIdentifier(tmp[0])
    quals: List[Union[str, x509.UserNotice]] = []
    if len(tmp) > 1:
        for elem in parse_list(tmp[1]):
            d: Dict[str, str] = dict((n[0], n[1]) for n in parse_dn(elem))
            klist = list(d.keys())
            p_value = d.get("P")
            if p_value:
                quals.append(p_value)
                if klist != ["P"]:
                    raise InvalidCertificate("Bad policy spec: P must be alone")
                continue
            klist = [k for k in klist if k not in ("T", "N", "O")]
            if klist:
                raise InvalidCertificate("Bad policy spec: unknown fields: %r" % klist)
            v_noticeref = d.get("N")
            v_orgname = d.get("O", "")
            v_text = d.get("T")
            ref = None
            nums = []
            if v_noticeref:
                nums = [int(n) for n in v_noticeref.split(":")]
            if v_orgname or nums:
                ref = x509.NoticeReference(v_orgname, nums)
            quals.append(x509.UserNotice(ref, v_text))
    return x509.PolicyInformation(pol_oid, quals or None)


def make_name(name_att_list: Sequence[Sequence[str]]) -> x509.Name:
    """Create Name object from list of tuples.
    """
    rdnlist = []
    for rdn in name_att_list:
        attlist = []
        while rdn:
            k, v, rdn = rdn[0], rdn[1], rdn[2:]
            if "." in k:
                oid = ObjectIdentifier(k)
            elif k in DN_CODE_TO_OID:
                oid = DN_CODE_TO_OID[k]
            else:
                raise InvalidCertificate("Unknown Name tag: %s" % (k,))
            n = x509.NameAttribute(oid, v)
            attlist.append(n)
        rdnlist.append(x509.RelativeDistinguishedName(attlist))
    return x509.Name(rdnlist)


def make_gnames(gname_list: Sequence[str]) -> List[x509.GeneralName]:
    """Converts list of prefixed strings to GeneralName list.
    """
    gnames = []
    for alt in gname_list:
        if ":" not in alt:
            raise InvalidCertificate("Invalid gname: %s" % (alt,))
        t, val = alt.split(":", 1)
        t = t.lower().strip()
        val = val.strip()
        gn: x509.GeneralName
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


def make_key_usage(
    digital_signature: bool = False,
    content_commitment: bool = False,
    key_encipherment: bool = False,
    data_encipherment: bool = False,
    key_agreement: bool = False,
    key_cert_sign: bool = False,
    crl_sign: bool = False,
    encipher_only: bool = False,
    decipher_only: bool = False,
) -> x509.KeyUsage:
    """Default arguments for KeyUsage.
    """
    return x509.KeyUsage(digital_signature=digital_signature, content_commitment=content_commitment,
                         key_encipherment=key_encipherment, data_encipherment=data_encipherment,
                         key_agreement=key_agreement, key_cert_sign=key_cert_sign, crl_sign=crl_sign,
                         encipher_only=encipher_only, decipher_only=decipher_only)


# for non-key objects: CRT/CSR/CRL
_X509_FORMATS = {
    "der": Encoding.DER,
    "pem": Encoding.PEM,
}

# public keys
_PUB_FORMATS = {
    "der": (Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
    "pem": (Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
    "raw": (Encoding.Raw, PublicFormat.Raw),
    "ssh": (Encoding.OpenSSH, PublicFormat.OpenSSH),
    "ssl": (Encoding.PEM, PublicFormat.PKCS1),
}

# private keys
_PRIV_FORMATS = {
    "der": (Encoding.DER, PrivateFormat.PKCS8),
    "pem": (Encoding.PEM, PrivateFormat.PKCS8),
    "raw": (Encoding.Raw, PrivateFormat.Raw),
    "ssh": (Encoding.PEM, PrivateFormat.OpenSSH),
    "ssl": (Encoding.PEM, PrivateFormat.TraditionalOpenSSL),
}

SerializeObj: TypeAlias = Union[AllPublicKeyTypes, AllPrivateKeyTypes, X509Types]
SerializePsw: TypeAlias = Optional[Union[str, bytes]]
SerializeBinEncoding = Literal["der", "raw"]
SerializeStrEncoding = Literal["pem", "ssh", "ssl"]
SerializeEncoding = Union[SerializeBinEncoding, SerializeStrEncoding]


@overload
def serialize(obj: SerializeObj, encoding: SerializeStrEncoding = "pem",
              password: SerializePsw = None) -> str: ...


@overload
def serialize(obj: SerializeObj, encoding: SerializeBinEncoding,
              password: SerializePsw = None) -> bytes: ...


def serialize(obj: SerializeObj, encoding: SerializeEncoding = "pem",
              password: SerializePsw = None) -> Union[str, bytes]:
    """Returns standard serialization for object.

    Supports: certificate, certificate request, CRL, public and private keys.

    Formats for CRT/CSR/CRL:
        pem - DER in ascii-armor
        der - binary format, X.509 ASN1

    Formats for public keys:
        pem - X.509 SubjectPublicKeyInfo + PKCS1 + PEM
        der - X.509 SubjectPublicKeyInfo + PKCS1
        ssh - OpenSSH oneliner
        ssl - Raw PKCS1 + PEM
        raw - EdDSA public bytes

    Formats for private keys:
        pem - PKCS8 + PEM
        der - PKCS8
        ssh - OpenSSH custom format for private keys
        ssl - Traditional OpenSSL/OpenSSH for RSA/DSA/EC keys
        raw - EdDSA private bytes

    Returns string value for textual formats (pem,ssh,ssl), bytes for binary formats (der,raw).
    """
    password = as_password(password)
    res: Optional[bytes] = None
    if encoding not in ("pem", "der", "ssh", "ssl", "raw"):
        raise ValueError("Unsupported encoding: %s" % encoding)
    if isinstance(obj, AllPrivateKeyClasses):
        priv = valid_private_key(obj)
        if encoding == "ssh":
            res = serialize_ssh_private_key(priv, password)
        else:
            enc, pubfmt = _PRIV_FORMATS[encoding]
            hide: Union[NoEncryption, BestAvailableEncryption] = NoEncryption()
            if password:
                if encoding == "raw":
                    raise ValueError("Raw format does not support password")
                hide = BestAvailableEncryption(password)
            res = priv.private_bytes(enc, pubfmt, hide)
    elif password is not None:
        raise ValueError("Only private keys can have password protection")
    elif isinstance(obj, AllPublicKeyClasses):
        pub = valid_public_key(obj)
        if encoding == "ssh":
            res = serialize_ssh_public_key(pub)
        else:
            enc, privfmt = _PUB_FORMATS[encoding]
            res = pub.public_bytes(enc, privfmt)
    elif isinstance(obj, X509Classes):
        if encoding not in _X509_FORMATS:
            raise ValueError("Encoding %s is for public/private keys" % encoding)
        xobj = cast(X509Types, obj)
        res = xobj.public_bytes(_X509_FORMATS[encoding])
    else:
        raise TypeError("Unsupported type for serialize(): %r" % obj)

    if encoding in ("pem", "ssh", "ssl"):
        txt: str = res.decode("utf8") if res else ""
        if txt and txt[-1] != "\n":
            txt += "\n"
        return txt
    assert isinstance(res, bytes)
    return res


def convert_urls_to_gnames(url_list: Sequence[str]) -> List[x509.GeneralName]:
    """Return urls as GeneralNames
    """
    urls = ["uri:" + u for u in url_list]
    return make_gnames(urls)


def extract_distribution_point_urls(
    extobj: Union[x509.CRLDistributionPoints, x509.FreshestCRL]
) -> List[str]:
    if not isinstance(extobj, (x509.CRLDistributionPoints, x509.FreshestCRL)):
        raise TypeError("Expect CRLDistributionPoints or FreshestCRL")
    urls: List[str] = []
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


def extract_auth_access(extobj: x509.AuthorityInformationAccess) -> Tuple[List[str], List[str]]:
    if not isinstance(extobj, x509.AuthorityInformationAccess):
        raise TypeError("Unexpected type: %r" % extobj)
    issuer_urls, ocsp_urls = [], []
    for ad in extobj:
        if not isinstance(ad.access_location, x509.UniformResourceIdentifier):
            raise InvalidCertificate("Unsupported access_location: %s" % (ad.access_location,))
        url = ad.access_location.value

        if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            issuer_urls.append(url)
        elif ad.access_method == AuthorityInformationAccessOID.OCSP:
            ocsp_urls.append(url)
        else:
            raise InvalidCertificate("Unsupported access_method: %s" % (ad.access_method,))
    return issuer_urls, ocsp_urls

