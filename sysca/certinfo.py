"""Certificate and CertificateSigningRequest support.
"""

from datetime import datetime
from typing import Callable, List, Optional, Sequence, TypeVar, Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import (
    AuthorityInformationAccessOID, ExtendedKeyUsageOID,
    ExtensionOID, ObjectIdentifier, SignatureAlgorithmOID,
)

from .compat import (
    GNameList, IssuerPrivateKeyTypes, IssuerPublicKeyTypes, MaybeList,
    MaybeName, NameSeq, SignatureParamsType, SubjectPrivateKeyClasses,
    SubjectPrivateKeyTypes, SubjectPublicKeyClasses, SubjectPublicKeyTypes,
    TypeAlias, get_utc_datetime, valid_issuer_private_key,
    valid_subject_private_key, valid_subject_public_key,
)
from .exceptions import InvalidCertificate
from .formats import (
    maybe_parse_dn, maybe_parse_list, maybe_parse_number,
    parse_time_period, render_name, render_serial, show_list, to_hex,
)
from .keys import (
    get_hash_algo, get_invalid_key_usage, get_key_name,
    get_param_info, get_rsa_padding, new_serial_number,
    safe_issuer_privkey, safe_subject_pubkey, same_pubkey,
)
from .objects import (
    convert_urls_to_gnames, extract_auth_access,
    extract_distribution_point_urls, extract_gnames, extract_name,
    extract_policy, make_gnames, make_key_usage, make_name, make_policy,
)

__all__ = ("CertInfo", "create_x509_req", "create_x509_cert")

LoadTypes: TypeAlias = Union[x509.Certificate, x509.CertificateSigningRequest,
                             SubjectPublicKeyTypes, SubjectPrivateKeyTypes]

B = TypeVar("B", x509.CertificateBuilder, x509.CertificateSigningRequestBuilder)


KU_FIELDS = [
    "digital_signature",    # non-CA signatures
    "content_commitment",   # weird signatures.  old alias: non_repudiation
    "key_encipherment",     # SSL-RSA key exchange
    "data_encipherment",    # Historical.
    "key_agreement",        # Historical?
    "key_cert_sign",        # CA
    "crl_sign",             # CA
    "encipher_only",        # option for key_agreement
    "decipher_only",        # option for key_agreement
]

XKU_CODE_TO_OID = {
    "any": ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
    "server": ExtendedKeyUsageOID.SERVER_AUTH,
    "client": ExtendedKeyUsageOID.CLIENT_AUTH,
    "code": ExtendedKeyUsageOID.CODE_SIGNING,
    "email": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "time": ExtendedKeyUsageOID.TIME_STAMPING,
    "ocsp": ExtendedKeyUsageOID.OCSP_SIGNING,
    "precert-ca": ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3"),
}

# minimal KeyUsage defaults to add when ExtendedKeyUsage is given
XKU_DEFAULTS = {
    "any": ["digital_signature", "key_encipherment", "key_agreement", "content_commitment", "data_encipherment", "key_cert_sign", "crl_sign"],
    "server": ["digital_signature"],    # key_agreement, key_encipherment
    "client": ["digital_signature"],    # key_agreement
    "code": ["digital_signature"],      # -
    "email": ["digital_signature"],     # content_commitment, key_agreement, key_encipherment
    "time": ["digital_signature"],      # content_commitment
    "ocsp": ["digital_signature"],      # content_commitment
    "precert-ca": ["key_cert_sign"],

    "encipher_only": ["key_agreement"],
    "decipher_only": ["key_agreement"],
}

# required for CA
CA_DEFAULTS = {
    "key_cert_sign": True,
    "crl_sign": True,
}

# when usage not set
NONCA_DEFAULTS = {
    "digital_signature": True,
}


def extract_xkey_usage(ext: x509.ExtendedKeyUsage) -> List[str]:
    """Walk oid list, return keywords.
    """
    oidmap = {v: k for k, v in XKU_CODE_TO_OID.items()}
    res: List[str] = []
    for oid in ext:
        if oid in oidmap:
            res.append(oidmap[oid])
        else:
            raise InvalidCertificate("Unsupported ExtendedKeyUsage oid: %s" % (oid,))
    return res


def extract_key_usage(ext: x509.KeyUsage) -> List[str]:
    """Extract list of tags from KeyUsage extension.
    """
    res: List[str] = []
    fields = KU_FIELDS[:]

    # "error-on-access", real funny
    if not ext.key_agreement:
        fields.remove("encipher_only")
        fields.remove("decipher_only")

    for k in fields:
        val = getattr(ext, k, False)
        if val:
            res.append(k)
    return res


def extract_precert_signed_timestamps(extobj: x509.PrecertificateSignedCertificateTimestamps) -> List[str]:
    return ["%s_%s - %s - %s" % (
            str(scts.version).split(".")[1], str(scts.entry_type).split(".")[1],
            scts.timestamp.isoformat(" "), to_hex(scts.log_id)
            ) for scts in extobj]


class CertInfo:
    """Container for certificate fields.
    """
    # core
    version: Optional[int]
    serial_number: Optional[int]
    not_valid_before: Optional[datetime]
    not_valid_after: Optional[datetime]
    issuer_name: NameSeq
    unknown_extensions: List[str]
    public_key_object: Optional[SubjectPublicKeyTypes]
    signature_algorithm_oid: Optional[x509.ObjectIdentifier]
    signature_algorithm_parameters: Optional[SignatureParamsType]
    rsa_pss: bool

    # Subject
    subject: NameSeq

    # BasicConstraints
    ca: bool
    path_length: Optional[int]

    # SubjectAltNames
    san: GNameList

    # IssuerAlternativeName
    issuer_san: GNameList

    # KeyUsage + ExtendedKeyUsage
    usage: List[str]

    # AuthorityInformationAccess
    ocsp_urls: List[str]
    issuer_urls: List[str]

    # CRLDistributionPoints
    crl_urls: List[str]

    # FreshestCRL
    delta_crl_urls: List[str]

    # NameConstraints
    exclude_subtrees: List[str]
    permit_subtrees: List[str]

    # OCSPNoCheck
    ocsp_nocheck: bool

    # TLSFeature
    ocsp_must_staple: bool
    ocsp_must_staple_v2: bool

    # InhibitAnyPolicy
    inhibit_any: Optional[int]

    # PolicyConstraints
    require_explicit_policy: Optional[int]
    inhibit_policy_mapping: Optional[int]

    # CertificatePolicies
    certificate_policies: List[str]

    # SubjectKeyIdentifier
    subject_key_identifier: Optional[str] = None

    # AuthorityKeyIdentifier
    authority_key_identifier: Optional[str]
    authority_cert_serial_number: Optional[int]
    authority_cert_issuer: GNameList

    # PrecertPoison
    precert_poison: bool

    # PrecertificateSignedCertificateTimestamps
    precert_signed_timestamps: List[str]

    def __init__(self,
                 subject: Optional[MaybeName] = None,
                 alt_names: Optional[MaybeList] = None,
                 ca: bool = False,
                 path_length: Optional[int] = None,
                 usage: Optional[MaybeList] = None,
                 ocsp_urls: Optional[MaybeList] = None,
                 crl_urls: Optional[MaybeList] = None,
                 issuer_urls: Optional[MaybeList] = None,
                 delta_crl_urls: Optional[MaybeList] = None,
                 ocsp_nocheck: bool = False,
                 ocsp_must_staple: bool = False,
                 ocsp_must_staple_v2: bool = False,
                 permit_subtrees: Optional[MaybeList] = None,
                 exclude_subtrees: Optional[MaybeList] = None,
                 inhibit_any: Optional[int] = None,
                 require_explicit_policy: Optional[int] = None,
                 inhibit_policy_mapping: Optional[int] = None,
                 certificate_policies: Optional[MaybeList] = None,
                 rsa_pss: bool = False,
                 load: Optional[LoadTypes] = None) -> None:
        """Initialize info object.

        Arguments:

            subject
                dict if strings.

            alt_names
                list of GeneralName strings

            ca
                boolean, isCA

            path_length
                max depth for CAs

            usage
                list of keywords (KU_FIELDS, XKU_CODE_TO_OID).

            ocsp_urls
                list of urls

            issuer_urls
                list of urls

            crl_urls
                list of urls

            delta_crl_urls
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

            inhibit_any
                number of levels

            require_explicit_policy
                number of levels

            inhibit_policy_mapping
                number of levels

            certificate_policies
                list of strings containing policy specs

            load
                object to extract from (cert or cert request)

        """
        # core
        self.version = None
        self.serial_number = None
        self.not_valid_before = None
        self.not_valid_after = None
        self.issuer_name = ()
        self.unknown_extensions = []
        self.public_key_object = None
        self.signature_algorithm_oid = None
        self.signature_algorithm_parameters = None
        self.rsa_pss = rsa_pss

        # Subject
        self.subject = maybe_parse_dn(subject)

        # BasicConstraints
        self.ca = ca
        self.path_length = path_length
        if self.path_length is not None and self.path_length < 0:
            self.path_length = None

        # SubjectAltNames
        self.san = maybe_parse_list(alt_names)

        # IssuerAlternativeName
        self.issuer_san = []

        # KeyUsage + ExtendedKeyUsage
        self.usage = maybe_parse_list(usage)

        # AuthorityInformationAccess
        self.ocsp_urls = maybe_parse_list(ocsp_urls)
        self.issuer_urls = maybe_parse_list(issuer_urls)

        # CRLDistributionPoints
        self.crl_urls = maybe_parse_list(crl_urls)

        # FreshestCRL
        self.delta_crl_urls = maybe_parse_list(delta_crl_urls)

        # NameConstraints
        self.exclude_subtrees = maybe_parse_list(exclude_subtrees)
        self.permit_subtrees = maybe_parse_list(permit_subtrees)

        # OCSPNoCheck
        self.ocsp_nocheck = ocsp_nocheck

        # TLSFeature
        self.ocsp_must_staple = ocsp_must_staple
        self.ocsp_must_staple_v2 = ocsp_must_staple_v2

        # InhibitAnyPolicy
        self.inhibit_any = inhibit_any

        # PolicyConstraints
        self.require_explicit_policy = require_explicit_policy
        self.inhibit_policy_mapping = inhibit_policy_mapping

        # CertificatePolicies
        self.certificate_policies = maybe_parse_list(certificate_policies)

        # SubjectKeyIdentifier
        self.subject_key_identifier = None

        # AuthorityKeyIdentifier
        self.authority_key_identifier = None
        self.authority_cert_serial_number = None
        self.authority_cert_issuer = []

        # PrecertPoison
        self.precert_poison = False

        # PrecertificateSignedCertificateTimestamps
        self.precert_signed_timestamps = []

        if load is not None:
            self.load_from_existing(load)

    def load_from_existing(self, obj: LoadTypes) -> None:
        """Load certificate info from existing certificate or certificate request.
        """
        self.unknown_extensions = []
        if isinstance(obj, x509.Certificate):
            self.serial_number = obj.serial_number
            if obj.version == x509.Version.v1:
                self.version = 1
            elif obj.version == x509.Version.v3:
                self.version = 3
            else:
                raise InvalidCertificate("Unsupported certificate version")
            self.issuer_name = extract_name(obj.issuer)
            self.not_valid_before = get_utc_datetime(obj, "not_valid_before")
            self.not_valid_after = get_utc_datetime(obj, "not_valid_after")
        elif isinstance(obj, x509.CertificateSigningRequest):
            self.version = None
            self.issuer_name = ()
            self.signature_algorithm_oid = obj.signature_algorithm_oid
        elif isinstance(obj, SubjectPublicKeyClasses):
            self.public_key_object = valid_subject_public_key(obj)
            return
        elif isinstance(obj, SubjectPrivateKeyClasses):
            priv_key = valid_subject_private_key(obj)
            self.public_key_object = priv_key.public_key()
            return
        else:
            raise InvalidCertificate("Invalid obj type: %s" % type(obj))

        self.public_key_object = valid_subject_public_key(obj.public_key())
        self.subject = extract_name(obj.subject)
        self.signature_algorithm_oid = obj.signature_algorithm_oid
        try:
            signature_algorithm_parameters = getattr(obj, "signature_algorithm_parameters", None)
        except ValueError:
            signature_algorithm_parameters = None
        self.signature_algorithm_parameters = signature_algorithm_parameters

        if self.signature_algorithm_oid:
            if self.signature_algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS:
                self.rsa_pss = True

        for ext in obj.extensions:
            extobj = ext.value
            if ext.oid == ExtensionOID.BASIC_CONSTRAINTS:
                self.ca = extobj.ca
                self.path_length = None
                if self.ca:
                    self.path_length = extobj.path_length
            elif ext.oid == ExtensionOID.KEY_USAGE:
                self.usage += extract_key_usage(extobj)
            elif ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                self.san = extract_gnames(extobj)
            elif ext.oid == ExtensionOID.ISSUER_ALTERNATIVE_NAME:
                self.issuer_san = extract_gnames(extobj)
            elif ext.oid == ExtensionOID.EXTENDED_KEY_USAGE:
                self.usage += extract_xkey_usage(extobj)
            elif ext.oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                self.issuer_urls, self.ocsp_urls = extract_auth_access(extobj)
            elif ext.oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
                self.crl_urls = extract_distribution_point_urls(extobj)
            elif ext.oid == ExtensionOID.FRESHEST_CRL:
                self.delta_crl_urls = extract_distribution_point_urls(extobj)
            elif ext.oid == ExtensionOID.NAME_CONSTRAINTS:
                self.permit_subtrees = extract_gnames(extobj.permitted_subtrees)
                self.exclude_subtrees = extract_gnames(extobj.excluded_subtrees)
            elif ext.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                self.subject_key_identifier = to_hex(extobj.digest)
            elif ext.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                self.authority_key_identifier = to_hex(extobj.key_identifier)
                self.authority_cert_serial_number = extobj.authority_cert_serial_number
                self.authority_cert_issuer = extract_gnames(extobj.authority_cert_issuer)
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
            elif ext.oid == ExtensionOID.POLICY_CONSTRAINTS:
                self.require_explicit_policy = extobj.require_explicit_policy
                self.inhibit_policy_mapping = extobj.inhibit_policy_mapping
            elif ext.oid == ExtensionOID.CERTIFICATE_POLICIES:
                self.certificate_policies = [extract_policy(pol) for pol in extobj]
            elif ext.oid == ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS:
                self.precert_signed_timestamps = extract_precert_signed_timestamps(extobj)
            elif ext.oid == ExtensionOID.PRECERT_POISON:
                self.precert_poison = True
            else:
                self.unknown_extensions.append(ext.oid.dotted_string)

    def public_key(self) -> Optional[SubjectPublicKeyTypes]:
        return self.public_key_object

    def get_tls_features(self) -> List[x509.TLSFeatureType]:
        """Return TLS Feature list
        """
        tls_features: List[x509.TLSFeatureType] = []
        if self.ocsp_must_staple:
            tls_features.append(x509.TLSFeatureType.status_request)
        if self.ocsp_must_staple_v2:
            tls_features.append(x509.TLSFeatureType.status_request_v2)
        return tls_features

    def install_extensions(self,
                           builder: B,
                           subject_pubkey: Optional[SubjectPublicKeyTypes],
                           issuer_pubkey: Optional[IssuerPublicKeyTypes],
                           issuer_san: Optional[Sequence[str]],
                           ) -> B:
        """Add common extensions to Cert- or CSR builder.
        """
        if self.unknown_extensions:
            raise InvalidCertificate("Unknown extensions: %s" %
                                     ", ".join(self.unknown_extensions))

        ext: x509.ExtensionType

        # BasicConstraints, critical
        if self.ca:
            ext = x509.BasicConstraints(ca=True, path_length=self.path_length)
        else:
            ext = x509.BasicConstraints(ca=False, path_length=None)
        builder = builder.add_extension(ext, critical=True)

        # KeyUsage, critical
        ku_args = {k: True in self.usage for k in KU_FIELDS}
        if self.ca:
            ku_args.update(CA_DEFAULTS)
        elif not self.usage:
            ku_args.update(NONCA_DEFAULTS)
        for k in XKU_DEFAULTS:
            if k in self.usage:
                for k2 in XKU_DEFAULTS[k]:
                    ku_args[k2] = True
        if subject_pubkey:
            invalid_usage = [k for k in get_invalid_key_usage(subject_pubkey) if ku_args.get(k)]
            if invalid_usage:
                raise InvalidCertificate("Key type does not support usage: %s" % ",".join(invalid_usage))
        ext = make_key_usage(**ku_args)
        builder = builder.add_extension(ext, critical=True)

        # ExtendedKeyUsage, critical
        xku = [x for x in self.usage if x not in KU_FIELDS]
        xku_bad = [x for x in xku if x not in XKU_CODE_TO_OID]
        if xku_bad:
            raise InvalidCertificate("Unknown usage keywords: %s" % (",".join(xku_bad),))
        if xku:
            xku_oids = [XKU_CODE_TO_OID[x] for x in xku]
            ext = x509.ExtendedKeyUsage(xku_oids)
            builder = builder.add_extension(ext, critical=True)

        # NameConstraints, critical
        if self.exclude_subtrees or self.permit_subtrees:
            if not self.ca:
                raise InvalidCertificate("NameConstraints applies only to CA certificates")
            allow = make_gnames(self.permit_subtrees) or None
            disallow = make_gnames(self.exclude_subtrees) or None
            ext = x509.NameConstraints(allow, disallow)
            builder = builder.add_extension(ext, critical=True)

        # SubjectAlternativeName
        if self.san:
            ext = x509.SubjectAlternativeName(make_gnames(self.san))
            builder = builder.add_extension(ext, critical=False)

        # SubjectKeyIdentifier
        if subject_pubkey is not None:
            ext = x509.SubjectKeyIdentifier.from_public_key(subject_pubkey)
            builder = builder.add_extension(ext, critical=False)

        # IssuerAlternativeName
        if issuer_san:
            ext = x509.IssuerAlternativeName(make_gnames(issuer_san))
            builder = builder.add_extension(ext, critical=False)

        # AuthorityKeyIdentifier
        if issuer_pubkey is not None:
            ext = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pubkey)
            builder = builder.add_extension(ext, critical=False)

        # CRLDistributionPoints
        if self.crl_urls:
            full_names = convert_urls_to_gnames(self.crl_urls)
            point = x509.DistributionPoint(full_names, None, None, None)
            ext = x509.CRLDistributionPoints([point])
            builder = builder.add_extension(ext, critical=False)

        # FreshestCRL
        if self.delta_crl_urls:
            full_names = convert_urls_to_gnames(self.delta_crl_urls)
            point = x509.DistributionPoint(full_names, None, None, None)
            ext = x509.FreshestCRL([point])
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

        # PolicyConstraints
        if self.require_explicit_policy is not None or self.inhibit_policy_mapping is not None:
            if not self.ca:
                raise InvalidCertificate("PolicyConstraints applies only to CA certificates")
            ext = x509.PolicyConstraints(self.require_explicit_policy, self.inhibit_policy_mapping)
            builder = builder.add_extension(ext, critical=True)

        # CertificatePolicies
        if self.certificate_policies:
            pols = [make_policy(p) for p in self.certificate_policies]
            ext = x509.CertificatePolicies(pols)
            builder = builder.add_extension(ext, critical=False)

        # Precert Poison
        if self.precert_poison:
            raise InvalidCertificate("Writing PrecertPoison not supported")

        # PrecertificateSignedCertificateTimestamps
        if self.precert_signed_timestamps:
            raise InvalidCertificate("Writing PrecertificateSignedCertificateTimestamps not supported")

        # configured builder
        return builder

    def combine(self, other: "CertInfo") -> "CertInfo":
        """Return new CertInfo combining fields from self and other.

        Attributes from self will be preferred.
        """
        def merge_number(a: Optional[int], b: Optional[int]) -> Optional[int]:
            return a if a is not None else b

        return CertInfo(
            subject=self.subject or other.subject,
            alt_names=self.san or other.san,
            ca=self.ca or other.ca,
            path_length=merge_number(self.path_length, other.path_length),
            usage=self.usage or other.usage,
            ocsp_urls=self.ocsp_urls or other.ocsp_urls,
            crl_urls=self.crl_urls or other.crl_urls,
            issuer_urls=self.issuer_urls or other.issuer_urls,
            delta_crl_urls=self.delta_crl_urls or other.delta_crl_urls,
            ocsp_nocheck=self.ocsp_nocheck or other.ocsp_nocheck,
            ocsp_must_staple=self.ocsp_must_staple or other.ocsp_must_staple,
            ocsp_must_staple_v2=self.ocsp_must_staple_v2 or other.ocsp_must_staple_v2,
            permit_subtrees=self.permit_subtrees or other.permit_subtrees,
            exclude_subtrees=self.exclude_subtrees or other.exclude_subtrees,
            inhibit_any=merge_number(self.inhibit_any, other.inhibit_any),
            require_explicit_policy=merge_number(self.require_explicit_policy, other.require_explicit_policy),
            inhibit_policy_mapping=merge_number(self.inhibit_policy_mapping, other.inhibit_policy_mapping),
            certificate_policies=self.certificate_policies or other.certificate_policies,
            rsa_pss=self.rsa_pss or other.rsa_pss,
        )

    def show(self, writeln: Callable[[str], None]) -> None:
        """Print out details.
        """
        if self.version is not None:
            writeln("Version: %s" % self.version)
        if self.public_key_object:
            writeln("Public key: %s" % get_key_name(self.public_key_object))
        if self.signature_algorithm_oid:
            signame = getattr(self.signature_algorithm_oid, "_name", "")
            if signame:
                writeln("Signature: %s" % signame)
            else:
                writeln("Signature: %s" % self.signature_algorithm_oid.dotted_string)
        if self.signature_algorithm_parameters and self.rsa_pss:
            writeln("Signature params: %s" % get_param_info(self.signature_algorithm_parameters))
        if self.not_valid_before:
            writeln("Not Valid Before: %s" % self.not_valid_before.isoformat(" "))
        if self.not_valid_after:
            writeln("Not Valid After: %s" % self.not_valid_after.isoformat(" "))
        if self.serial_number is not None:
            writeln("Serial: %s" % render_serial(self.serial_number))
        if self.subject:
            writeln("Subject: %s" % render_name(self.subject))
        show_list("Subject Alternative Name", self.san, writeln)
        if self.ca:
            writeln("CA: True")
        if self.path_length is not None:
            writeln("Path Length: %d" % self.path_length)
        if self.usage:
            writeln("Usage: %s" % ", ".join(self.usage))
        if self.subject_key_identifier:
            writeln("Subject Key Identifier: %s" % self.subject_key_identifier)
        if self.authority_key_identifier:
            writeln("Authority Key Identifier: %s" % self.authority_key_identifier)
        if self.authority_cert_serial_number:
            writeln("Authority Cert Serial Number: %s" % render_serial(self.authority_cert_serial_number))
        show_list("Authority Cert Issuer", self.authority_cert_issuer, writeln)
        if self.issuer_name:
            writeln("Issuer Name: %s" % render_name(self.issuer_name))
        show_list("Issuer SAN", self.issuer_san, writeln)
        show_list("Issuer URLs", self.issuer_urls, writeln)
        show_list("OCSP URLs", self.ocsp_urls, writeln)
        show_list("CRL URLs", self.crl_urls, writeln)
        show_list("Delta CRL URLs", self.delta_crl_urls, writeln)
        show_list("Permit", self.permit_subtrees, writeln)
        show_list("Exclude", self.exclude_subtrees, writeln)
        if self.ocsp_nocheck:
            writeln("OCSP NoCheck: True")

        tls_features: List[str] = []
        if self.ocsp_must_staple:
            tls_features.append("status_request")
        if self.ocsp_must_staple_v2:
            tls_features.append("status_request_v2")
        show_list("TLS Features", tls_features, writeln)
        if self.inhibit_any is not None:
            writeln("Inhibit ANY policy: skip_certs=%r" % self.inhibit_any)
        if self.require_explicit_policy is not None:
            writeln("Policy Constraint - Require Explicit Policy: %d" % self.require_explicit_policy)
        if self.inhibit_policy_mapping is not None:
            writeln("Policy Constraint - Inhibit Policy Mapping: %d" % self.inhibit_policy_mapping)
        show_list("Certificate Policies", self.certificate_policies, writeln)
        show_list("Precert Signed Timestamps", self.precert_signed_timestamps, writeln)
        if self.precert_poison:
            writeln("Precert Poison: True")
        if self.unknown_extensions:
            writeln("Unknown extensions: %s" % ", ".join(self.unknown_extensions))


MaybeCertInfo: TypeAlias = Union[CertInfo, x509.Certificate, x509.CertificateSigningRequest]


def create_x509_req(
    privkey: SubjectPrivateKeyTypes,
    subject_info: MaybeCertInfo,
) -> x509.CertificateSigningRequest:
    """Create x509.CertificateSigningRequest.
    """
    if not safe_subject_pubkey(privkey.public_key()):
        raise ValueError("Invalid private key")
    if isinstance(subject_info, (x509.Certificate, x509.CertificateSigningRequest)):
        subject_info = CertInfo(load=subject_info)
    elif not isinstance(subject_info, CertInfo):
        raise ValueError("Expect certinfo")

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(make_name(subject_info.subject))
    builder = subject_info.install_extensions(builder, privkey.public_key(), None, None)

    # cannot create X25519/X448 certs ATM
    issuer_key = valid_issuer_private_key(privkey)

    # create final request
    if subject_info.rsa_pss and isinstance(issuer_key, rsa.RSAPrivateKey):
        req = builder.sign(private_key=issuer_key,
                           algorithm=get_hash_algo(issuer_key, "CSR"),
                           rsa_padding=get_rsa_padding(issuer_key, "CSR"))
    else:
        req = builder.sign(private_key=issuer_key,
                           algorithm=get_hash_algo(issuer_key, "CSR"))
    return req


def validate_issuer(issuer_info: CertInfo) -> None:
    if not issuer_info.ca:
        raise InvalidCertificate("Issuer must be CA.")
    if "key_cert_sign" not in issuer_info.usage:
        raise InvalidCertificate("Issuer CA is not allowed to sign certs.")


def validate_subject_ca(subject_info: CertInfo, issuer_info: CertInfo) -> None:
    # not self-signing, check depth
    if issuer_info.path_length is None:
        pass
    elif issuer_info.path_length == 0:
        raise InvalidCertificate("Issuer cannot sign sub-CAs")
    elif subject_info.path_length is None:
        subject_info.path_length = issuer_info.path_length - 1
    elif issuer_info.path_length - 1 < subject_info.path_length:
        raise InvalidCertificate("--path-length not allowed by issuer")


def create_x509_cert(
    issuer_privkey: IssuerPrivateKeyTypes,
    subject_pubkey: SubjectPublicKeyTypes,
    subject_info: MaybeCertInfo,
    issuer_info: MaybeCertInfo,
    days: Optional[int] = None,
    serial_number: Optional[Union[str, int]] = None,
    not_valid_before: Optional[Union[str, datetime]] = None,
    not_valid_after: Optional[Union[str, datetime]] = None,
) -> x509.Certificate:
    """Create x509.Certificate
    """
    if isinstance(subject_info, x509.CertificateSigningRequest):
        subject_info = CertInfo(load=subject_info)
    elif not isinstance(subject_info, CertInfo):
        raise ValueError("Expect subject_info to be CertInfo or x509.CertificateSigningRequest")

    if isinstance(issuer_info, (x509.Certificate, x509.CertificateSigningRequest)):
        issuer_info = CertInfo(load=issuer_info)
    elif not isinstance(issuer_info, CertInfo):
        raise ValueError("Expect issuer_info to be CertInfo or x509.Certificate")

    if not safe_issuer_privkey(issuer_privkey):
        raise ValueError("Invalid issuer private key")
    if not safe_subject_pubkey(subject_pubkey):
        raise ValueError("Invalid subject public key")

    ikey = issuer_info.public_key()
    if ikey is None or not same_pubkey(issuer_privkey.public_key(), ikey):
        raise InvalidCertificate("Issuer private key does not match certificate")

    # need ca rights, unless selfsigned
    if not same_pubkey(subject_pubkey, issuer_privkey.public_key()):
        validate_issuer(issuer_info)
        if subject_info.ca:
            validate_subject_ca(subject_info, issuer_info)

    # calculare time period
    not_valid_before, not_valid_after = parse_time_period(days, not_valid_before, not_valid_after)

    # set serial
    if serial_number is None:
        final_serial_number = new_serial_number()
    else:
        final_serial_number = maybe_parse_number(serial_number)

    # create builder
    builder = (x509.CertificateBuilder()
               .subject_name(make_name(subject_info.subject))
               .issuer_name(make_name(issuer_info.subject))
               .not_valid_before(not_valid_before)
               .not_valid_after(not_valid_after)
               .serial_number(final_serial_number)
               .public_key(subject_pubkey))

    builder = subject_info.install_extensions(
        builder, subject_pubkey, issuer_privkey.public_key(), issuer_info.san
    )

    # final cert
    rsa_pss = subject_info.rsa_pss or issuer_info.rsa_pss
    if rsa_pss and isinstance(issuer_privkey, rsa.RSAPrivateKey):
        cert = builder.sign(private_key=issuer_privkey,
                            algorithm=get_hash_algo(issuer_privkey, "CRT"),
                            rsa_padding=get_rsa_padding(issuer_privkey, "CRT"))
    else:
        cert = builder.sign(private_key=issuer_privkey,
                            algorithm=get_hash_algo(issuer_privkey, "CRT"))
    return cert

