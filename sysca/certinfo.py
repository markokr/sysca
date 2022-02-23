"""Certificate and CertificateSigningRequest support.
"""

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import (
    AuthorityInformationAccessOID, ExtendedKeyUsageOID,
    ExtensionOID, ObjectIdentifier,
)

from .compat import PRIVKEY_CLASSES, PUBKEY_CLASSES
from .exceptions import InvalidCertificate
from .formats import (
    maybe_parse, maybe_parse_str, parse_dn, parse_list, parse_number,
    parse_time_period, render_name, render_serial, show_list, to_hex,
)
from .keys import (
    get_hash_algo, get_invalid_key_usage, get_key_name,
    new_serial_number, same_pubkey, valid_privkey, valid_pubkey,
)
from .objects import (
    convert_urls_to_gnames, extract_auth_access,
    extract_distribution_point_urls, extract_gnames, extract_name,
    extract_policy, make_gnames, make_key_usage, make_name, make_policy,
)

__all__ = ("CertInfo", "create_x509_req", "create_x509_cert")


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


def extract_xkey_usage(ext):
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


def extract_key_usage(ext):
    """Extract list of tags from KeyUsage extension.
    """
    res = []
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


def extract_precert_signed_timestamps(extobj):
    return ["%s_%s - %s - %s" % (
            str(scts.version).split(".")[1], str(scts.entry_type).split(".")[1],
            scts.timestamp.isoformat(" "), to_hex(scts.log_id)
            ) for scts in extobj]


class CertInfo:
    """Container for certificate fields.
    """
    def __init__(self, subject=None, alt_names=None, ca=False, path_length=None,
                 usage=None, ocsp_urls=None, crl_urls=None, issuer_urls=None,
                 delta_crl_urls=None,
                 ocsp_nocheck=False, ocsp_must_staple=False, ocsp_must_staple_v2=False,
                 permit_subtrees=None, exclude_subtrees=None, inhibit_any=None,
                 require_explicit_policy=None, inhibit_policy_mapping=None,
                 certificate_policies=None,
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
        self.serial_number = None
        self.not_valid_before = None
        self.not_valid_after = None
        self.issuer_name = None
        self.version = None
        self.unknown_extensions = []
        self.public_key_object = None
        # Subject
        self.subject = maybe_parse(subject, parse_dn)
        # BasicConstraints
        self.ca = ca
        self.path_length = path_length
        if self.path_length is not None and self.path_length < 0:
            self.path_length = None
        # SubjectAltNames
        self.san = maybe_parse(alt_names, parse_list)
        # IssuerAlternativeName
        self.issuer_san = None
        # KeyUsage + ExtendedKeyUsage
        self.usage = maybe_parse(usage, parse_list)
        # AuthorityInformationAccess
        self.ocsp_urls = maybe_parse(ocsp_urls, parse_list)
        self.issuer_urls = maybe_parse(issuer_urls, parse_list)
        # CRLDistributionPoints
        self.crl_urls = maybe_parse(crl_urls, parse_list)
        # FreshestCRL
        self.delta_crl_urls = maybe_parse(delta_crl_urls, parse_list)
        # NameConstraints
        self.exclude_subtrees = maybe_parse(exclude_subtrees, parse_list)
        self.permit_subtrees = maybe_parse(permit_subtrees, parse_list)
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
        self.certificate_policies = certificate_policies
        # SubjectKeyIdentifier
        self.subject_key_identifier = None
        # AuthorityKeyIdentifier
        self.authority_key_identifier = None
        self.authority_cert_serial_number = None
        self.authority_cert_issuer = None
        # PrecertPoison
        self.precert_poison = False
        # PrecertificateSignedCertificateTimestamps
        self.precert_signed_timestamps = None

        if load is not None:
            self.load_from_existing(load)

    def load_from_existing(self, obj):
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
            self.not_valid_before = obj.not_valid_before
            self.not_valid_after = obj.not_valid_after
        elif isinstance(obj, x509.CertificateSigningRequest):
            self.version = None
            self.issuer_name = None
        elif isinstance(obj, PUBKEY_CLASSES):
            self.public_key_object = obj
            return
        elif isinstance(obj, PRIVKEY_CLASSES):
            self.public_key_object = obj.public_key()
            return
        else:
            raise InvalidCertificate("Invalid obj type: %s" % type(obj))

        self.public_key_object = obj.public_key()
        self.subject = extract_name(obj.subject)

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
                self.authority_cert_issuer = extract_gnames(self.authority_cert_issuer)
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

    def public_key(self):
        return self.public_key_object

    def get_tls_features(self):
        """Return TLS Feature list
        """
        tls_features = []
        if self.ocsp_must_staple:
            tls_features.append(x509.TLSFeatureType.status_request)
        if self.ocsp_must_staple_v2:
            tls_features.append(x509.TLSFeatureType.status_request_v2)
        return tls_features

    def install_extensions(self, builder, subject_pubkey, issuer_pubkey, issuer_san):
        """Add common extensions to Cert- or CSR builder.
        """
        if self.unknown_extensions:
            raise InvalidCertificate("Unknown extensions: %s" %
                                     ", ".join(self.unknown_extensions))

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

    def show(self, writeln):
        """Print out details.
        """
        if self.version is not None:
            writeln("Version: %s" % self.version)
        if self.public_key_object:
            writeln("Public key: %s" % get_key_name(self.public_key_object))
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

        tls_features = []
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


def create_x509_req(privkey, subject_info):
    """Create x509.CertificateSigningRequest.
    """
    if not valid_privkey(privkey):
        raise ValueError("Invalid private key")
    if isinstance(subject_info, (x509.Certificate, x509.CertificateSigningRequest)):
        subject_info = CertInfo(load=subject_info)
    elif not isinstance(subject_info, CertInfo):
        raise ValueError("Expect certinfo")

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(make_name(subject_info.subject))
    builder = subject_info.install_extensions(builder, privkey.public_key(), None, None)

    # create final request
    req = builder.sign(private_key=privkey,
                       algorithm=get_hash_algo(privkey, "CSR"),
                       backend=default_backend())
    return req


def validate_issuer(issuer_info):
    if not issuer_info.ca:
        raise InvalidCertificate("Issuer must be CA.")
    if "key_cert_sign" not in issuer_info.usage:
        raise InvalidCertificate("Issuer CA is not allowed to sign certs.")


def validate_subject_ca(subject_info, issuer_info):
    # not self-signing, check depth
    if issuer_info.path_length is None:
        pass
    elif issuer_info.path_length == 0:
        raise InvalidCertificate("Issuer cannot sign sub-CAs")
    elif subject_info.path_length is None:
        subject_info.path_length = issuer_info.path_length - 1
    elif issuer_info.path_length - 1 < subject_info.path_length:
        raise InvalidCertificate("--path-length not allowed by issuer")


def create_x509_cert(issuer_privkey, subject_pubkey, subject_info, issuer_info,
                     days=None, serial_number=None,
                     not_valid_before=None, not_valid_after=None) -> x509.Certificate:
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

    if not valid_privkey(issuer_privkey):
        raise ValueError("Invalid issuer private key")
    if not valid_pubkey(subject_pubkey):
        raise ValueError("Invalid subject public key")

    if not same_pubkey(issuer_privkey, issuer_info):
        raise InvalidCertificate("Issuer private key does not match certificate")

    # need ca rights, unless selfsigned
    if not same_pubkey(subject_pubkey, issuer_privkey.public_key()):
        validate_issuer(issuer_info)
        if subject_info.ca:
            validate_subject_ca(subject_info, issuer_info)

    # calculare time period
    not_valid_before, not_valid_after = parse_time_period(days, not_valid_before, not_valid_after)

    # set serial
    serial_number = maybe_parse_str(serial_number, parse_number, int)
    if serial_number is None:
        serial_number = new_serial_number()

    # create builder
    builder = (x509.CertificateBuilder()
               .subject_name(make_name(subject_info.subject))
               .issuer_name(make_name(issuer_info.subject))
               .not_valid_before(not_valid_before)
               .not_valid_after(not_valid_after)
               .serial_number(serial_number)
               .public_key(subject_pubkey))

    builder = subject_info.install_extensions(
        builder, subject_pubkey, issuer_privkey.public_key(), issuer_info.san
    )

    # final cert
    cert = builder.sign(private_key=issuer_privkey,
                        algorithm=get_hash_algo(issuer_privkey, "CRT"),
                        backend=default_backend())
    return cert

