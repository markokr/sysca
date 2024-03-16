"""Certificate Revocation List handling.
"""

from datetime import datetime, timezone
from typing import (
    Any, Callable, Dict, FrozenSet, List, Literal, Optional, Union,
)

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import (
    AuthorityInformationAccessOID, CRLEntryExtensionOID,
    ExtensionOID, SignatureAlgorithmOID,
)

from .certinfo import CertInfo
from .compat import (
    GNameList, IssuerPrivateKeyTypes, MaybeList, MaybeNumber,
    MaybeTimestamp, NameSeq, SignatureParamsType, TypeAlias,
    get_utc_datetime, get_utc_datetime_opt,
)
from .exceptions import InvalidCertificate
from .formats import (
    maybe_parse_list, maybe_parse_number,
    maybe_parse_timestamp, parse_time_period, render_name,
    render_serial, show_list, to_hex, to_issuer_gnames,
)
from .keys import (
    get_hash_algo, get_param_info, get_rsa_padding, safe_issuer_privkey,
)
from .objects import (
    convert_urls_to_gnames, extract_auth_access,
    extract_distribution_point_urls, extract_gnames,
    extract_name, make_gnames, make_name,
)

__all__ = ("CRLInfo", "RevCertInfo", "create_x509_crl", "CRLScope")


CRLScope: TypeAlias = Literal["all", "user", "ca", "attr"]


# CRL reason
CRL_REASON = {
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "aa_compromise": x509.ReasonFlags.aa_compromise,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
    "superseded": x509.ReasonFlags.superseded,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "remove_from_crl": x509.ReasonFlags.remove_from_crl,
    "unspecified": x509.ReasonFlags.unspecified,
}

CRL_REASON_MAP = {v: k for k, v in CRL_REASON.items()}


class RevCertInfo:
    """Container for revoced certificate info.
    """
    serial_number: Optional[int]
    reason: Optional[str]
    revocation_date: Optional[datetime]
    invalidity_date: Optional[datetime]
    issuer_gnames: GNameList

    def __init__(self,
                 serial_number: Optional[MaybeNumber] = None,
                 reason: Optional[str] = None,
                 revocation_date: Optional[MaybeTimestamp] = None,
                 invalidity_date: Optional[MaybeTimestamp] = None,
                 issuer_gnames: Optional[MaybeList] = None,
                 load: Optional[x509.RevokedCertificate] = None,
                 ) -> None:
        self.serial_number = maybe_parse_number(serial_number)
        self.reason = reason
        self.revocation_date = maybe_parse_timestamp(revocation_date)
        self.invalidity_date = maybe_parse_timestamp(invalidity_date)
        self.issuer_gnames = maybe_parse_list(issuer_gnames)

        if load is not None:
            self.load_from_existing(load)
            if not self.issuer_gnames:
                self.issuer_gnames = maybe_parse_list(issuer_gnames)

    def generate_rcert(self, indirect_crl: bool, cur_gnames: Optional[List[str]]) -> x509.RevokedCertificate:
        """Return x509.RevokedCertificate
        """
        if self.revocation_date is None:
            self.revocation_date = datetime.now(timezone.utc)

        builder = x509.RevokedCertificateBuilder()
        if self.serial_number is not None:
            builder = builder.serial_number(self.serial_number)
        builder = builder.revocation_date(self.revocation_date)
        builder = self.install_extensions(builder, indirect_crl, cur_gnames)
        return builder.build()

    def install_extensions(self,
                           builder: x509.RevokedCertificateBuilder,
                           indirect_crl: bool,
                           cur_gnames: Optional[List[str]],
                           ) -> x509.RevokedCertificateBuilder:
        """Install additional extensions to builder.
        """
        ext: x509.ExtensionType

        if self.reason is not None:
            if self.reason not in CRL_REASON:
                raise ValueError("invalid reason: %r" % self.reason)
            code = CRL_REASON[self.reason]
            if code != x509.ReasonFlags.unspecified:
                ext = x509.CRLReason(code)
                builder = builder.add_extension(ext, critical=False)

        if self.invalidity_date is not None:
            ext = x509.InvalidityDate(self.invalidity_date)
            builder = builder.add_extension(ext, critical=False)

        if indirect_crl:
            if not self.issuer_gnames:
                raise InvalidCertificate("Indirect CRL requires issuer_gnames")
            elif self.issuer_gnames != cur_gnames:
                glist = make_gnames(self.issuer_gnames)
                ext = x509.CertificateIssuer(glist)
                builder = builder.add_extension(ext, critical=True)
        elif self.issuer_gnames and self.issuer_gnames != cur_gnames:
            raise InvalidCertificate("Only Indirect-CRL can store certs from different CAs")
        return builder

    def load_from_existing(self, obj: x509.RevokedCertificate) -> None:
        """Load data from x509.RevokedCertificate
        """
        if not isinstance(obj, x509.RevokedCertificate):
            raise InvalidCertificate("Expect RevokedCertificate, got %s" % type(obj))

        self.serial_number = obj.serial_number
        self.revocation_date = get_utc_datetime(obj, "revocation_date")
        self.reason = None
        self.invalidity_date = None
        self.issuer_gnames = []

        for ext in obj.extensions:
            extobj = ext.value
            if ext.oid == CRLEntryExtensionOID.CRL_REASON:
                self.reason = CRL_REASON_MAP.get(extobj.reason)
            elif ext.oid == CRLEntryExtensionOID.INVALIDITY_DATE:
                self.invalidity_date = get_utc_datetime(extobj, "invalidity_date")
            elif ext.oid == CRLEntryExtensionOID.CERTIFICATE_ISSUER:
                self.issuer_gnames = extract_gnames(extobj)
            else:
                raise InvalidCertificate("Unsupported extension in CRL: %s" % (ext,))

    def show(self, writeln: Callable[[str], None]) -> None:
        """Print info.
        """
        writeln("Revoked certificate:")
        if self.serial_number is not None:
            writeln("  Serial: %s" % render_serial(self.serial_number))
        if self.revocation_date is not None:
            writeln("  Revocation Date: %s" % self.revocation_date.isoformat(" "))
        if self.invalidity_date is not None:
            writeln("  Invalidity Date: %s" % self.invalidity_date.isoformat(" "))
        if self.reason is not None:
            writeln("  Reason: %s" % self.reason)
        show_list("  Issuer GNames", self.issuer_gnames, writeln)


class CRLInfo:
    """Container for certificate revocation object info.
    """
    revoked_list: List[RevCertInfo]
    next_update: Optional[datetime]
    last_update: Optional[datetime]
    issuer_name: NameSeq
    signature_algorithm_oid: Optional[x509.ObjectIdentifier]
    signature_algorithm_parameters: Optional[SignatureParamsType]
    rsa_pss: bool

    # CRLNumber
    crl_number: Optional[int]

    # DeltaCRLIndicator
    delta_crl_number: Optional[int]

    # IssuerAlternativeName
    issuer_san: GNameList

    # IssuingDistributionPoint
    crl_scope: CRLScope
    indirect_crl: bool
    only_some_reasons: FrozenSet[str]
    full_methods: List[str]

    # Freshest CRL (a.k.a. Delta CRL Distribution Point)
    delta_crl_urls: List[str]

    # AuthorityKeyIdentifier
    authority_key_identifier: Optional[str]
    authority_cert_issuer: NameSeq
    authority_cert_serial_number: Optional[int]

    # AuthorityInformationAccess
    issuer_urls: List[str]
    ocsp_urls: List[str]

    def __init__(self,
                 revoked_list: Optional[List[RevCertInfo]] = None,
                 next_update: Optional[MaybeTimestamp] = None,
                 last_update: Optional[MaybeTimestamp] = None,
                 crl_number: Optional[MaybeNumber] = None,
                 delta_crl_number: Optional[MaybeNumber] = None,
                 crl_scope: CRLScope = "all",
                 indirect_crl: bool = False,
                 only_some_reasons: Optional[MaybeList] = None,
                 full_methods: Optional[MaybeList] = None,
                 issuer_urls: Optional[MaybeList] = None,
                 ocsp_urls: Optional[MaybeList] = None,
                 delta_crl_urls: Optional[MaybeList] = None,
                 rsa_pss: bool = False,
                 load: Optional[x509.CertificateRevocationList] = None):
        """Initialize info object.
        """
        self.revoked_list = revoked_list or []
        self.next_update = maybe_parse_timestamp(next_update)
        self.last_update = maybe_parse_timestamp(last_update)
        self.issuer_name = ()
        self.signature_algorithm_oid = None
        self.signature_algorithm_parameters = None
        self.rsa_pss = rsa_pss

        # CRLNumber
        self.crl_number = maybe_parse_number(crl_number)

        # DeltaCRLIndicator
        self.delta_crl_number = maybe_parse_number(delta_crl_number)

        # IssuerAlternativeName
        self.issuer_san = []

        # IssuingDistributionPoint
        self.crl_scope = crl_scope      # all,user,ca,attr
        self.indirect_crl = indirect_crl
        self.only_some_reasons = frozenset(maybe_parse_list(only_some_reasons))
        self.full_methods = maybe_parse_list(full_methods)

        # Freshest CRL (a.k.a. Delta CRL Distribution Point)
        self.delta_crl_urls = maybe_parse_list(delta_crl_urls)

        # AuthorityKeyIdentifier
        self.authority_key_identifier = None
        self.authority_cert_issuer = ()
        self.authority_cert_serial_number = None

        # AuthorityInformationAccess
        self.issuer_urls = maybe_parse_list(issuer_urls)
        self.ocsp_urls = maybe_parse_list(ocsp_urls)

        if load is not None:
            self.load_from_existing(load)

    def load_from_existing(self, obj: x509.CertificateRevocationList) -> None:
        """Load certificate info from existing CRL.
        """
        if not isinstance(obj, x509.CertificateRevocationList):
            raise TypeError("Expect CertificateRevocationList")
        self.issuer_name = extract_name(obj.issuer)
        self.next_update = get_utc_datetime_opt(obj, "next_update")
        self.last_update = get_utc_datetime(obj, "last_update")

        self.signature_algorithm_oid = obj.signature_algorithm_oid
        if self.signature_algorithm_oid:
            if self.signature_algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS:
                self.rsa_pss = True
        try:
            signature_algorithm_parameters = getattr(obj, "signature_algorithm_parameters", None)
        except ValueError:
            signature_algorithm_parameters = None
        self.signature_algorithm_parameters = signature_algorithm_parameters

        for ext in obj.extensions:
            extobj = ext.value
            if ext.oid == ExtensionOID.CRL_NUMBER:
                self.crl_number = extobj.crl_number
            elif ext.oid == ExtensionOID.DELTA_CRL_INDICATOR:
                self.delta_crl_number = extobj.crl_number
            elif ext.oid == ExtensionOID.ISSUER_ALTERNATIVE_NAME:
                self.issuer_san = extract_gnames(extobj)
            elif ext.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                self.authority_key_identifier = to_hex(extobj.key_identifier)
                self.authority_cert_issuer = extract_name(extobj.authority_cert_issuer)
                self.authority_cert_serial_number = extobj.authority_cert_serial_number
            elif ext.oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                self.issuer_urls, self.ocsp_urls = extract_auth_access(extobj)
            elif ext.oid == ExtensionOID.FRESHEST_CRL:
                # list of DistributionPoint
                self.delta_crl_urls = extract_distribution_point_urls(extobj)
            elif ext.oid == ExtensionOID.ISSUING_DISTRIBUTION_POINT:
                # IssuingDistributionPoint
                self.extract_issuing_dpoint(extobj)
            else:
                raise InvalidCertificate("Unsupported extension in CRL: %s" % (ext,))

        # load revoked certs
        cur_gnames: GNameList = to_issuer_gnames(self.issuer_name, self.issuer_san)
        for r_cert_obj in obj:
            r_cert = RevCertInfo(load=r_cert_obj, issuer_gnames=cur_gnames)
            cur_gnames = r_cert.issuer_gnames
            self.revoked_list.append(r_cert)

    def extract_issuing_dpoint(self, extobj: x509.IssuingDistributionPoint) -> None:
        if extobj.only_contains_user_certs:
            self.crl_scope = "user"
        elif extobj.only_contains_ca_certs:
            self.crl_scope = "ca"
        elif extobj.only_contains_attribute_certs:
            self.crl_scope = "attr"
        else:
            self.crl_scope = "all"

        self.indirect_crl = extobj.indirect_crl
        self.full_methods = extract_gnames(extobj.full_name)
        if extobj.only_some_reasons:
            self.only_some_reasons = frozenset(CRL_REASON_MAP[f] for f in extobj.only_some_reasons)
        if extobj.relative_name:
            raise InvalidCertificate("Relative Name not supported")

    def make_issuing_dpoint(self) -> Optional[x509.IssuingDistributionPoint]:
        args: Dict[str, Any] = {
            "full_name": None, "relative_name": None,
            "only_contains_user_certs": False,
            "only_contains_ca_certs": False,
            "only_some_reasons": None, "indirect_crl": False,
            "only_contains_attribute_certs": False,
        }

        if self.crl_scope == "ca":
            args["only_contains_ca_certs"] = True
        elif self.crl_scope == "user":
            args["only_contains_user_certs"] = True
        elif self.crl_scope == "attr":
            args["only_contains_attribute_certs"] = True
        elif self.crl_scope != "all":
            raise ValueError("invalid scope: %r" % self.crl_scope)

        if self.indirect_crl:
            args["indirect_crl"] = True

        if self.only_some_reasons:
            args["only_some_reasons"] = frozenset([CRL_REASON[r] for r in self.only_some_reasons])

        if self.full_methods is not None:
            args["full_name"] = make_gnames(self.full_methods)

        if any(args.values()):
            return x509.IssuingDistributionPoint(**args)
        return None

    def install_extensions(
            self, builder: x509.CertificateRevocationListBuilder) -> x509.CertificateRevocationListBuilder:
        """Add common extensions to CRL builder.
        """
        ext: x509.ExtensionType

        # CRLNumber
        if self.crl_number is not None:
            ext = x509.CRLNumber(self.crl_number)
            builder = builder.add_extension(ext, critical=False)

        # DeltaCRLIndicator
        if self.delta_crl_number is not None:
            if self.crl_number is None:
                raise InvalidCertificate("Delta CRL must also have CRLNumber extension")
            ext = x509.DeltaCRLIndicator(self.delta_crl_number)
            builder = builder.add_extension(ext, critical=True)

        # IssuingDistributionPoint
        extd = self.make_issuing_dpoint()
        if extd is not None:
            builder = builder.add_extension(extd, critical=True)

        # AuthorityInformationAccess
        if self.issuer_urls or self.ocsp_urls:
            url_list: List[x509.AccessDescription] = []
            oid = AuthorityInformationAccessOID.CA_ISSUERS
            for gn in convert_urls_to_gnames(self.issuer_urls):
                url_list.append(x509.AccessDescription(oid, gn))
            oid = AuthorityInformationAccessOID.OCSP
            for gn in convert_urls_to_gnames(self.ocsp_urls):
                url_list.append(x509.AccessDescription(oid, gn))
            ext = x509.AuthorityInformationAccess(url_list)
            builder = builder.add_extension(ext, critical=False)

        # FreshestCRL
        if self.delta_crl_urls:
            if self.delta_crl_number is not None:
                raise InvalidCertificate("FreshestCRL must not apper in Delta CRL")
            full_names = convert_urls_to_gnames(self.delta_crl_urls)
            point = x509.DistributionPoint(full_names, None, None, None)
            ext = x509.FreshestCRL([point])
            builder = builder.add_extension(ext, critical=False)

        return builder

    def install_revoked_certs(self, builder: x509.CertificateRevocationListBuilder,
                              cur_gnames: Optional[List[str]]) -> x509.CertificateRevocationListBuilder:
        for rev_cert in self.revoked_list:
            rcert = rev_cert.generate_rcert(self.indirect_crl, cur_gnames)
            builder = builder.add_revoked_certificate(rcert)
            cur_gnames = rev_cert.issuer_gnames
        return builder

    def show(self, writeln: Callable[[str], None]) -> None:
        """Print out details.
        """
        writeln("CRL Scope: %s" % self.crl_scope)
        if self.crl_number is not None:
            writeln("CRL Number: %s" % render_serial(self.crl_number))
        if self.delta_crl_number is not None:
            writeln("Delta CRL Number: %s" % render_serial(self.delta_crl_number))
        if self.last_update:
            writeln("Last update: %s" % self.last_update.isoformat(" "))
        if self.next_update:
            writeln("Next update: %s" % self.next_update.isoformat(" "))
        if self.indirect_crl:
            writeln("Indirect CRL: True")
        if self.signature_algorithm_oid:
            signame = getattr(self.signature_algorithm_oid, "_name", "")
            if signame:
                writeln("Signature: %s" % signame)
            else:
                writeln("Signature: %s" % self.signature_algorithm_oid.dotted_string)
        if self.signature_algorithm_parameters and self.rsa_pss:
            writeln("Signature params: %s" % get_param_info(self.signature_algorithm_parameters))
        if self.issuer_name:
            writeln("Issuer Name: %s" % render_name(self.issuer_name))
        show_list("Issuer SAN", self.issuer_san, writeln)
        if self.authority_key_identifier:
            writeln("Authority Key Identifier: %s" % self.authority_key_identifier)
        if self.authority_cert_serial_number:
            writeln("Authority Certificate Serial: %s" % render_serial(self.authority_cert_serial_number))
        if self.authority_cert_issuer:
            writeln("Authority Certificate Issuer: %s" % render_name(self.authority_cert_issuer))
        if self.only_some_reasons:
            show_list("OnlySomeReasons", list(sorted(self.only_some_reasons)), writeln)
        show_list("Full Methods", self.full_methods, writeln)
        show_list("Issuer URLs", self.issuer_urls, writeln)
        show_list("OCSP URLs", self.ocsp_urls, writeln)
        show_list("Delta CRL URLs", self.delta_crl_urls, writeln)

        for rcert in self.revoked_list:
            rcert.show(writeln)

    def add_serial_number(self, serial: int, reason: Optional[str] = None,
                          invalidity_date: Optional[Union[str, datetime]] = None,
                          issuer_gnames: Optional[Union[str, List[str]]] = None,
                          revocation_date: Optional[Union[str, datetime]] = None,
                          ) -> None:
        rcrt = RevCertInfo(serial_number=serial, reason=reason, invalidity_date=invalidity_date,
                           revocation_date=revocation_date,
                           issuer_gnames=issuer_gnames)
        self.revoked_list.append(rcrt)

    def add_certificate(self, cert: Union[CertInfo, x509.Certificate],
                        reason: Optional[str] = None,
                        invalidity_date: Optional[Union[str, datetime]] = None,
                        revocation_date: Optional[Union[str, datetime]] = None,
                        ) -> None:
        if isinstance(cert, x509.Certificate):
            cert = CertInfo(load=cert)
        elif not isinstance(cert, CertInfo):
            raise TypeError("Expect CertInfo or x509.Certificate")

        assert cert.serial_number
        self.add_serial_number(cert.serial_number, reason=reason, invalidity_date=invalidity_date,
                               revocation_date=revocation_date,
                               issuer_gnames=to_issuer_gnames(cert.issuer_name, cert.issuer_san))


def create_x509_crl(issuer_privkey: IssuerPrivateKeyTypes,
                    issuer_info: Union[CertInfo, x509.Certificate, x509.CertificateSigningRequest],
                    crl_info: Union[CRLInfo, x509.CertificateRevocationList],
                    days: Optional[int] = None,
                    last_update: Optional[datetime] = None,
                    next_update: Optional[datetime] = None) -> x509.CertificateRevocationList:
    """Create x509.CertificateRevocationList
    """
    ext: x509.ExtensionType

    if not safe_issuer_privkey(issuer_privkey):
        raise TypeError("Invalid issuer private key")
    if isinstance(issuer_info, (x509.Certificate, x509.CertificateSigningRequest)):
        issuer_info = CertInfo(load=issuer_info)
    elif not isinstance(issuer_info, CertInfo):
        raise TypeError("Expect issuer_info to be CertInfo or x509.Certificate")

    if not isinstance(crl_info, CRLInfo):
        crl_info = CRLInfo(load=crl_info)

    if "crl_sign" not in issuer_info.usage:
        raise InvalidCertificate("Signing certificate needs to have crl_sign usage set.")

    last_update, next_update = parse_time_period(days, last_update, next_update, gap=0)

    builder = x509.CertificateRevocationListBuilder()
    if issuer_info.subject:
        builder = builder.issuer_name(make_name(issuer_info.subject))
    builder = builder.last_update(last_update)
    builder = builder.next_update(next_update)
    builder = crl_info.install_extensions(builder)

    # add revoked certs
    cur_gnames = to_issuer_gnames(issuer_info.subject, issuer_info.san)
    builder = crl_info.install_revoked_certs(builder, cur_gnames)

    # IssuerAlternativeName
    if issuer_info.san:
        ext = x509.IssuerAlternativeName(make_gnames(issuer_info.san))
        builder = builder.add_extension(ext, critical=False)

    # AuthorityKeyIdentifier
    ext = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_privkey.public_key())
    builder = builder.add_extension(ext, critical=False)

    rsa_pss = crl_info.rsa_pss or issuer_info.rsa_pss
    if rsa_pss and isinstance(issuer_privkey, rsa.RSAPrivateKey):
        crl = builder.sign(private_key=issuer_privkey,
                           algorithm=get_hash_algo(issuer_privkey, "CRL"),
                           rsa_padding=get_rsa_padding(issuer_privkey, "CRL"))
    else:
        crl = builder.sign(private_key=issuer_privkey,
                           algorithm=get_hash_algo(issuer_privkey, "CRL"))
    return crl

