SysCA - Certificate tool for Sysadmins
======================================

Description
-----------

Easy-to-use command-line tool for certificate management.

Features
--------

- Simple command-line UI.
- Good defaults, sets up common extensions automatically.
- PGP- and password-protected private keys.
- OCSP and CRL info settings.
- Supports EC, RSA and DSA keys.

Dependencies
------------

- Python `cryptography`_ module (version >= 2.1).
- (Optional) `gpg`_ command-line tool to decrypt files.

.. _cryptography: https://cryptography.io/
.. _gpg: https://www.gnupg.org/

Summary
-------

Generate new key::

    sysca new-key              [--password-file TXT_FILE] [--out DST]
    sysca new-key ec[:<curve>] [--password-file TXT_FILE] [--out DST]
    sysca new-key rsa[:<bits>] [--password-file TXT_FILE] [--out DST]
    sysca new-key dsa[:<bits>] [--password-file TXT_FILE] [--out DST]

Create certificate signing request::

    sysca request --key KEY_FILE [--password-file TXT_FILE]
                  [--subject DN] [--san ALTNAMES]
                  [--CA] [--path-length DEPTH]
                  [--usage FLAGS] [--ocsp-url URLS] [--crl-url URLS]
                  [--issuer-cert-url URLS]
                  [--out CSR_FN]

Create selfsigned certificate::

    sysca selfsign --key KEY_FILE --days N [--password-file TXT_FILE]
                  [--subject DN] [--san ALTNAMES]
                  [--CA] [--path-length DEPTH]
                  [--usage FLAGS] [--ocsp-url URLS] [--crl-url URLS]
                  [--issuer-cert-url URLS]
                  [--out CRT_FN]

Sign certificate signing request::

    sysca sign --ca-key KEY_FILE --ca-info CRT_FILE
               --request CSR_FILE --days NUM
               [--out CRT_FN] [--password-file TXT_FILE]
               [--reset ...]

Create or update CRL file::

    sysca update-crl [--crl CRL_FILE] [--out CRT_FN]
               --ca-key KEY_FILE --ca-info CRT_FILE [--password-file TXT_FILE]
               --days NUM [--crl-number NUM] [--delta-crl-number NUM]
               [--reason REASON_NAME]
               [--revoke-cert CERT_FILE] ...
               [--revoke-serial SERIAL] ...

Display contents of CRT, CSR or CRL file::

    sysca show FILE

Commands
--------

new-key
~~~~~~~

Generate new key.

Takes key type as optional argument.  Value can be either ``ec:<curve>``,
``rsa:<bits>`` or ``dsa:<bits>``.  Shortcuts: ``ec`` is ``ec:secp256r1``,
``rsa`` is ``rsa:2048``, ``dsa`` is ``dsa:2048``.  Default: ``ec``.

Suggested curves for EC: ``secp256r1``, ``secp384r1``, ``secp521r1``, ``ed25519``.

Options:

**--password-file FILE**
    Password will be loaded from file.  Can be PGP-encrypted.
    Resulting private key will be encrypted with this password.

**--out DST_FN**
    Target file to write key to.  It's preferable to write to
    stdout and encrypt with GPG.

**--outform PEM|DER**
    Output file format.  PEM is textual format, DER is binary.  Default: PEM.

request
~~~~~~~

Create certificate signing request (CSR).

Options:

**--out CSR_FILE**
    Target file to write Certificate Signing Request to.

**--outform PEM|DER**
    Output file format.  PEM is textual format, DER is binary.  Default: PEM.

**--key KEY_FILE**
    Private key file to create request for.  Can be PGP-encrypted.
    Can be password-protected.

**--password-file FN**
    Password file for private key.  Can be PGP-encrypted.

**--subject DN**
    Subject's DistinguishedName which is X509 Name structure, which is collection
    of key-value pairs.

    Each pair is separated with "/", key and value are separated with "=".
    Surrounding whitespace around both "/" and "=" will be stripped.
    "\\" can be used for escaping.

    Most important field: CN=commonName.

    Common fields: O=organizationName, OU=organizationalUnit, C=countryName,
    L=locality, ST=stateOrProvinceName.

    Less common fields: SN=surname, GN=givenName, T=title, P=pseudonym,
    SA=streetAddress.

    Example: ``--subject "/CN=www.example.com/ O=My Company / OU = DevOps"``

    Default: empty.

    Certificate field: Subject_.

**--CA**
    The certificate will have CA rights - that means it can
    sign other certificates.

    Extension: BasicConstraints_.

**--path-length**
    Applies only for CA certs - limits how many levels on sub-CAs
    can exist under generated certificate.  Default: Undefined.

    Extension: BasicConstraints_.

**--san ALT_NAMES**
    Specify alternative names for subject as list of comma-separated
    strings, that have prefix that describes data type.

    Supported prefixes:

        dns
            Domain name.
        email
            Email address.  Plain addr-spec_ (local_part @ domain) is allowed here,
            no <> or full name.
        ip
            IPv4 or IPv6 address.
        uri
            Uniform Resource Identifier.
        dn
            DirectoryName, which is X509 Name structure.  See ``--subject`` for syntax.

    Example: ``--san "dns: *.example.com, dns: www.foo.org, ip: 127.0.0.1 "``

    Extension: SubjectAlternativeName_.

Options useful only when apps support them:

**--usage USAGE_FLAGS**
    Comma-separated keywords that set KeyUsage and ExtendedKeyUsage flags.

    ExtendedKeyUsage_ flags, none set by default.

        client
            TLS Web Client Authentication.
        server
            TLS Web Server Authentication.
        code
            Code signing.
        email
            E-mail protection.
        time
            Time stamping.
        ocsp
            OCSP signing.
        any
            All other purposes too that are not explicitly mentioned.

    KeyUsage_ flags, by default CA certificate will have ``key_cert_sign`` and ``crl_sign`` set,
    non-CA certificate will have ``digital_signature`` and ``key_encipherment`` set but only
    if no ``--usage`` was given by user.

        digital_signature
            Allowed to sign anything that is not certificate for key.
        key_agreement
            Key is allowed to use in key agreement.
        key_cert_sign
            Allowed to sign certificates for other keys.
        crl_sign
            Allowed to sign certificates for certificate revocation lists (CRLs).
        key_encipherment
            Secret keys (either private or symmetric) can be encrypted against
            public key in certificate.  Does not apply to session keys, but
            standalone secret keys?
        data_encipherment
            Raw data can be encrypted against public key in certificate. [Bad idea.]
        content_commitment
            Public key in certificate can be used for signature checking in
            "seriously-i-mean-it" environment.  [Historical.]
        encipher_only
            If ``key_agreement`` is true, this flag limits use only for data encryption.
        decipher_only
            If ``key_agreement`` is true, this flag limits use only for data decryption.

**--ocsp-nocheck**
    Disable OCSP checking for this certificate.  Used for certificates that
    sign OCSP status replies.

    Extension: OCSPNoCheck_.

**--ocsp-must-staple**
    Requires that TLS handshake must be done with stapled OCSP response
    using ``status_request`` protocol.

    Extension: OCSPMustStaple_.

**--ocsp-must-staple-v2**
    Requires that TLS handshake must be done with stapled OCSP response
    using ``status_request_v2`` protocol.

    Extension: OCSPMustStapleV2_.

**--crl-url URLS**
    List of URLs where certificate revocation lists can be downloaded.

    Extension: CRLDistributionPoints_.

**--ocsp-url URLS**
    List of URL for OCSP endpoint where validity can be checked.

    Extension: AuthorityInformationAccess_.

**--issuer-url URLS**
    List of URLS where parent certificate can be downloaded,
    in case the parent CA is not root CA.  Usually sub-CA certificates
    should be provided during key-agreement (TLS).  This setting
    is for situations where this cannot happen or for fallback
    for badly-configured TLS servers.

    Extension: AuthorityInformationAccess_.

**--exclude-subtrees NAME_PATTERNS**
    Disallow CA to sign subjects that match patterns.  See ``--permit-subtrees``
    for details.

**--permit-subtrees NAME_PATTERNS**
    Allow CA to sign subjects that match patterns.

    Specify patters for subject as list of comma-separated
    strings, that have prefix that describes data type.

    Supported prefixes:

        dns
            Domain name.
        email
            Email address.  Plain addr-spec_ (local_part @ domain) is allowed here,
            no <> or full name.
        net
            IPv4 or IPv6 network.
        uri
            Uniform Resource Identifier.
        dn
            DirectoryName, which is X509 Name structure.  See ``--subject`` for syntax.

    Extension: NameConstraints_.

**--inhibit-any N**
    Disallow special handling of ``any`` policy (2.5.29.32.0)
    after N levels.

    Extension: InhibitAnyPolicy_.

**--require-explicit-policy N**
    Require explicit certificate policy for whole path after N levels.

    Extension: PolicyConstraints_.

**--inhibit-policy-mapping N**
    Disallow policy mapping processing after N levels.

    Extension: PolicyConstraints_.

**--add-policy OID:SPECS**
    Add another PolicyInformation record to certificate with optional qualifiers.

    Usage:

        ``--add-policy OID``
            Just add OID alone.  Recommended usage.

        ``--add-policy OID:SPEC,SPEC``
            Add policy OID with one or more qualifiers.

    Qualifier spec for URI pointer to CPS (Certification Practice Statement): ``|P=URI|``

    Qualifier spec for UserNotice with explicitText and noticeRef: ``|T=explicit_text|O=orgName|N=1:2:3|``

    Extension: CertificatePolicies_.

sign
~~~~

Create signed certificate based on data in request.
Any unsupported extensions in request will cause error.

It will add SubjectKeyIdentifier_ and AuthorityKeyIdentifier_
extensions to final certificate that help to uniquely identify
both subject and issuers public keys.  Also IssuerAlternativeName_
is added as copy of CA cert's SubjectAlternativeName_ extension
if present.

Options:

**--out CRT_FILE**
    Target file to write certificate to.

**--outform PEM|DER**
    Output file format.  PEM is textual format, DER is binary.  Default: PEM.

**--days NUM**
    Lifetime for certificate in days.

**--request CSR_FILE**
    Certificate request file generated by **request** command.

**--ca-key KEY_FILE**
    CA private key file.  Can be PGP-encrypted.
    Can be password-protected.

**--ca-info CRT_FILE**
    CRT file generated by **request** command.  Issuer CA info
    will be loaded from it.

**--password-file FN**
    Password file for CA private key.  Can be PGP-encrypted.

**--reset**
    Do not use any info fields from CSR, reload all info from command line.
    Without it, all info from CSR is kept and command line is ignored.

selfsign
~~~~~~~~

This commands takes same arguments as ``request`` plus ``--days NUM``.
Preferable to use with ``--CA`` and ``--usage`` options.

update-crl
~~~~~~~~~~

Creates or updates Certificate Revocation List file.

CRL file can be either full or delta:

    full
        Contains full set of revoked certificates.
        Options: ``--crl-number=CUR``
    delta
        Contains only certificates missing from older CRL version.
        Options: ``--delta-crl-number=OLD --crl-number=CUR``

CRL file can be either direct or indirect:

    direct
        All revoked certificates belong to signer that issues CRL.
    indirect
        Revoked certificates contain reference to actual CA that issued.
        Set with option: ``--indirect-crl``.

Options for CRL itself:

**--crl FN**
    Load existing file.  Version numbers are reused unless overrided on command line.

**--out FN**
    Write output to file.

**--outform PEM|DER**
    Output file format.  PEM is textual format, DER is binary.  Default: PEM.

**--days NUM**
    Set period that this CRL is valid.

**--ca-key KEY_FILE**
    CA private key file.  Can be PGP-encrypted.  Can be password-protected.

**--ca-info CRT_FILE**
    CA certificate used for signing.

**--crl-number VER**
    Version number for main CRL.

    Extension: CRLNumber_.

**--delta-crl-number VER**
    Version number of prevous CRL that this delta is from.

    Extension: DeltaCRLNumber_.

**--crl-scope SCOPE**
    CRL scope, one of: all, user, ca, attr. Default: all

    This flags shows that CRL contains only specific types of certificates.

        all
            All types.  Default.
        user
            Only user certificates.
        ca
            Only CA certificates.
        attr
            Only attribute certificates.

    Extension: CRLIssuingDistributionPoint_.

**--indirect-crl**
    CRL list can contain revoked certificates not issued by CRL signer.

    Extension: CRLIssuingDistributionPoint_.

**--issuer-urls URLS**
    Override issuer URLs.  Default: taken from signer certificate.

    Extension: CRLAuthorityInformationAccess_.

Options for adding entries:

**--revoke-certs FN [FN ...]**
    Filenames of certificates to add.

**--revoke-serials NUM [NUM ...]**
    Certificate serial numbers to add.

**--reason REASON**
    Revocation reason.  Used for all entries added in one command.  One of:

        key_compromise
            Private key compromise.
        ca_compromise
            CA key compromise.
        affiliation_changed
            Current certificate is obsolete.  Another CA is being responsible.
        superseded
            Current certificate is obsolete.  New certificate has been issued.
        cessation_of_operation
            Current certificate is obsolete.  CA shut down.
        privilege_withdrawn
            Certificate attributes are not valid anymore.
        aa_compromise
            Provider of attributes to certificate has been compromised.
        certificate_hold
            Temporary entry, actual reason will follow later.
        remove_from_crl
            Certificate should not be in CRL anymore.
        unspecified
            Default, means no reason has been provided.

    Extension: CRLReason_.

**--invalidity-date DATE**
    Consider certificate invalid from date.  Optional, if missing
    revocation date is used.

    Extension: CRLInvalidityDate_.

show
~~~~

Display contents of CSR or CRT file.

list
~~~~

Output values for various parameters.

**list ec-curves**
    Show supported safe curves.  Needs ``--unsafe`` flag to show all supported curves.

**list name-fields**
    Show keywords usable in name fields.

export
~~~~~~

Reads and outputs file again.  Useful for converting key formats.

Options:

**--out FN**
    Write output to file.

**--outform PEM|DER**
    Output file format.  PEM is textual format, DER is binary.  Default: PEM.

**--password-file FN**
    Password file for CA private key.  Can be PGP-encrypted.

export-pub
~~~~~~~~~~

Reads certificate, certificate request or private key file and outputs it's public key.

Options:

**--out FN**
    Write output to file.

**--outform PEM|DER**
    Output file format.  PEM is textual format, DER is binary.  Default: PEM.

**--password-file FN**
    Password file for CA private key.  Can be PGP-encrypted.

autogen
~~~~~~~

Generates key and certificate based on config file.

Options:

**--ca-dir DIRNAME**
    Where are CA keys located.

**--password-file FN**
    Password file for CA private key.  Can be PGP-encrypted.

**--out OUTDIR**
    Directory where output is written.

**--outform PEM|DER**
    Output file format.  PEM is textual format, DER is binary.  Default: PEM.

Autogen config format
---------------------

Config is in INI/ConfigParser format::

    [DEFAULT]
    default_ca = SomeCA

    [webserver]
    usage = server
    subject = CN=server.com, O=Org
    alt_names = dns:server.com, dns:www.server.com
    days = 500
    ca_name = ${default_ca}

Default section
~~~~~~~~~~~~~~~

Config can contain optional section named ``DEFAULT``.  Parameters
defined there are visible in all other sections.

Named sections
~~~~~~~~~~~~~~

All other sections define key and certificate pair to generate.

Options:

**ca_name = <CA name>**
    CA name to use.

    Required parameter, no default.

**days = <number-of-days>**
    How many days is certificate valid.

    Default: 730

**ktype = key-type**
    Which key type to use.

    Default: ec

**subject = Subject DN string**
    Distinguished Name for certificate subject./CN=foo/O=Org/OU=Web/

    Default: CN=${common_name}

**common_name = name**
    Common name for sertificate when subject= is not given.

    Default: section name.

**alt_names = <SAN string>**
    Common name for sertificate when subject= is not given.

    Default: set to dns:${common_name} when subject= is missing.

Private Key Protection
----------------------

Private keys can be stored unencryped, encrypted with PGP, encrypted with password or both.
Unencrypted keys are good only for testing.  Good practice is to encrypt both CA and
end-entity keys with PGP and use passwords only for keys that can be deployed to servers
with password-protection.

For each key, different set of PGP keys can be used that can decrypt it::

    $ sysca new-key | gpg -aes -r "admin@example.com" -r "backup@example.com" > CA.key.gpg
    $ sysca new-key | gpg -aes -r "admin@example.com" -r "devops@example.com" > server.key.gpg

Example
-------

Self-signed CA example::

    $ sysca new-key | gpg -aes -r "admin@example.com" > TestCA.key.gpg
    $ sysca selfsign --key TestCA.key.gpg --subject "/CN=TestCA/O=Gov" --CA > TestCA.crt

Sign server key::

    $ sysca new-key | gpg -aes -r "admin@example.com" > Server.key.gpg
    $ sysca request --key Server.key.gpg --subject "/CN=web.server.com/O=Gov" > Server.csr
    $ sysca sign --days 365 --request Server.csr --ca-key TestCA.key.gpg --ca-info TestCA.crt > Server.crt


Critical extensions
-------------------

SysCA does not allow tuning of critical_ extension flag,
following extensions are always set as critical when added to certificate:

* BasicConstraints_
* KeyUsage_
* ExtendedKeyUsage_
* NameConstraints_
* PolicyConstraints_
* InhibitAnyPolicy_

All other added extensions will be non-critical.

Compatibility notes
-------------------

Although SysCA allows to set various extension parameters, that does not
mean any software that uses the certificates actually looks or acts on
the extensions.  So it's reasonable to set up only extensions that are
actually used.

.. _Subject: https://tools.ietf.org/html/rfc5280#section-4.1.2.6
.. _BasicConstraints: https://tools.ietf.org/html/rfc5280#section-4.2.1.9
.. _KeyUsage: https://tools.ietf.org/html/rfc5280#section-4.2.1.3
.. _ExtendedKeyUsage: https://tools.ietf.org/html/rfc5280#section-4.2.1.12
.. _CRLDistributionPoints: https://tools.ietf.org/html/rfc5280#section-4.2.1.13
.. _SubjectAlternativeName: https://tools.ietf.org/html/rfc5280#section-4.2.1.6
.. _IssuerAlternativeName: https://tools.ietf.org/html/rfc5280#section-4.2.1.7
.. _AuthorityInformationAccess: https://tools.ietf.org/html/rfc5280#section-4.2.2.1
.. _NameConstraints: https://tools.ietf.org/html/rfc5280#section-4.2.1.10
.. _AuthorityKeyIdentifier: https://tools.ietf.org/html/rfc5280#section-4.2.1.1
.. _SubjectKeyIdentifier: https://tools.ietf.org/html/rfc5280#section-4.2.1.2
.. _addr-spec: https://tools.ietf.org/html/rfc5322#section-3.4.1
.. _OCSPNoCheck: https://tools.ietf.org/html/rfc6960
.. _OCSPMustStaple: https://tools.ietf.org/html/rfc7633
.. _OCSPMustStapleV2: https://tools.ietf.org/html/rfc7633
.. _CRLNumber: https://tools.ietf.org/html/rfc5280#section-5.2.3
.. _DeltaCRLNumber: https://tools.ietf.org/html/rfc5280#section-5.2.4
.. _CRLAuthorityInformationAccess: https://tools.ietf.org/html/rfc5280#section-5.2.7
.. _CRLIssuingDistributionPoint: https://tools.ietf.org/html/rfc5280#section-5.2.5
.. _CRLReason: https://tools.ietf.org/html/rfc5280#section-5.3.1
.. _CRLInvalidityDate: https://tools.ietf.org/html/rfc5280#section-5.3.2
.. _InhibitAnyPolicy: https://tools.ietf.org/html/rfc5280#section-4.2.1.14
.. _PolicyConstraints: https://tools.ietf.org/html/rfc5280#section-4.2.1.11
.. _CertificatePolicies: https://tools.ietf.org/html/rfc5280#section-4.2.1.4
.. _critical: https://tools.ietf.org/html/rfc5280#section-4.2
