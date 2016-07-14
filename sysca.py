#! /usr/bin/env python

"""Certificate tool for sysadmins.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os.path
import sys
import uuid
import argparse
import subprocess
import ipaddress
import re

from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat,
    BestAvailableEncryption, NoEncryption, load_pem_private_key)
from cryptography.x509.oid import (
    NameOID, ExtendedKeyUsageOID, ObjectIdentifier,
    ExtensionOID, AuthorityInformationAccessOID)
from cryptography import x509


__version__ = '1.0'

__all__ = [
    'CertInfo',
    'new_ec_key', 'new_rsa_key',
    'load_key', 'load_req', 'load_cert',
    'load_gpg_file', 'load_password',
    'create_x509_req', 'create_x509_cert',
    'key_to_pem', 'cert_to_pem', 'req_to_pem',
    'run_sysca'
]

#
# Shortcut maps
#

MIN_RSA_BITS = 1024
MAX_RSA_BITS = 8192

EC_CURVES = {
    'secp192r1': ec.SECP192R1,
    'secp224r1': ec.SECP224R1,
    'secp256r1': ec.SECP256R1,
    'secp384r1': ec.SECP384R1,
    'secp521r1': ec.SECP521R1,
    # aliases
    'prime256v1': ec.SECP256R1,
}

DN_CODE_TO_OID = {
    'CN': NameOID.COMMON_NAME,

    'O': NameOID.ORGANIZATION_NAME,
    'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,

    'C': NameOID.COUNTRY_NAME,
    'L': NameOID.LOCALITY_NAME,
    'ST': NameOID.STATE_OR_PROVINCE_NAME,
    'SA': ObjectIdentifier('2.5.4.9'),      # streetAddress

    'SN': NameOID.SURNAME,
    'GN': NameOID.GIVEN_NAME,
    'T': NameOID.TITLE,
    'GQ': NameOID.GENERATION_QUALIFIER,
    'DQ': NameOID.DN_QUALIFIER,
    'P': NameOID.PSEUDONYM,
}

KU_FIELDS = [
    'digital_signature',
    'content_commitment',
    'key_encipherment',
    'data_encipherment',
    'key_agreement',
    'key_cert_sign',
    'crl_sign',
    'encipher_only',
    'decipher_only',
]

XKU_CODE_TO_OID = {
    'any': ObjectIdentifier('2.5.29.37.0'),         # anyExtendedKeyUsage
    'server': ExtendedKeyUsageOID.SERVER_AUTH,
    'client': ExtendedKeyUsageOID.CLIENT_AUTH,
    'code': ExtendedKeyUsageOID.CODE_SIGNING,
    'email': ExtendedKeyUsageOID.EMAIL_PROTECTION,
    'time': ExtendedKeyUsageOID.TIME_STAMPING,
    'ocsp': ExtendedKeyUsageOID.OCSP_SIGNING,
}

QUIET = False

if sys.version_info[0] > 2:
    unicode = str


def as_bytes(s):
    """Return byte-string.
    """
    if isinstance(s, unicode):
        return s.encode('utf8')
    return s


def as_unicode(s):
    """Return unicode-string.
    """
    if isinstance(s, unicode):
        return s
    return s.decode('utf8')


def _escape_char(m):
    """Backslash-escape.
    """
    c = m.group(0)
    if c in (',', '\\', '/'):
        return '\\' + c
    return '\\x%02x' % ord(c)


def dn_escape(s):
    """Distinguishedname backslash-escape"""
    return re.sub(r'[\\/\x00-\x1F]', _escape_char, s)


def list_escape(s):
    """Escape value for comma-separated list
    """
    return re.sub(r'[\\,]', _escape_char, s)


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


def render_name(name):
    """Convert DistinguishedName dict to '/'-separated string.
    """
    res = ['']
    for k, v in name.items():
        v = dn_escape(v)
        res.append("%s=%s" % (k, v))
    res.append('')
    return '/'.join(res)


class CertInfo:
    """Container for certificate fields.
    """
    def __init__(self, subject=None, alt_names=None, ca=False, path_length=0,
                 usage=None, load=None, ocsp_urls=None, crl_urls=None, issuer_urls=None,
                 ocsp_nocheck=False,
                 permit_subtrees=None, exclude_subtrees=None):
        """Setup up details.

        Args:

            subject
                dict if strings.

            alt_names
                list of gname strings

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

            permit_subtrees
                list of gnames for permitted subtrees

            exclude_subtrees
                list of gnames for excluded subtrees

            load
                object to extract from (cert or cert request)

        """
        self.ca = ca
        self.path_length = path_length
        self.subject = subject and subject.copy() or {}
        self.san = alt_names and alt_names[:] or []
        self.usage = usage and usage[:] or []
        self.ocsp_urls = ocsp_urls and ocsp_urls[:] or []
        self.crl_urls = crl_urls and crl_urls[:] or []
        self.issuer_urls = issuer_urls and issuer_urls[:] or []
        self.exclude_subtrees = exclude_subtrees and exclude_subtrees[:] or []
        self.permit_subtrees = permit_subtrees and permit_subtrees[:] or []
        self.ocsp_nocheck = ocsp_nocheck

        if self.path_length < 0:
            self.path_length = None

        if load:
            self.load_from_existing(load)

    def load_from_existing(self, obj):
        """Load certificate info from existing certificate or certificate request.
        """
        self.subject = self.extract_name(obj.subject)

        for ext in obj.extensions:
            crit = ext.critical
            extobj = ext.value
            if ext.oid == ExtensionOID.BASIC_CONSTRAINTS:
                if not crit:
                    die("BASIC_CONSTRAINTS must be critical")
                self.ca = extobj.ca
                self.path_length = None
                if self.ca:
                    self.path_length = extobj.path_length
            elif ext.oid == ExtensionOID.KEY_USAGE:
                if not crit:
                    die("KEY_USAGE must be critical")
                self.usage += self.extract_key_usage(extobj)
            elif ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                self.san = self.extract_gnames(extobj)
            elif ext.oid == ExtensionOID.EXTENDED_KEY_USAGE:
                self.usage += self.extract_xkey_usage(extobj)
            elif ext.oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                for ad in extobj:
                    if not isinstance(ad.access_location, x509.UniformResourceIdentifier):
                        die("Unsupported access_location: %s", ad.access_location)
                    url = as_unicode(ad.access_location.value)

                    if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                        self.issuer_urls.append(url)
                    elif ad.access_method == AuthorityInformationAccessOID.OCSP:
                        self.ocsp_urls.append(url)
                    else:
                        die("Unsupported access_method: %s", ad.access_method)
            elif ext.oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
                for dp in extobj:
                    if dp.relative_name:
                        die("DistributionPoint.relative_name not supported")
                    if dp.crl_issuer:
                        die("DistributionPoint.crl_issuer not supported")
                    if dp.reasons:
                        die("DistributionPoint.reasons not supported")

                    for gn in self.extract_gnames(dp.full_name):
                        if gn.startswith('uri:'):
                            self.crl_urls.append(gn[4:])
                        else:
                            die("Unsupported DistributionPoint: %s", gn)
            elif ext.oid == ExtensionOID.NAME_CONSTRAINTS:
                self.permit_subtrees = self.extract_gnames(extobj.permitted_subtrees)
                self.exclude_subtrees = self.extract_gnames(extobj.excluded_subtrees)
            elif ext.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                pass
            elif ext.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                pass
            elif ext.oid == ExtensionOID.OCSP_NO_CHECK:
                self.ocsp_nocheck = True
            else:
                die("Unsupported extension in CSR: %s", ext)

    def extract_xkey_usage(self, ext):
        """Walk oid list, return keywords.
        """
        oidmap = {v: k for k, v in XKU_CODE_TO_OID.items()}
        res = []
        for oid in ext:
            if oid in oidmap:
                res.append(oidmap[oid])
            else:
                die("Unsupported ExtendedKeyUsage oid: %s", oid)
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

    def extract_name(self, name):
        """Convert Name object to shortcut-dict.
        """
        name_oid2code_map = {v: k for k, v in DN_CODE_TO_OID.items()}
        res = {}
        for att in name:
            if att.oid not in name_oid2code_map:
                die("Unsupported RDN: %s", att)
            desc = name_oid2code_map[att.oid]
            val = as_unicode(att.value)
            res[desc] = val
        return res

    def extract_gnames(self, ext):
        """Convert list of GeneralNames to list of prefixed strings.
        """
        res = []
        for gn in ext:
            if isinstance(gn, x509.RFC822Name):
                res.append('email:' + as_unicode(gn.value))
            elif isinstance(gn, x509.DNSName):
                res.append('dns:' + as_unicode(gn.value))
            elif isinstance(gn, x509.UniformResourceIdentifier):
                res.append('uri:' + as_unicode(gn.value))
            elif isinstance(gn, x509.IPAddress):
                res.append('ip:' + str(gn.value))
            elif isinstance(gn, x509.DirectoryName):
                val = self.extract_name(gn.value)
                res.append('dn:' + render_name(val))
            else:
                die("Unsupported subjectAltName type: %s", gn)
        return res

    def load_name(self, nmap):
        """Create Name object from subject DN.
        """
        attlist = []
        for k, v in nmap.items():
            oid = DN_CODE_TO_OID[k]
            n = x509.NameAttribute(oid, as_unicode(v))
            attlist.append(n)
        return x509.Name(attlist)

    def get_name(self):
        """Create Name object from subject DN.
        """
        return self.load_name(self.subject)

    def load_gnames(self, gname_list):
        """Converts list of prefixed strings to GeneralName list.
        """
        gnames = []
        for alt in gname_list:
            if ':' not in alt:
                die("Invalid gname: %s", alt)
            t, val = alt.split(':', 1)
            t = t.lower().strip()
            val = val.strip()
            if t == 'dn':
                gn = x509.DirectoryName(self.load_name(parse_dn(val)))
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
                gn = x509.DirectoryName(self.load_name(parse_dn(val)))
            elif t == 'net':
                if val.find(':') >= 0:
                    gn = x509.IPAddress(ipaddress.IPv6Network(val))
                else:
                    gn = x509.IPAddress(ipaddress.IPv4Network(val))
            else:
                raise Exception('Invalid GeneralName: ' + alt)
            gnames.append(gn)
        return gnames

    def get_san_gnames(self):
        """Return SubjectAltNames as GeneralNames
        """
        return self.load_gnames(self.san)

    def get_ocsp_gnames(self):
        """Return ocsp_urls as GeneralNames
        """
        urls = ['uri:' + u for u in self.ocsp_urls]
        return self.load_gnames(urls)

    def get_issuer_urls_gnames(self):
        """Return issuer_urls as GeneralNames
        """
        urls = ['uri:' + u for u in self.issuer_urls]
        return self.load_gnames(urls)

    def get_crl_gnames(self):
        """Return crl_urls as GeneralNames
        """
        urls = ['uri:' + u for u in self.crl_urls]
        return self.load_gnames(urls)

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
            ku_args['key_cert_sign'] = True
            ku_args['crl_sign'] = True
            ext = make_key_usage(**ku_args)
        else:
            ku_args['digital_signature'] = True
            ku_args['key_encipherment'] = True
            ext = make_key_usage(**ku_args)
        builder = builder.add_extension(ext, critical=True)

        # ExtendedKeyUsage, critical
        xku = [x for x in self.usage if x not in KU_FIELDS]
        xku_bad = [x for x in xku if x not in XKU_CODE_TO_OID]
        if xku_bad:
            die("Unknown usage keywords: %s", ','.join(xku_bad))
        if xku:
            xku_oids = [XKU_CODE_TO_OID[x] for x in xku]
            ext = x509.ExtendedKeyUsage(xku_oids)
            builder = builder.add_extension(ext, critical=True)

        # NameConstraints, critical
        if (self.exclude_subtrees or self.permit_subtrees) and self.ca:
            allow = self.load_gnames(self.permit_subtrees) or None
            disallow = self.load_gnames(self.exclude_subtrees) or None
            ext = x509.NameConstraints(allow, disallow)
            builder = builder.add_extension(ext, critical=True)

        # SubjectAlternativeName
        if self.san:
            ext = x509.SubjectAlternativeName(self.get_san_gnames())
            builder = builder.add_extension(ext, critical=False)

        # CRLDistributionPoints
        if self.crl_urls:
            full_names = self.get_crl_gnames()
            reasons = None
            crl_issuer = None
            point = x509.DistributionPoint(full_names, None, reasons, crl_issuer)
            ext = x509.CRLDistributionPoints([point])
            builder = builder.add_extension(ext, critical=False)

        # AuthorityInformationAccess
        if self.ocsp_urls or self.issuer_urls:
            oid = AuthorityInformationAccessOID.OCSP
            ocsp_list = [x509.AccessDescription(oid, gn) for gn in self.get_ocsp_gnames()]
            oid = AuthorityInformationAccessOID.CA_ISSUERS
            ca_list = [x509.AccessDescription(oid, gn) for gn in self.get_issuer_urls_gnames()]
            ext = x509.AuthorityInformationAccess(ocsp_list + ca_list)
            builder = builder.add_extension(ext, critical=False)

        # OCSPNoCheck
        if self.ocsp_nocheck:
            ext = x509.OCSPNoCheck()
            builder = builder.add_extension(ext, critical=False)

        # configured builder
        return builder

    def show_list(self, desc, lst, writeln):
        """Print out list field.
        """
        if not lst:
            return
        val = ', '.join([list_escape(v) for v in lst])
        writeln("%s: %s" % (desc, val))

    def show(self, writeln):
        """Print out details.
        """
        if self.subject:
            writeln('Subject: %s' % render_name(self.subject))
        self.show_list('SAN', self.san, writeln)
        self.show_list('Usage', self.usage, writeln)
        self.show_list('OCSP URLs', self.ocsp_urls, writeln)
        self.show_list('Issuer URLs', self.issuer_urls, writeln)
        self.show_list('CRL URLs', self.crl_urls, writeln)
        self.show_list('Permit', self.permit_subtrees, writeln)
        self.show_list('Exclude', self.exclude_subtrees, writeln)
        if self.ocsp_nocheck:
            self.show_list('OCSP NoCheck', ['True'], writeln)


def get_backend():
    """Returns backend to use.
    """
    from cryptography.hazmat.backends import default_backend
    return default_backend()


def make_key_usage(digital_signature=False, content_commitment=False, key_encipherment=False,
                  data_encipherment=False, key_agreement=False, key_cert_sign=False,
                  crl_sign=False, encipher_only=False,  decipher_only=False):
    """Default args for KeyUsage.
    """
    return x509.KeyUsage(digital_signature=digital_signature, content_commitment=content_commitment,
            key_encipherment=key_encipherment, data_encipherment=data_encipherment,
            key_agreement=key_agreement, key_cert_sign=key_cert_sign, crl_sign=crl_sign,
            encipher_only=encipher_only, decipher_only=decipher_only)


def create_x509_req(privkey, subject_info):
    """Main CSR creation code.
    """
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject_info.get_name())
    builder = subject_info.install_extensions(builder)

    # final req
    req = builder.sign(private_key=privkey, algorithm=SHA256(), backend=get_backend())
    return req


def create_x509_cert(privkey, pubkey, subject_info, issuer_info, days):
    """Main cert creation code.
    """

    dt_start = datetime.now()
    dt_end = dt_start + timedelta(days=days)

    builder = (x509.CertificateBuilder()
        .subject_name(subject_info.get_name())
        .issuer_name(issuer_info.get_name())
        .not_valid_before(dt_start)
        .not_valid_after(dt_end)
        .serial_number(int(uuid.uuid4()))
        .public_key(pubkey))

    builder = subject_info.install_extensions(builder)

    # SubjectKeyIdentifier
    ext = x509.SubjectKeyIdentifier.from_public_key(pubkey)
    builder = builder.add_extension(ext, critical=False)

    # AuthorityKeyIdentifier
    ext = x509.AuthorityKeyIdentifier.from_issuer_public_key(privkey.public_key())
    builder = builder.add_extension(ext, critical=False)

    # IssuerAlternativeName
    if issuer_info.san:
        ext = x509.IssuerAlternativeName(issuer_info.get_san_gnames())
        builder = builder.add_extension(ext, critical=False)

    # final cert
    cert = builder.sign(private_key=privkey, algorithm=SHA256(), backend=get_backend())
    return cert


def new_ec_key(name='secp256r1'):
    """New Elliptic Curve key
    """
    if name not in EC_CURVES:
        raise ValueError('Unknown curve')
    return ec.generate_private_key(curve=EC_CURVES[name], backend=get_backend())


def new_rsa_key(bits=2048):
    """New RSA key.
    """
    if bits < MIN_RSA_BITS or bits > MAX_RSA_BITS:
        raise ValueError('Bad value for bits')
    return rsa.generate_private_key(key_size=bits, public_exponent=65537, backend=get_backend())


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
    log = as_unicode(err).strip()
    if p.returncode != 0:
        die("%s: gpg failed: \n  %s", fn, log)

    # cannot say "you need to check sigs" to gpg...
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


def load_password(fn):
    """Read password from potentially gpg-encrypted file.
    """
    if not fn:
        return None
    data = load_gpg_file(fn)
    data = data.strip(b'\n')
    return data


def loop_escaped(val, c):
    """Parse list of strings, separated by c.
    """
    if not val:
        val = ''
    val = as_unicode(val)
    rc = re.compile(r'([^%c\\]|\\.)*' % c)
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
            res.append(v.strip())
    return res


def parse_dn(dnstr):
    """Parse openssl-style /-separated list to dict.
    """
    res = {}
    for part in loop_escaped(dnstr, '/'):
        if '=' not in part:
            die("Need k=v in Name string")
        k, v = part.split('=', 1)
        k = k.strip()
        if k in res:
            die("Double key: %s (%s)", k, dnstr)
        res[k] = v.strip()
    return res


def same_pubkey(o1, o2):
    """Compare public keys.
    """
    fmt = PublicFormat.SubjectPublicKeyInfo
    p1 = o1.public_key().public_bytes(Encoding.PEM, fmt)
    p2 = o2.public_key().public_bytes(Encoding.PEM, fmt)
    return p1 == p2


def die(msg, *args):
    """Print message and exit.
    """
    if args:
        msg = msg % args
    sys.stderr.write(msg + '\n')
    sys.exit(1)


def msg(msg, *args):
    """Print message to stderr.
    """
    if QUIET:
        return
    if args:
        msg = msg % args
    sys.stderr.write(msg + '\n')


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
    short = {'ec': 'ec:secp256r1', 'rsa': 'rsa:2048'}
    if len(args.files) > 1:
        die("Unexpected positional arguments")
    if args.files:
        keydesc = args.files[0]
    else:
        keydesc = 'ec'
    keydesc = short.get(keydesc, keydesc)

    # create key
    t, v = keydesc.lower().split(':')
    if t == 'ec':
        try:
            k = new_ec_key(v)
        except ValueError:
            die("Invalid curve: %s", v)
    elif t == 'rsa':
        try:
            k = new_rsa_key(int(v))
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
    """Collect command-line args
    """
    subject_info = CertInfo(
        subject=parse_dn(args.subject),
        usage=parse_list(args.usage),
        alt_names=parse_list(args.san),
        ocsp_nocheck=args.ocsp_nocheck,
        ocsp_urls=parse_list(args.ocsp_urls),
        crl_urls=parse_list(args.crl_urls),
        issuer_urls=parse_list(args.issuer_urls),
        permit_subtrees=parse_list(args.permit_subtrees),
        exclude_subtrees=parse_list(args.exclude_subtrees),
        ca=args.CA,
        path_length=args.path_length)
    return subject_info


def msg_show(ln):
    msg('  %s', ln)


def req_command(args):
    """Load args, create CSR.
    """
    if args.files:
        die("Unexpected positional arguments")

    subject_info = info_from_args(args)

    if subject_info.ca:
        msg('Request for CA cert')
    else:
        msg('Request for end-entity cert')
    subject_info.show(msg_show)

    # Load private key, create req
    key = load_key(args.key, load_password(args.password_file))
    req = create_x509_req(key, subject_info)
    do_output(req_to_pem(req), args, 'req')


def sign_command(args):
    """Load args, output cert.
    """
    if args.files:
        die("Unexpected positional arguments")

    # Certificate duration
    days = args.days
    if days is None:
        die("Need --days")
    if days <= 0:
        die("Invalid --days")

    # Load CA info
    if not args.ca_info:
        die("Need --ca-info")
    if args.ca_info.endswith('.csr'):
        issuer_obj = load_req(args.ca_info)
    else:
        issuer_obj = load_cert(args.ca_info)
    issuer_info = CertInfo(load=issuer_obj)

    # Load certificate request
    subject_csr = load_req(args.request)
    subject_info = CertInfo(load=subject_csr)

    # Check CA params
    if not same_pubkey(subject_csr, issuer_obj):
        if not issuer_info.ca:
            die("Issuer must be CA.")
        if 'key_cert_sign' not in issuer_info.usage:
            die("Issuer CA is not allowed to sign certs.")
    if subject_info.ca:
        if not same_pubkey(subject_csr, issuer_obj):
            # not selfsigning, check depth
            if issuer_info.path_length == 0:
                die("Issuer cannot sign sub-CAs")
            if issuer_info.path_length - 1 < args.path_length:
                die("--path-length not allowed by issuer")

    # Load subject's public key, check sanity
    pkey = subject_csr.public_key()
    if isinstance(pkey, ec.EllipticCurvePublicKey):
        pkeyinfo = 'ec:' + str(pkey.curve.name)
        if pkey.curve.name not in EC_CURVES:
            die("Curve not allowed: %s", pkey.curve.name)
    elif isinstance(pkey, rsa.RSAPublicKey):
        pkeyinfo = 'rsa:' + str(pkey.key_size)
        if pkey.key_size < MIN_RSA_BITS or pkey.key_size > MAX_RSA_BITS:
            die("RSA size not allowed: %s", pkey.key_size)
    else:
        die("Unsupported public key: %s", str(pkey))

    # Report
    if subject_info.ca:
        msg('Signing CA cert [%s] - %s', pkeyinfo, args.request)
    else:
        msg('Signing end-entity cert [%s] - %s', pkeyinfo, args.request)
    msg('Issuer name: %s', render_name(issuer_info.subject))
    msg('Subject:')
    subject_info.show(msg_show)

    # Load CA private key
    key = load_key(args.ca_key, load_password(args.password_file))
    if not same_pubkey(key, issuer_obj):
        die("--ca-private-key does not match --ca-info data")

    # Stamp request
    cert = create_x509_cert(key, subject_csr.public_key(), subject_info, issuer_info, days=args.days)
    do_output(cert_to_pem(cert), args, 'x509')


def show_command(args):
    """Dump .crt and .csr files.
    """
    for fn in args.files:
        ext = os.path.splitext(fn)[1].lower()
        if ext == '.csr':
            cmd = ['openssl', 'req', '-in', fn, '-text']
        elif ext == '.crt':
            cmd = ['openssl', 'x509', '-in', fn, '-text']
        else:
            die("Unsupported file: %s", fn)
        subprocess.check_call(cmd)


def setup_args():
    """Create ArgumentParser
    """
    p = argparse.ArgumentParser(description=__doc__.strip(), fromfile_prefix_chars='@',
                                usage="%(prog)s --help | --version\n" +
                                "       %(prog)s new-key [KEY_TYPE] [--password-file FN] [--out FN]\n" +
                                "       %(prog)s request --key KEY_FILE [--subject DN] [--san ALT] [...]\n" +
                                "       %(prog)s sign --request FN --ca-key FN --ca-info FN --days N [...]\n" +
                                "       %(prog)s show FILE")
    p.add_argument('--version', help='show version and exit', action='version',
                   version='%(prog)s ' + __version__)
    p.add_argument('--password-file', help='File to load password from', metavar='FN')
    p.add_argument('--text', help='Add human-readable text about output', action='store_true')
    p.add_argument('--out', help='File to write output to, instead stdout', metavar='FN')
    p.add_argument('--quiet', '-q', help='Be quiet', action='store_true')
    p.add_argument('command', help=argparse.SUPPRESS)

    p.add_argument_group('Command "new-key"',
                         "Generate new EC or RSA key.  Key type can be either ec:<curve> "
                         "or rsa:<bits>.  Default: ec:secp256r1.")

    g2 = p.add_argument_group('Command "request"',
                              "Create certificate request for private key")
    g2.add_argument('--key', help='Private key file', metavar='FN')

    g2 = p.add_argument_group("Certificate fields")
    g2.add_argument('--subject', help='Subject Distinguished Name - /CN=foo/O=Org/OU=Web/')
    g2.add_argument('--san',
                    help='SubjectAltNames - dns:hostname, email:addrspec, ip:ipaddr, uri:url, dn:DirName.',
                    metavar='GNAMES')
    g2.add_argument('--CA', help='Request CA cert.  Default: not set.', action='store_true')
    g2.add_argument('--path-length',
                    help='Max levels of sub-CAs.  Default: 0',
                    type=int, default=0, metavar='DEPTH')
    g2.add_argument('--usage', help='Keywords: client, server, code, email, time, ocsp.')
    g2.add_argument('--ocsp-urls', help='URLs for OCSP info.', metavar='URLS')
    g2.add_argument('--ocsp-nocheck', help='Disable OCSP check.', action='store_true')
    g2.add_argument('--crl-urls', help='URLs URL for CRL data.', metavar='URLS')
    g2.add_argument('--issuer-urls', help='URLs for issuer cert.', metavar='URLS')
    g2.add_argument('--permit-subtrees', help='Allowed NameConstraints.', metavar='GNAMES')
    g2.add_argument('--exclude-subtrees', help='Disallowed NameConstraints.', metavar='GNAMES')

    g3 = p.add_argument_group('Command "sign"',
                              "Create certificate for key in certificate request.  "
                              "All metadata is taken from certificate request file.")
    g3.add_argument('--ca-key', help='Private key file.', metavar='FN')
    g3.add_argument('--ca-info', help='Filename of CA details (CRT or CSR).', metavar='FN')
    g3.add_argument('--request', help='Filename of certificate request (CSR) to be signed.', metavar='FN')
    g3.add_argument('--days', help='Certificate lifetime in days', type=int)

    g4 = p.add_argument_group('Command "show"',
                              "Show CSR or CRT file contents.  Takes .crt or .csr filenames as arguments.")
    g4.add_argument('files', help=argparse.SUPPRESS, nargs='*')

    return p


def run_sysca(argv):
    """Parse args, run command.
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
    elif args.command == 'show':
        show_command(args)
    else:
        die("Unknown command: %s", args.command)


def main():
    """Command-line application entry point.
    """
    return run_sysca(sys.argv[1:])


if __name__ == '__main__':
    main()

