"""Command-line UI for SysCA.
"""

import argparse
import os.path
import subprocess
import sys
from datetime import datetime

from cryptography import x509

from .api import (
    CRL_REASON, DN_CODE_TO_OID, FULL_VERSION, PRIVKEY_CLASSES, PUBKEY_CLASSES,
    CertInfo, CRLInfo, as_bytes, autogen_config_file, create_x509_cert,
    create_x509_crl, create_x509_req, get_ec_curves, get_key_name, load_cert,
    load_crl, load_file_any, load_key, load_password, load_req, new_key,
    parse_dn, parse_list, parse_number, render_name, render_serial,
    same_pubkey, serialize, set_unsafe, to_issuer_gnames,
)

__all__ = ("main", "run_sysca")

QUIET = False

#
# Command-line UI
#


def die(txt, *args):
    """Print message and exit.
    """
    if args:
        txt = txt % args
    sys.stderr.write(txt + "\n")
    sys.exit(1)


def msg(txt, *args):
    """Print message to stderr.
    """
    if QUIET:
        return
    if args:
        txt = txt % args
    sys.stderr.write(txt + "\n")


def do_output(obj, args, password=None):
    """Output X509 structure
    """
    data = serialize(obj, args.outform.lower(), password=password)
    if args.text:
        if args.outform.lower() != "pem":
            die("Need --outform=pem for --text to work")
        extra_args = []
        if isinstance(obj, x509.Certificate):
            cmd = "x509"
        elif isinstance(obj, x509.CertificateRevocationList):
            cmd = "crl"
        elif isinstance(obj, x509.CertificateSigningRequest):
            cmd = "req"
        elif isinstance(obj, PUBKEY_CLASSES):
            cmd = "pkey"
            extra_args = ["-pubin"]
        elif isinstance(obj, PRIVKEY_CLASSES):
            cmd = "pkey"
        run_openssl(cmd, None, args.out, as_bytes(data), extra_args)
    elif args.out:
        with open(args.out, "wb") as f:
            f.write(as_bytes(data))
    elif isinstance(data, str):
        sys.stdout.write(data)
        sys.stdout.flush()
    elif sys.stdout.isatty():
        die("Will not write binary output to console")
    else:
        with os.fdopen(sys.stdout.fileno(), "wb") as f:
            f.write(data)


def run_openssl(cmd, srcfn, outfn=None, data=b"", extra_args=None):
    cmdline = ["openssl", cmd, "-text"]
    if srcfn:
        cmdline.extend(["-in", srcfn])
    if outfn:
        cmdline.extend(["-out", outfn])
    if extra_args:
        cmdline.extend(extra_args)
    with subprocess.Popen(
            cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.PIPE) as p:
        out, err = p.communicate(data)
    out = out.decode("utf8", "replace")
    err = err.decode("utf8", "replace")
    if p.returncode == 0:
        sys.stdout.write(out)
    else:
        sys.stderr.write(err)
        sys.stdout.write(out)
        sys.exit(1)


def newkey_command(args):
    """Create new key.
    """
    keydesc = args.keytype or "ec"
    k = new_key(keydesc)
    msg("New key: %s", keydesc)

    # Output with optional encryption
    psw = load_password(args.password_file)
    do_output(k, args, password=psw)


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
        certificate_policies=args.add_policy,
        inhibit_any=args.inhibit_any,
        require_explicit_policy=args.require_explicit_policy,
        inhibit_policy_mapping=args.inhibit_policy_mapping,
        path_length=args.path_length)


def msg_show(ln):
    """Show indented line.
    """
    msg("  %s", ln)


def do_sign(subject_csr, issuer_obj, issuer_key, days, path_length, reqInfo,
            reset_info=None, not_valid_before=None, not_valid_after=None,
            serial_number=None):
    """Sign with already loaded parameters.
    """
    # Certificate duration
    if days is None and not_valid_after is None:
        die("Need --days")

    # Load CA info
    issuer_info = CertInfo(load=issuer_obj)

    # Load certificate request
    subject_info = CertInfo(load=subject_csr)
    if reset_info:
        subject_info = reset_info

    # Report
    pkey = subject_csr.public_key()
    if subject_info.ca:
        msg("Signing CA cert [%s] - %s", get_key_name(pkey), reqInfo)
    else:
        msg("Signing end-entity cert [%s] - %s", get_key_name(pkey), reqInfo)
    msg("Issuer name: %s", render_name(issuer_info.subject))
    msg("Subject:")
    subject_info.show(msg_show)

    # Stamp request
    cert = create_x509_cert(issuer_privkey=issuer_key,
                            subject_pubkey=subject_csr.public_key(),
                            subject_info=subject_info, issuer_info=issuer_info,
                            days=days, serial_number=serial_number,
                            not_valid_before=not_valid_before,
                            not_valid_after=not_valid_after)
    msg("Serial: %s", render_serial(cert.serial_number))
    msg("Not Valid Before: %s", cert.not_valid_before.isoformat(" "))
    msg("Not Valid After: %s", cert.not_valid_after.isoformat(" "))
    return cert


def req_command(args):
    """Load command-line arguments, create Certificate Signing Request (CSR).
    """
    subject_info = info_from_args(args)

    if subject_info.ca:
        msg("Request for CA cert")
    else:
        msg("Request for end-entity cert")
    subject_info.show(msg_show)

    # Load private key, create signing request
    key = load_key(args.key, load_password(args.password_file))
    req = create_x509_req(key, subject_info)
    do_output(req, args)


def sign_command(args):
    """Load command-line arguments, output cert.
    """
    # Load certificate request
    subject_csr = load_req(args.request)

    reset_info = None
    if args.reset:
        reset_info = info_from_args(args)

    # Load CA info
    if args.ca_info.endswith(".csr"):
        issuer_obj = load_req(args.ca_info)
    else:
        issuer_obj = load_cert(args.ca_info)

    # Load CA private key
    issuer_key = load_key(args.ca_key, load_password(args.password_file))
    if not same_pubkey(issuer_key, issuer_obj):
        die("--ca-key does not match --ca-info data")

    # Certificate generation
    cert = do_sign(subject_csr=subject_csr, issuer_obj=issuer_obj, issuer_key=issuer_key,
                   path_length=args.path_length, reqInfo=args.request,
                   not_valid_before=args.not_valid_before,
                   not_valid_after=args.not_valid_after,
                   serial_number=args.serial_number,
                   days=args.days, reset_info=reset_info)

    # Write certificate
    do_output(cert, args)


def selfsign_command(args):
    """Load command-line arguments, create self-signed CRT.
    """
    subject_info = info_from_args(args)

    if subject_info.ca:
        msg("Selfsigning CA cert")
    else:
        msg("Selfsigning end-entity cert")
    subject_info.show(msg_show)

    # Load private key, create signing request
    key = load_key(args.key, load_password(args.password_file))
    subject_csr = create_x509_req(key, subject_info)

    # sign created request
    cert = do_sign(subject_csr, subject_csr, key, path_length=args.path_length,
                   days=args.days, reqInfo=args.key,
                   not_valid_before=args.not_valid_before, not_valid_after=args.not_valid_after)
    do_output(cert, args)


def update_crl_command(args):
    """Load command-line arguments, output new CRL.
    """
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
        crl_info.crl_number = parse_number(args.crl_number)
    if args.delta_crl_number:
        crl_info.delta_crl_number = parse_number(args.delta_crl_number)
    if args.indirect_crl:
        crl_info.indirect_crl = True
    if args.crl_reasons:
        crl_info.only_some_reasons = set(parse_list(args.crl_reasons))

    invalidity_date = args.invalidity_date
    revocation_date = args.revocation_date
    if not revocation_date:
        # use same value for all new records
        revocation_date = datetime.utcnow()

    if args.issuer_urls:
        crl_info.issuer_urls = parse_list(args.issuer_urls)

    if args.delta_crl_urls:
        crl_info.delta_crl_urls = parse_list(args.delta_crl_urls)

    for crt_fn in (args.revoke_certs or []):
        cert_obj = load_cert(crt_fn)
        crl_info.add_certificate(cert_obj, reason=args.reason, invalidity_date=invalidity_date,
                                 revocation_date=revocation_date)

    for crt_serial in (args.revoke_serials or []):
        crl_info.add_serial_number(crt_serial, reason=args.reason, invalidity_date=invalidity_date,
                                   revocation_date=revocation_date,
                                   issuer_gnames=to_issuer_gnames(issuer_info.subject, issuer_info.san))

    res = create_x509_crl(issuer_key, issuer_info, crl_info, days=args.days,
                          last_update=args.last_update, next_update=args.next_update)
    do_output(res, args)


def show_command_sysca(args):
    """Dump .crt and .csr files.
    """
    def simple_write(ln):
        sys.stdout.write(ln + "\n")
    psw = load_password(args.password_file)
    for fn in args.file:
        obj = load_file_any(fn, password=psw)
        try:
            if isinstance(obj, (x509.Certificate, x509.CertificateSigningRequest)):
                CertInfo(load=obj).show(simple_write)
            elif isinstance(obj, x509.CertificateRevocationList):
                CRLInfo(load=obj).show(simple_write)
            elif isinstance(obj, PUBKEY_CLASSES):
                sys.stdout.write(serialize(obj))
            elif isinstance(obj, PRIVKEY_CLASSES):
                sys.stdout.write(serialize(obj, password=psw))
            else:
                die("bad format")
        except TypeError as ex:
            die("ERROR: %s: %s", fn, str(ex))


def show_command_openssl(args):
    """Dump .crt and .csr files via openssl tool.
    """
    for fn in args.file:
        ext = os.path.splitext(fn)[1].lower()
        if ext == ".csr":
            run_openssl("req", fn)
        elif ext == ".crt":
            run_openssl("x509", fn)
        elif ext == ".crl":
            run_openssl("crl", fn)
        else:
            die("Unsupported file: %s", fn)


def show_command(args):
    """Dump using either internal code or openssl tool.
    """
    if args.text:
        show_command_openssl(args)
    else:
        show_command_sysca(args)


def export_command(args):
    """Rewrite data.
    """
    psw = load_password(args.password_file)
    obj = load_file_any(args.file, password=psw)
    if isinstance(obj, PRIVKEY_CLASSES):
        do_output(obj, args, psw)
    else:
        do_output(obj, args)


def export_pub_command(args):
    """Dump public key.
    """
    psw = load_password(args.password_file)
    obj = load_file_any(args.file, password=psw)
    if isinstance(obj, PUBKEY_CLASSES):
        do_output(obj, args)
    elif hasattr(obj, "public_key"):
        do_output(obj.public_key(), args)
    else:
        die("no public key")


def list_name_fields():
    oids = {}
    for k, v in DN_CODE_TO_OID.items():
        oids.setdefault(v, []).append(k)
    lines = []
    for names in oids.values():
        if len(names) == 1:
            lines.append("\t" + names[0])
        else:
            lines.append("\t".join(sorted(names)))
    lines.sort(key=lambda ln: ln.strip())
    print("%s" % "\n".join(lines))


def list_command(args):
    if args.what == "ec-curves":
        print("%s" % "\n".join(get_ec_curves()))
    elif args.what == "name-fields":
        list_name_fields()


def safe_write(fn, data):
    with open(fn, "wb", buffering=0) as f:
        f.write(data)


def autogen_command(args):
    def load_ca_keypair(ca_name):
        matches = []
        pfx = ca_name + '_'
        for fn in sorted(os.listdir(args.ca_dir)):
            if not fn.startswith(pfx):
                continue
            keyfn = os.path.join(args.ca_dir, fn)
            if fn.endswith('.key.gpg'):
                certfn = keyfn[:-8] + '.crt'
            elif fn.endswith('.key'):
                certfn = keyfn[:-4] + '.crt'
            else:
                continue
            matches.append((keyfn, certfn))
        return matches[0]

    class CertArgs:
        out = None
        outform = args.outform
        text = args.text
    cert_args = CertArgs()

    class KeyArgs:
        out = None
        outform = 'pem'
        text = False
    key_args = KeyArgs()

    defs = {}
    for fn in args.file:
        msg("Processing %s", fn)
        res = autogen_config_file(fn, load_ca_keypair, defs)
        for basefn, vals in res.items():
            key_obj = vals[0]
            cert_obj = vals[1]
            if args.out_dir:
                basefn = os.path.join(args.out_dir, basefn)
            key_args.out = basefn + ".key"
            cert_args.out = basefn + ".crt"

            do_output(key_obj, key_args)
            do_output(cert_obj, cert_args)
            msg("  %s", key_args.out)

#
# argparse setup
#


def opts_password(p):
    p.add_argument("--password-file", metavar="FN", help="File to load password from")


def opts_text(p):
    p.add_argument("--text", action="store_true", help="Add human-readable text about output")


def opts_unsafe(p):
    p.add_argument("--unsafe", action="store_true", help="Allow unsafe parameters")


def opts_output(p):
    p.add_argument("--out", metavar="FN",
                   help="File to write output to, instead stdout")
    p.add_argument("--outform", default="PEM",
                   help="Select output format: PEM|DER.  Default: PEM")


def opts_reset(p):
    p.add_argument("--reset", action="store_true",
                   help="Rewrite all info fields.  Default: no.")


def opts_request(p):
    p.add_argument("--request", metavar="FN", required=True,
                   help="Filename of certificate request (CSR) to be signed.")


def opts_key(p):
    p.add_argument("--key", metavar="FN", required=True, help="Private key file")


def opts_ca_key(p):
    p.add_argument("--ca-key", metavar="FN", required=True,
                   help="Private key file.")
    p.add_argument("--ca-info", metavar="FN", required=True,
                   help="Filename of CA details (CRT or CSR).")


def opts_signing(p):
    p.add_argument("--days", type=int,
                   help="Certificate lifetime in days from now")
    p.add_argument("--not-valid-before",
                   help="Timestamp of validity period start")
    p.add_argument("--not-valid-after",
                   help="Timestamp of validity period end")
    p.add_argument("--serial-number", metavar="SN",
                   help="Disable automatic serial number generation.")


def opts_cert_fields(p):
    p.add_argument("--subject",
                   help="Subject Distinguished Name - /CN=foo/O=Org/OU=Web/")
    p.add_argument("--san", metavar="GNAMES",
                   help="SubjectAltNames - dns:hostname, email:addrspec, ip:ipaddr, uri:url, dn:DirName.")
    p.add_argument("--CA", action="store_true",
                   help="Request CA cert.  Default: not set.")
    p.add_argument("--path-length", type=int, default=None, metavar="DEPTH",
                   help="Max levels of sub-CAs.  Default: 0")
    p.add_argument("--usage",
                   help="Keywords: client, server, code, email, time, ocsp.")
    p.add_argument("--ocsp-urls", metavar="URLS",
                   help="URLs for OCSP info.")
    p.add_argument("--ocsp-nocheck", action="store_true",
                   help="Disable OCSP check.")
    p.add_argument("--ocsp-must-staple", action="store_true",
                   help="OCSP Must-Staple.")
    p.add_argument("--ocsp-must-staple-v2", action="store_true",
                   help="OCSP Must-Staple V2.")
    p.add_argument("--crl-urls", metavar="URLS",
                   help="URLs URL for CRL data.")
    p.add_argument("--issuer-urls", metavar="URLS",
                   help="URLs for issuer cert.")
    p.add_argument("--permit-subtrees", metavar="GNAMES",
                   help="Allowed NameConstraints.")
    p.add_argument("--exclude-subtrees", metavar="GNAMES",
                   help="Disallowed NameConstraints.")
    p.add_argument("--inhibit-any", metavar="N", type=int,
                   help="Number of levels after which <anyPolicy> policy is ignored.")
    p.add_argument("--require-explicit-policy", metavar="N", type=int,
                   help="Number of levels after which certificate policy is required.")
    p.add_argument("--inhibit-policy-mapping", metavar="N", type=int,
                   help="Number of levels after which policy mapping is disallowed.")
    p.add_argument("--add-policy", metavar="POLICY", type=str, action="append",
                   help="Add policy.  Value is OID:/T=qualifier1/,/T=qualifier2/")


def opts_crl(p):
    p.add_argument("--crl", metavar="FN",
                   help="Filename of certificate revocation list (CRL) to be updated.")
    p.add_argument("--crl-number", metavar="VER",
                   help="Version number for main CRL")
    p.add_argument("--delta-crl-number", metavar="VER",
                   help="Version number for parent CRL")
    p.add_argument("--revoke-certs", metavar="FN", nargs="+",
                   help="Certificate files to add")
    p.add_argument("--revoke-serials", metavar="NUM", nargs="+",
                   help="Certificate serial numbers to add")
    p.add_argument("--reason",
                   help="Reason for revocation: %s" % ", ".join(CRL_REASON.keys()))
    p.add_argument("--invalidity-date", metavar="DATE",
                   help="Consider certificate invalid from date")
    p.add_argument("--revocation-date", metavar="DATE",
                   help="Disable default timestamp")
    p.add_argument("--crl-scope", metavar="SCOPE",
                   help="Score for types of certificates in CRL, one of: all, user, ca, attr.  Default: all")
    p.add_argument("--crl-reasons", metavar="REASONS",
                   help="Limit CRL scope to only list of reasons")
    p.add_argument("--issuer-urls", metavar="URLS",  # DBL
                   help="URLs for issuer cert.")
    p.add_argument("--delta-crl-urls", metavar="URLS",
                   help="Delta CRL URLs")
    p.add_argument("--indirect-crl", action="store_true",
                   help="Set Indirect-CRL flag")
    p.add_argument("--last-update", metavar="DATE",
                   help="Set last_update explicitly instead using current timestamp.")
    p.add_argument("--next-update", metavar="DATE",
                   help="Set next_update explicitly instead using --days.")
    p.add_argument("--days", type=int,  # DBL
                   help="CRL lifetime in days from now")


def opts_top(p):
    p.add_argument("-V", "--version", action="version", version="%(prog)s " + FULL_VERSION,
                   help="Show version and exit")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Be quiet")


def opts_file(p):
    p.add_argument("file", help="A file to be read and exported")


def opts_files(p):
    p.add_argument("file", help="File(s) to show", nargs="+")

#
# collect per-command switches
#


def loadhelp(func):
    """Convert docstring to add_parser() args
    """
    doc = func.__doc__.strip()
    return {"help": doc, "description": doc}


def setup_args_newkey(sub):
    """Generate new EC, RSA or DSA key.
    """
    p = sub.add_parser("new-key", **loadhelp(setup_args_newkey))
    p.set_defaults(command=newkey_command)

    p.add_argument("keytype", nargs="?", help="Key type can be either "
                   "ec:<curve>, rsa:<bits> or dsa:<bits>.  Default: ec:secp256r1.")
    g = p.add_argument_group("Output")
    opts_password(g)
    opts_output(g)
    opts_text(g)


def setup_args_request(sub):
    """Create certificate signing request (CSR)
    """
    p = sub.add_parser("request", **loadhelp(setup_args_request))
    p.set_defaults(command=req_command)

    g = p.add_argument_group("Input key")
    opts_key(g)
    opts_password(g)

    g = p.add_argument_group("Output")
    opts_output(g)
    opts_text(g)

    g = p.add_argument_group("Certificate fields")
    opts_cert_fields(g)


def setup_args_sign(sub):
    """Create certificate (CRT) based on existing request
    """
    p = sub.add_parser("sign", **loadhelp(setup_args_sign))
    p.set_defaults(command=sign_command)

    g = p.add_argument_group("Output")
    opts_output(g)
    opts_text(g)

    g = p.add_argument_group("Signing")
    opts_request(g)
    opts_ca_key(g)
    opts_password(g)
    opts_signing(g)
    opts_reset(g)

    g = p.add_argument_group("Certificate fields")
    opts_cert_fields(g)


def setup_args_selfsign(sub):
    """Create certificate by selfsigning with input key
    """
    p = sub.add_parser("selfsign", **loadhelp(setup_args_selfsign))
    p.set_defaults(command=selfsign_command)

    g = p.add_argument_group("Output")
    opts_output(g)
    opts_text(g)

    g = p.add_argument_group("Signing")
    opts_key(g)
    opts_password(g)
    opts_signing(g)

    g = p.add_argument_group("Certificate fields")
    opts_cert_fields(g)


def setup_args_update_crl(sub):
    """Create or update Certificate Revocation List (CRL)
    """
    p = sub.add_parser("update-crl", **loadhelp(setup_args_update_crl))
    p.set_defaults(command=update_crl_command)

    g = p.add_argument_group("Output")
    opts_output(g)
    opts_text(g)

    g = p.add_argument_group("Signing")
    opts_ca_key(g)
    opts_password(g)

    g = p.add_argument_group("CRL fields")
    opts_crl(g)


def setup_args_export(sub):
    """Reformat file
    """
    p = sub.add_parser("export", **loadhelp(setup_args_export))
    p.set_defaults(command=export_command)

    g = p.add_argument_group("Output")
    opts_output(g)
    opts_text(g)

    opts_file(p)
    opts_password(p)


def setup_args_export_pub(sub):
    """Extract public key from certificate or certificate request
    """
    p = sub.add_parser("export-pub", **loadhelp(setup_args_export_pub))
    p.set_defaults(command=export_pub_command)

    g = p.add_argument_group("Output")
    opts_output(g)
    opts_text(g)

    opts_file(p)
    opts_password(p)


def setup_args_show(sub):
    """Show file contents in readable form.
    """
    p = sub.add_parser("show", **loadhelp(setup_args_show))
    p.set_defaults(command=show_command)

    opts_text(p)

    opts_files(p)
    opts_password(p)


def setup_args_list(sub):
    """Show available parameters
    """
    whats = ("ec-curves", "name-fields")
    p = sub.add_parser("list", **loadhelp(setup_args_list))
    p.add_argument("what", help="What parameter to show", choices=whats)
    p.set_defaults(command=list_command)


def setup_args_autogen(sub):
    """Generate key and certificate.
    """
    p = sub.add_parser("autogen", **loadhelp(setup_args_autogen))
    p.set_defaults(command=autogen_command)

    g = p.add_argument_group("Signing")
    g.add_argument("--ca-dir", required=True,
                   help="Select output format: PEM|DER.  Default: PEM")
    opts_password(g)

    g = p.add_argument_group("Output")
    g.add_argument("--out-dir", metavar="OUTDIR",
                   help="File to write output to, instead stdout")
    g.add_argument("--outform", default="PEM",
                   help="Select output format: PEM|DER.  Default: PEM")
    opts_text(g)

    p.add_argument("file", help="Config file(s) to process", nargs="+")


#
# top-level parser
#


def setup_args():
    """Create ArgumentParser
    """
    topargs = {}
    topargs["allow_abbrev"] = False
    topargs["fromfile_prefix_chars"] = "@"
    topargs["prog"] = "sysca"
    topargs["description"] = "Run any COMMAND with --help switch to get command-specific help."

    top = argparse.ArgumentParser(**topargs)
    opts_top(top)
    opts_unsafe(top)

    sub = top.add_subparsers(metavar="COMMAND")
    setup_args_newkey(sub)
    setup_args_request(sub)
    setup_args_sign(sub)
    setup_args_selfsign(sub)
    setup_args_update_crl(sub)
    setup_args_show(sub)
    setup_args_export(sub)
    setup_args_export_pub(sub)
    setup_args_list(sub)
    setup_args_autogen(sub)
    return top


def run_sysca(argv):
    """Load arguments, select and run command.
    """
    global QUIET

    args = setup_args().parse_args(argv)
    if not hasattr(args, "command"):
        die("Need command")

    QUIET = bool(args.quiet)
    set_unsafe(bool(args.unsafe))

    args.command(args)


def main():
    """Command-line application entry point.
    """
    try:
        return run_sysca(sys.argv[1:])
    except (BrokenPipeError, KeyboardInterrupt):
        sys.exit(1)


if __name__ == "__main__":
    main()

