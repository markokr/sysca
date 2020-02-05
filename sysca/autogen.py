"""Generate key and issue certificate based on config file.
"""

from configparser import ConfigParser, ExtendedInterpolation

from .certinfo import CertInfo, create_x509_cert
from .files import load_cert, load_key
from .keys import new_key

__all__ = ['autogen_config_file', 'autogen_config']


def autogen_config_file(fn, load_ca, defs):
    r"""process certs defined in config
    """
    cf = ConfigParser(defaults=defs, interpolation=ExtendedInterpolation(),
                      delimiters=['='], comment_prefixes=['#'], inline_comment_prefixes=['#'])
    with open(fn, "r") as f:
        cf.read_file(f, fn)
    return autogen_config(cf, load_ca)


def autogen_config(cf, load_ca):
    r"""process already loaded config
    """
    res = {}
    for kname in cf.sections():
        sect = dict(cf.items(kname))

        days = int(sect.get('days', '730'))
        ktype = sect.get('ktype', 'ec')
        alt_names = sect.get('alt_names')

        subject = sect.get('subject')
        if not subject:
            subject = {}
            common_name = sect.get('common_name')
            if not common_name:
                common_name = kname
            common_name = common_name.rstrip('.')
            subject['CN'] = common_name

            if not alt_names:
                if '.' in common_name:
                    if '@' not in common_name:
                        alt_names = ['dns:' + common_name]

        ca_name = sect['ca_name']
        ca_key_fn, ca_cert_fn = load_ca(ca_name)
        ca_key = load_key(ca_key_fn)
        ca_cert = load_cert(ca_cert_fn)

        usage = sect.get('usage')
        if not usage:
            usage = ['client']

        key = new_key(ktype)
        inf = CertInfo(subject=subject, usage=usage, alt_names=alt_names)
        cert = create_x509_cert(ca_key, key.public_key(), inf, ca_cert, days)

        res[kname] = (key, cert, sect)
    return res

