"""String <> Python objects.
"""

import re
import binascii
from datetime import datetime, timedelta

from .exceptions import InvalidCertificate

__all__ = (
    "as_bytes", "as_unicode", "as_password",
    "maybe_parse_str", "maybe_parse",
    "parse_dn", "parse_list", "parse_number", "parse_timestamp",
    "parse_time_period",
    "render_name", "render_serial",
    "show_list", "to_hex", "to_issuer_gnames",
)


def as_bytes(s):
    """Return byte-string.
    """
    if not isinstance(s, bytes):
        return s.encode("utf8")
    return s


def as_unicode(s, errs="strict"):
    """Return unicode-string.
    """
    if not isinstance(s, bytes):
        return s
    return s.decode("utf8", errs)


def as_password(password):
    if not password:
        return None
    if not isinstance(password, (bytes, bytearray, memoryview)):
        password = password.encode("utf8")
    return password


def render_serial(snum):
    """Format certificate serial number as string.
    """
    s = "%x" % snum
    s = "0" * (len(s) & 1) + s
    s = re.sub(r"..", r":\g<0>", s).strip(":")
    return s


def parse_number(sval):
    """Parse number from command line.
    """
    if re.match(r"^[0-9a-f]+(:[0-9a-f]+)+$", sval, re.I):
        val = int(sval.replace(":", ""), 16)
    elif re.match(r"^[0-9a-f]+(-[0-9a-f]+)+$", sval, re.I):
        val = int(sval.replace("-", ""), 16)
    elif re.match(r"^[0-9]+$", sval):
        val = int(sval, 10)
    else:
        raise ValueError("Invalid number: %r" % sval)
    return val


def parse_timestamp(sval):
    """Parse date from command line.
    """
    if hasattr(datetime, "fromisoformat"):
        return datetime.fromisoformat(sval)
    if re.match(r"^\d\d\d\d-\d\d-\d\d$", sval):
        return datetime.strptime(sval, "%Y-%m-%d")
    if re.match(r"^\d\d\d\d-\d\d-\d\d \d\d:\d\d$", sval):
        return datetime.strptime(sval, "%Y-%m-%d %H:%M")
    if re.match(r"^\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d$", sval):
        return datetime.strptime(sval, "%Y-%m-%d %H:%M:%S")
    raise ValueError("Invalid timestamp: %r" % sval)


def _escape_char(m):
    """Backslash-escape.
    """
    c = m.group(0)
    if c in (",", "\\", "/"):
        return "\\" + c
    return "\\x%02x" % ord(c)


def dn_escape(s, sep="/"):
    """DistinguishedName backslash-escape"""
    return re.sub(r"[\\%c\x00-\x1F]" % sep, _escape_char, s)


def list_escape(s):
    """Escape value for comma-separated list
    """
    return re.sub(r"[\\,]", _escape_char, s)


def show_list(desc, lst, writeln):
    """Print out list field.
    """
    if not lst:
        return
    if len(lst) == 1:
        writeln("%s: %s" % (desc, lst[0]))
    else:
        writeln("%s:" % desc)
        for val in lst:
            writeln("  %s" % (val,))


def to_hex(data):
    """Converts bytes to hex if not None
    """
    if data is None:
        return None
    if not isinstance(data, bytes):
        raise TypeError("Expect bytes")
    return binascii.b2a_hex(data).decode("ascii")


def _unescape_char(m):
    """Unescape helper
    """
    xmap = {",": ",", "/": "/", "\\": "\\", "t": "\t"}
    c = m.group(1)
    if len(c) > 1:
        if c[0] == "x":
            return chr(int(c[1:], 16))
    return xmap[c]


def unescape(s):
    """Remove backslash escapes.
    """
    return re.sub(r"\\(x[0-9a-fA-F][0-9a-fA-F]|.)", _unescape_char, s)


def render_name(name_att_list, sep="/"):
    """Convert DistinguishedName dict to "/"-separated string.
    """
    res = [""]
    for k, v in name_att_list:
        v = dn_escape(v, sep)
        res.append("%s=%s" % (k, v))
    res.append("")
    return sep.join(res)


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


def maybe_parse_str(val, parse_func, vtype):
    """Parse argument value with function if string.
    """
    if val is None:
        return None
    if isinstance(val, str):
        val = parse_func(val)
    if not isinstance(val, vtype):
        raise TypeError("expect %s for %s" % (vtype, type(val)))
    return val


def loop_escaped(val, c):
    """Parse list of strings, separated by c.
    """
    if not val:
        val = ""
    val = as_unicode(val)
    rc = re.compile(r"([^%s\\]|\\.)*" % re.escape(c))
    pos = 0
    while pos < len(val):
        if val[pos] == c:
            pos += 1
            continue
        m = rc.match(val, pos)
        if not m:
            raise Exception("rx bug")
        pos = m.end()
        yield unescape(m.group(0))


def parse_list(slist):
    """Parse comma-separated list to strings.
    """
    res = []
    for v in loop_escaped(slist, ","):
        v = v.strip()
        if v:
            res.append(v)
    return res


def parse_dn(dnstr, sep="/"):
    """Parse openssl-style /-separated list to dict.
    """
    res = []
    for part in loop_escaped(dnstr, sep):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise InvalidCertificate("Need k=v in Name string")
        k, v = part.split("=", 1)
        res.append((k.strip(), v.strip()))
    return tuple(res)


def to_issuer_gnames(subject, san):
    """Issuer GeneralNames for CRL usage.
    """
    gnames = []
    if subject:
        gnames.append("dn:" + render_name(subject))
    if san:
        gnames.extend(san)
    return gnames


def parse_time_period(days=None, not_valid_before=None, not_valid_after=None, gap=1):
    """Calculate time range
    """
    days = maybe_parse_str(days, parse_number, int)
    not_valid_before = maybe_parse_str(not_valid_before, parse_timestamp, datetime)
    not_valid_after = maybe_parse_str(not_valid_after, parse_timestamp, datetime)
    dt_now = datetime.utcnow()
    if not_valid_before is None:
        not_valid_before = dt_now - timedelta(hours=gap)
    if not_valid_after is None:
        if days is None:
            raise ValueError("need days")
        not_valid_after = dt_now + timedelta(days=days)
    if not_valid_before > not_valid_after:
        raise ValueError("negative time range")
    return not_valid_before, not_valid_after
