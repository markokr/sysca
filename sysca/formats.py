"""String <> Python objects.
"""

import binascii
import re
from datetime import datetime, timedelta
from typing import (
    Callable, Dict, Iterable, List, Match, Optional, Sequence, Union,
)

__all__ = (
    "as_bytes", "as_password",
    "maybe_parse_str", "maybe_parse",
    "parse_dn", "parse_list", "parse_number", "parse_timestamp",
    "parse_time_period",
    "render_name", "render_serial",
    "show_list", "to_hex", "to_issuer_gnames",
)


def as_bytes(s: Union[str, bytes]) -> bytes:
    """Return byte-string.
    """
    if not isinstance(s, bytes):
        return s.encode("utf8")
    return s


def as_password(password: Optional[Union[str, bytes]]) -> Optional[bytes]:
    if not password:
        return None
    if not isinstance(password, (bytes, bytearray, memoryview)):
        password = password.encode("utf8")
    return password


def render_serial(snum: int) -> str:
    """Format certificate serial number as string.
    """
    s = "%x" % snum
    s = "0" * (len(s) & 1) + s
    s = re.sub(r"..", r":\g<0>", s).strip(":")
    return s


def parse_number(sval: str) -> int:
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


def parse_timestamp(sval: str) -> datetime:
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


def _escape_char(m: Match[str]) -> str:
    """Backslash-escape.
    """
    c = m.group(0)
    if c in (",", "\\", "/"):
        return "\\" + c
    return "\\x%02x" % ord(c)


def list_escape(s: str) -> str:
    """Escape value for comma-separated list
    """
    return re.sub(r"[\\,]", _escape_char, s)


def show_list(desc: str, lst: List[str], writeln: Callable[[str], None]) -> None:
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


def to_hex(data: Optional[bytes]) -> Optional[str]:
    """Converts bytes to hex if not None
    """
    if data is None:
        return None
    if not isinstance(data, bytes):
        raise TypeError("Expect bytes")
    return binascii.b2a_hex(data).decode("ascii")


def _unescape_char(m: Match[str]) -> str:
    """Unescape helper
    """
    xmap = {",": ",", "/": "/", "\\": "\\", "t": "\t"}
    c = m.group(1)
    if len(c) > 1:
        if c[0] == "x":
            return chr(int(c[1:], 16))
    return xmap[c]


def unescape(s: str) -> str:
    """Remove backslash escapes.
    """
    return re.sub(r"\\(x[0-9a-fA-F][0-9a-fA-F]|.)", _unescape_char, s)


def render_name(name_att_list: Iterable[Sequence[str]], sep: str = ",") -> str:
    """Convert DistinguishedName dict to "," or "/"-separated string.
    """
    return ldap_to_string(name_att_list, sep)


def maybe_parse(val: Optional[Union[str, bytes, Dict[str, str], Sequence[str]]], parse_func):
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


def loop_escaped(val: str, c: str) -> Iterable[str]:
    """Parse list of strings, separated by c.
    """
    if not val:
        val = ""
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


def parse_list(slist: str) -> List[str]:
    """Parse comma-separated list to strings.
    """
    res = []
    for v in loop_escaped(slist, ","):
        v = v.strip()
        if v:
            res.append(v)
    return res


def parse_dn(dnstr: str):
    """Parse openssl-style /-separated list to dict.
    """
    return ldap_from_string(dnstr)


def to_issuer_gnames(subject, san):
    """Issuer GeneralNames for CRL usage.
    """
    gnames = []
    if subject:
        gnames.append("dn:" + render_name(subject, "/"))
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


#
# LDAP string representation of Distinguished Names from RFC4514
#

_ldap_allow_sep = (",", "/", "|")
_ldap_seg_rc = re.compile(r"""
    [^\s#,+=\\/|]+ | \\[0-9a-fA-F][0-9a-fA-F] | \\. | .
""", re.X)
_ldap_escape_rc = re.compile(r"""\A[ #]|[ ]\Z|["+;<>\\=\x00-\x1F\x7F-\x9F]""")
_ldap_unescape_rc = re.compile(r"(?:\\[0-9a-fA-F][0-9a-fA-F])+|\\.")


def _ldap_escape_fn(m: Match[str]) -> str:
    c = m.group()
    if c < "\x20" or c >= "\x7F":
        return "\\%02x" % ord(c)
    return "\\" + c


def _ldap_escape(s: str, sep: str) -> str:
    s = _ldap_escape_rc.sub(_ldap_escape_fn, s)
    if sep in s:
        s = s.replace(sep, "\\" + sep)
    return s


def _ldap_unescape_fn(m: Match[str]) -> str:
    s = m.group()
    if len(s) > 2:
        s = s.replace("\\", "")
        return binascii.a2b_hex(s).decode("utf8")
    return s[1]


def _ldap_unescape(val: List[str]) -> str:
    # avoid eating escaped whitespace
    while val and val[-1].isspace():
        val.pop()
    s = "".join(val).lstrip()
    if s.startswith("#"):
        raise ValueError("Hex octet representation not supported")
    return _ldap_unescape_rc.sub(_ldap_unescape_fn, s)


def ldap_to_string(mv_rdn: Iterable[Sequence[str]], rdnsep=","):
    """Render RDN list using format from RFC4514.
    """
    if rdnsep not in _ldap_allow_sep:
        raise ValueError("Separator not supported")
    space = " "
    if rdnsep != ",":
        space = ""
    sep, mvsep, kvsep = "", space + "+" + space, space + "=" + space
    res = []
    for rdn in mv_rdn:
        while rdn:
            res.append(sep)
            k, v, rdn, sep = rdn[0], rdn[1], rdn[2:], mvsep
            res.append(_ldap_escape(k, rdnsep))
            res.append(kvsep)
            res.append(_ldap_escape(v, rdnsep))
        sep = rdnsep + space
    if rdnsep == ",":
        return "".join(res)
    return "%s%s%s" % (rdnsep, "".join(res), rdnsep)


def ldap_from_string(val: str) -> Sequence[Sequence[str]]:
    """Parse RDN list using format from RFC4514.
    """
    sep = ","
    if val and val[0] in _ldap_allow_sep:
        sep = val[0]

    rdns = []
    rdn = []
    key: List[str] = []
    curTok: List[str] = []

    def flushpair() -> None:
        k = _ldap_unescape(key)
        v = _ldap_unescape(curTok)
        if k:
            if not v:
                raise ValueError("Need non-empty value")
            rdn.append(k)
            rdn.append(v)
            key.clear()
            curTok.clear()
        elif v:
            raise ValueError("Need key before value")

    for m in _ldap_seg_rc.finditer(val):
        c = m.group()
        if len(c) != 1:
            curTok.append(c)
        elif c == "=" and not key:
            key = curTok
            curTok = []
            if not key:
                raise ValueError("Need key before value")
        elif c == sep:
            flushpair()
            if rdn:
                rdns.append(tuple(rdn))
                rdn = []
        elif c == "+":
            flushpair()
        else:
            curTok.append(c)
    flushpair()
    if rdn:
        rdns.append(tuple(rdn))
    return tuple(rdns)

