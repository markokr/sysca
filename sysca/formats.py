"""String <> Python objects.
"""

import binascii
import re
from datetime import datetime, timedelta, timezone
from typing import (
    Callable, Iterable, List, Match, Optional,
    Sequence, Tuple, Union, overload,
)

from .compat import (
    GNameList, MaybeList, MaybeName, MaybeNumber, MaybeTimestamp, NameSeq,
)

__all__ = (
    "as_bytes", "as_password",
    #"maybe_parse_str", "maybe_parse",
    "maybe_parse_list",
    "maybe_parse_timestamp",
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
        dt = datetime.fromisoformat(sval)
        if dt.tzinfo is not None:
            return dt.astimezone(timezone.utc)
    elif re.match(r"^\d\d\d\d-\d\d-\d\d$", sval):
        dt = datetime.strptime(sval, "%Y-%m-%d")
    elif re.match(r"^\d\d\d\d-\d\d-\d\d \d\d:\d\d$", sval):
        dt = datetime.strptime(sval, "%Y-%m-%d %H:%M")
    elif re.match(r"^\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d$", sval):
        dt = datetime.strptime(sval, "%Y-%m-%d %H:%M:%S")
    else:
        raise ValueError("Invalid timestamp: %r" % sval)
    return dt.replace(tzinfo=timezone.utc)


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


def show_list(desc: str, lst: Optional[Sequence[str]], writeln: Callable[[str], None]) -> None:
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


@overload
def maybe_parse_timestamp(val: MaybeTimestamp) -> datetime: ...
@overload
def maybe_parse_timestamp(val: Optional[MaybeTimestamp]) -> Optional[datetime]: ...


def maybe_parse_timestamp(val: Optional[MaybeTimestamp]) -> Optional[datetime]:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        return parse_timestamp(val)
    raise TypeError("expected str or timestamp")


def maybe_parse_list(val: Optional[MaybeList]) -> List[str]:
    if val is None:
        return []
    if isinstance(val, str):
        return parse_list(val)
    if isinstance(val, (list, tuple)):
        return list(val)
    raise TypeError("expected str or list[str]")


@overload
def maybe_parse_number(val: MaybeNumber) -> int: ...
@overload
def maybe_parse_number(val: Optional[MaybeNumber]) -> Optional[int]: ...


def maybe_parse_number(val: Optional[MaybeNumber]) -> Optional[int]:
    if val is None:
        return None
    if isinstance(val, str):
        return int(val)
    if isinstance(val, int):
        return val
    raise TypeError("expected str or int")


def maybe_parse_dn(val: Optional[MaybeName]) -> NameSeq:
    if val is None:
        return ()
    if isinstance(val, str):
        return parse_dn(val)
    if isinstance(val, dict):
        return tuple(val.items())
    if isinstance(val, tuple):
        return val
    raise TypeError("expected str, dict or tuple")


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
            raise ValueError("rx bug")
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


def parse_dn(dnstr: str) -> NameSeq:
    """Parse openssl-style /-separated list to dict.
    """
    return ldap_from_string(dnstr)


def to_issuer_gnames(subject: Optional[NameSeq], san: Optional[GNameList]) -> GNameList:
    """Issuer GeneralNames for CRL usage.
    """
    gnames: List[str] = []
    if subject:
        gnames.append("dn:" + render_name(subject, "/"))
    if san:
        gnames.extend(san)
    return gnames


def parse_time_period(
    days: Optional[Union[str, int]] = None,
    not_valid_before: Optional[MaybeTimestamp] = None,
    not_valid_after: Optional[MaybeTimestamp] = None,
    gap: int = 1,
) -> Tuple[datetime, datetime]:
    """Calculate time range
    """
    days = maybe_parse_number(days)
    dt_now = datetime.now(timezone.utc)
    if not_valid_before is None:
        dt_not_valid_before = dt_now - timedelta(hours=gap)
    else:
        dt_not_valid_before = maybe_parse_timestamp(not_valid_before)
    if not_valid_after is None:
        if days is None:
            raise ValueError("need days")
        dt_not_valid_after = dt_now + timedelta(days=days)
    else:
        dt_not_valid_after = maybe_parse_timestamp(not_valid_after)
    if dt_not_valid_before > dt_not_valid_after:
        raise ValueError("negative time range")
    return dt_not_valid_before, dt_not_valid_after


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


def ldap_to_string(mv_rdn: Iterable[Sequence[str]], rdnsep: str = ",") -> str:
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


def ldap_from_string(val: str) -> NameSeq:
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

