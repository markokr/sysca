
from sysca.formats import ldap_to_string, ldap_from_string

import pytest


def test_ldap_to_string():
    assert ldap_to_string([("C", "QQ")]) == "C = QQ"
    assert ldap_to_string((("C", "QQ"), ("O", "org"))) == "C = QQ, O = org"
    assert ldap_to_string([("C", "QQ", "O", "org")]) == "C = QQ + O = org"
    assert ldap_to_string([("C", "QQ", "O", "org", "OU", "u"), ("ST", "s")]) == "C = QQ + O = org + OU = u, ST = s"
    assert ldap_to_string([("O", "  x  ")]) == r"O = \  x \ "
    assert ldap_to_string([("O", "#z#")]) == r"O = \#z#"
    assert ldap_to_string([("O", "+<>\"=;\\")]) == r"""O = \+\<\>\"\=\;\\"""

    assert ldap_to_string([("O", "o", "O", "oo"), ("OU", "u")]) == r"O = o + O = oo, OU = u"
    assert ldap_to_string([("O", "o", "O", "oo"), ("OU", "u")], "/") == r"/O=o+O=oo/OU=u/"
    assert ldap_to_string([("O", "o", "O", "oo"), ("OU", "u")], "|") == r"|O=o+O=oo|OU=u|"

    assert ldap_to_string([("O", ",|/")]) == r"O = \,|/"
    assert ldap_to_string([("O", ",|/")], ",") == r"O = \,|/"
    assert ldap_to_string([("O", ",|/")], "|") == r"|O=,\|/|"
    assert ldap_to_string([("O", ",|/")], "/") == r"/O=,|\//"

    assert ldap_to_string([("O", "\x00\x1f\n\r\x7F")]) == r"O = \00\1f\0a\0d\7f"

    assert ldap_to_string([]) == r""
    assert ldap_to_string([()]) == r""
    assert ldap_to_string([(), (), ()]) == r""

    with pytest.raises(ValueError):
        ldap_to_string([], "+")


def test_ldap_from_string():
    assert ldap_from_string("C=QQ") == (("C", "QQ"),)
    assert ldap_from_string("C=QQ,O=o+OU=z") == (("C", "QQ"), ("O", "o", "OU", "z"))
    assert ldap_from_string(" C = QQ , O = o + OU = z ") == (("C", "QQ"), ("O", "o", "OU", "z"))
    assert ldap_from_string(r"C=\  x \ ") == (("C", "  x  "),)
    assert ldap_from_string(r" C = \  x \  ") == (("C", "  x  "),)
    assert ldap_from_string("\r\n\tC\r\n\t=\r\n\tx\r\n\t+\r\n\tOU\t=\tz\n,\nL=y") == (("C", "x", "OU", "z"), ("L", "y"))
    assert ldap_from_string(" , + C=x , + , O=y + ,") == (("C", "x"), ("O", "y"))

    assert ldap_from_string("1.2.3 = f") == (("1.2.3", "f"),)
    assert ldap_from_string(r"O = \00\01\02 \03") == (("O", "\x00\x01\x02 \x03"),)
    assert ldap_from_string(r"O = Lu\C4\8Di\C4\87") == (("O", "Lu\u010Di\u0107"),)

    with pytest.raises(ValueError):
        ldap_from_string("O=#00")

    with pytest.raises(ValueError):
        ldap_from_string("O")
    with pytest.raises(ValueError):
        ldap_from_string("O=")
    with pytest.raises(ValueError):
        ldap_from_string("O + C=x")
    with pytest.raises(ValueError):
        ldap_from_string("O= + C=x")
    with pytest.raises(ValueError):
        ldap_from_string("O , C=x")
    with pytest.raises(ValueError):
        ldap_from_string("O= , C=x")
    with pytest.raises(ValueError):
        ldap_from_string("=z")
    with pytest.raises(ValueError):
        ldap_from_string(" = z")
