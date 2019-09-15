"""SysCA - Certificate tool for sysadmins.
"""

__version__ = "2.0"


def _version_info():
    """Info string for --version.
    """
    try:
        import cryptography
        from cryptography.hazmat.backends import default_backend
        cver = cryptography.__version__
        b = default_backend()
        bver = b.name
        if hasattr(b, "openssl_version_text"):
            bver = b.openssl_version_text()
        return "%s (cryptography %s, %s)" % (__version__, cver, bver)
    except ImportError:
        return __version__ + " (no cryptography)"


FULL_VERSION = _version_info()
