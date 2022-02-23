"""Custom exceptions.
"""

__all__ = ("InvalidCertificate", "UnsupportedParameter")


class InvalidCertificate(ValueError):
    """Invalid input for certificate."""


class UnsupportedParameter(ValueError):
    """Invalid parameter."""

