Version history
===============

1.3
---

* [feature] Support all EC curves (``cryptography`` 2.6+)
* [feature] Support DSA keys
* [fix] Prepare for ed25519 keys, requires ``cryptography`` 2.8+
* [fix] CRL handling fixes
* [fix] Do not set path-length by default for CAs.
* [fix] Use 20 byte serial number instead 16.

1.2
---

* [feature] Support CRL generation via ``update-crl`` command.
* [feature] Support ed25519 keys, if ``cryptography`` supports them.
* [fix] Drop support of Python 2.

1.1
---

* [feature] Add ``selfsign`` command.
* [feature] Switches ``--ocsp-must-staple`` and ``--ocsp-must-staple-v2`` to set OCSP Must-Staple flags.
* [feature] Switch ``--reset`` for sign to rewrite all info in CSR.
* [feature] Support all DN fields defined in ``x509`` module.
* [feature] Support multi-value attributes for DN.
* [fix] Sanitize ``--usage`` defaults.
* [dev] Move to pylist+pytest.

1.0.4
-----

* [pip] Add setup.cfg to allow universal wheel.

1.0.3
-----

* [fix] Ignore unicode errors when decoding stderr

1.0.2
-----

* [fix] Use utcnow() instead now(), otherwise local time is set as utc.
* [api] Flexible argument types

1.0.1
-----

* [pip] setup: use install_requires instead requires

1.0
---

* Initial release

