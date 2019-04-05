Version history
===============

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

