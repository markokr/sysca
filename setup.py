
from setuptools import setup

# load version without importing
import re
src = open("sysca/__init__.py", "r").read()
version = re.search(r"""^__version__\s*=\s*['"]([^'"]+)['"]""", src, re.M).group(1)

# load description
longdesc = open("README.rst", "r").read().split("\nCommands\n")[0].strip()
desc = longdesc.splitlines()[0].split("-", 1)[1].strip()

setup(
    name="sysca",
    version=version,
    description=desc,
    long_description=longdesc,
    author="Marko Kreen",
    license="ISC",
    author_email="markokr@gmail.com",
    url="https://github.com/markokr/sysca",
    packages=["sysca"],
    entry_points={
        "console_scripts": ["sysca=sysca.tool:main"],
    },
    zip_safe=True,
    install_requires=["cryptography>=2.8"],
    keywords=["x509", "tls", "ssl", "certificate", "authority", "command-line", "server", "authentication"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: ISC License (ISCL)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ]
)

