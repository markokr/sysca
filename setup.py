
from setuptools import setup

# load version without importing
import re
src = open('sysca.py', 'r').read()
version = re.search(r"""^__version__\s*=\s*['"]([^'"]+)['"]""", src, re.M).group(1)

# load description
longdesc = open('README.rst', 'r').read().strip()
desc = longdesc.splitlines()[0].split('-', 1)[1].strip()

setup(
    name="sysca",
    version=version,
    description=desc,
    long_description=longdesc,
    author="Marko Kreen",
    license="ISC",
    author_email="markokr@gmail.com",
    url="https://github.com/markokr/sysca",
    py_modules=['sysca'],
    entry_points={
        'console_scripts': ['sysca=sysca:main'],
    },
    install_requires=['cryptography>=1.2'],
    tests_require=['nose'],
    test_suite='nose.collector',
    keywords=['x509', 'tls', 'ssl', 'certificate', 'authority', 'command-line', 'server', 'authentication'],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: ISC License (ISCL)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ]
)

