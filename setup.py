
from setuptools import setup

# load version without importing
import re
src = open('sysca.py', 'r').read()
version = re.search(r"""^__version__\s*=\s*['"]([^'"]+)['"]""", src, re.M).group(1)

# load description
longdesc = open('README.rst', 'r').read().split('\nCommands\n')[0].strip()
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
    zip_safe=True,
    install_requires=['cryptography>=2.1'],
    keywords=['x509', 'tls', 'ssl', 'certificate', 'authority', 'command-line', 'server', 'authentication'],
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

