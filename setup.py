#!/usr/bin/env python3
from io import open
from os import path
import re

from setuptools import setup

version_py = path.join('vipaccess', 'version.py')

with open(version_py, 'r', encoding='utf-8') as fh:
    version_match = re.search(r'^__version__\s*=\s*[\'"]([^\'"]+)[\'"]', fh.read(), re.MULTILINE)
if version_match is None:
    raise RuntimeError('Unable to determine package version from %s' % version_py)
version_pep = version_match.group(1)

setup(
    name='python-vipaccess',
    version=version_pep,
    description="A free software implementation of Symantec's VIP Access application and protocol",
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/dlenski/python-vipaccess',
    author='Daniel Lenski',
    author_email='dlenski@gmail.com',
    license='Apache 2.0',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    keywords='development',
    packages=['vipaccess'],
    install_requires=[
        # verify consistency with requirements.txt
        'pycryptodome>=3.6.6',
        'oath>=1.4.1',
        'requests',
    ],
    extras_require={"qr": ["qrcode"]},
    entry_points={
        'console_scripts': [
            'vipaccess=vipaccess.__main__:main',
        ],
    },
    test_suite='nose2.collector.collector',
)
