#!/usr/bin/env python

import setuptools

setuptools.setup(
    name='octodns-m365',
    version='1.0.0',
    description='Octodns provider for M365 config',
    url='http://github.com/ski7777/octodns-m365',
    author='Raphael Jacob',
    author_email='r.jacob2002@gmail.com',
    license='GPLv3',
    py_modules=["octodns_m365"],
    install_requires=[
        'octodns>=0.9.21'
    ]
)
