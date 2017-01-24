#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2010-2017 GRNET S.A.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from os.path import dirname, abspath, join
from setuptools import setup, find_packages
from imp import load_source

CWD = dirname(abspath(__file__))
README = join(CWD, 'README.md')
VERSION = join(CWD, 'nfdhcpd', 'version.py')

setup(
    name='nfdhcpd',
    version=getattr(load_source('version', VERSION), "__version__"),
    description="NFQUEUE-based DHCP, DHCPv6 and ICMPv6 RA for VM hosting",
    long_description=open(README).read(),
    url='https://github.com/grnet/nfdhcpd',
    download_url='https://pypi.python.org/pypi/nfdhcpd',
    maintainer="Nikos Skalkotos",
    maintainer_email="skalkoto@grnet.gr",
    license='GNU GPLv2+',
    packages=find_packages(),
    include_package_data=True,
    install_requires=['python-daemon', 'pyinotify', 'setproctitle',
                      'scapy', 'configobj'],
    # Unresolvable dependencies:
    #   python-nfqueue, python-cap-ng
    entry_points={
        'console_scripts': ['nfdhcpd = nfdhcpd:main']
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7'],
    keywords='cloud IaaS networking'
)
# vim: set sta sts=4 shiftwidth=4 sw=4 et ai :
