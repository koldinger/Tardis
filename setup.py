#! /usr/bin/python3
# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2019, Eric Koldinger, All Rights Reserved.
# kolding@washington.edu
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import os
import subprocess

from setuptools import setup, find_packages

import Tardis

longdesc = '''
This is a system for performing backups, supporting incremental, delta backups, with option encryption, and 
recovery of data via either a filesystem based interface, or via explicit tools.  Please pardon any Dr. Who
jokes.
'''

buildVersion = subprocess.check_output(['git', 'describe', '--dirty', '--tags', '--always']).strip()

print(buildVersion.decode('utf8'), file=open("Tardis/tardisversion", "w"))

root = os.environ.setdefault('VIRTUAL_ENV', '')

version = Tardis.__version__
add_pkgs = Tardis.check_features()

setup(  name                    = 'Tardis-Backup',
        version                 = version,
        description             = "Tardis Backup System",
        long_description        = longdesc,
        packages                = find_packages(exclude=['ez_setup', 'examples', 'tests']),
        author                  = "Eric Koldinger",
        author_email            = "kolding@washington.edu",
        url                     = "https://github.com/koldinger/Tardis",
        license                 = "BSD",
        platforms               = "Posix; MacOS X",
        include_package_data    = True,
        zip_safe                = False,
        install_requires = ['msgpack-python', 'daemonize', 'parsedatetime', 'pycryptodomex', 'requests',
			    'requests_cache', 'flask',     'tornado',       'termcolor',     'passwordmeter',
			    'pid', 	      'python-magic',   'urllib3',   'binaryornot',  'python-snappy',   'srp',
                            'colorlog',       'progressbar2',   'reportlab', 'qrcode',       'fusepy',
                            'Tardis_Backup'] + add_pkgs,
        data_files = [( root + '/etc/tardis',                     [ 'tardisd.cfg-template', 'types.ignore', 'tardisremote.cfg-template' ]),
                      ( root + '/etc/init.d',                     [ 'init/tardisd', 'init/tardisremote' ]),
                      ( root + '/usr/lib/systemd/system',         [ 'init/tardisd.service', 'init/tardisremote.service' ]),
                      ( root + '/etc/logrotate.d',                [ 'logrotate/tardisd', 'logrotate/tardisremote' ]),
                      ( root + '/etc/logwatch/conf/services',     [ 'logwatch/conf/services/tardisd.conf' ]),
                      ( root + '/etc/logwatch/conf/services',     [ 'logwatch/conf/services/tardisd.conf' ]),
                      ( root + '/etc/logwatch/conf/logfiles',     [ 'logwatch/conf/logfiles/tardisd.conf' ]),
                      ( root + '/etc/logwatch/scripts/services',  [ 'logwatch/scripts/services/tardisd' ]),
                     ],
	package_dir = {'': '.'},
	package_data = {
                        'Tardis':   [ 'tardisversion', 'schema/tardis.sql' ],
                       },
        entry_points = {
            'console_scripts' : [
                'tardis = Tardis.Client:main',
                'tardisd = Tardis.Daemon:main',
                'tardisfs = Tardis.TardisFS:main',
                'regenerate = Tardis.Regenerate:main',
                'lstardis = Tardis.List:main',
                'sonic = Tardis.Sonic:main',
                'tardiff = Tardis.Diff:main',
                'tardisremote = Tardis.HttpInterface:tornado',
            ],
        },
        classifiers = [
            'License :: OSI Approved :: BSD License',
            'Development Status :: 4 - Beta',
            'Intended Audience :: Developers',
            'Intended Audience :: System Administrators',
            'Topic :: System :: Archiving :: Backup',
            'Programming Language :: Python',
            'Programming Language :: Python :: 3',
            'Operating System :: MacOS :: MacOS X',
            'Operating System :: POSIX',
            'Operating System :: POSIX :: Linux',
        ]
     )

os.remove("Tardis/tardisversion")
