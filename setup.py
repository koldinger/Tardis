#! /usr/bin/python3

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
			    'pid', 	      'python-magic',   'urllib3',   'binaryornot',   'python-snappy',   'srp',
                            'colorlog',       'progressbar2',   'reportlab', 'qrcode',
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
