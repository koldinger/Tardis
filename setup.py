#! /usr/bin/python

from setuptools import setup, find_packages
import sys, os
import subprocess
    
buildVersion = subprocess.check_output(['git', 'describe', '--dirty', '--tags', '--always']).strip()
file('tardisversion', 'w').write(buildVersion + "\n")

import Tardis

root = os.environ.setdefault('VIRTUAL_ENV', '')

version = Tardis.__version__
add_pkgs = Tardis.__check_features()

setup(  name                    = 'Tardis-Backup',
        version                 = version,
        description             = "Tardis Backup System",
        packages                = find_packages(exclude=['ez_setup', 'examples', 'tests']),
        include_package_data    = True,
        zip_safe                = False,
        install_requires = ['msgpack-python', 'daemonize', 'parsedatetime', 'pycrypto', 'pycurl', 'requests', 'flask', 'tornado', 'termcolor', 'python-magic' ] + add_pkgs,
        data_files = [( root + '/etc/tardis',              [ 'tardisd.cfg', 'types.ignore', 'tardisremote.cfg' ]),
                      ( 'schema',                          [ 'schema/tardis.sql' ]),
                      ( 'info',                            [ 'tardisversion' ]),
                      ( root + '/etc/init.d',              [ 'init/tardisd', 'init/tardisremote' ]),
                      ( root + '/usr/lib/systemd/system',  [ 'init/tardisd.service', 'init/tardisremote.service' ]),
                      ( root + '/etc/logrotate.d',         [ 'logrotate/tardisd', 'logrotate/tardisremote' ]),
                      #( '/etc/logwatch/conf/services', [ 'logwatch/tardisd.conf' ]),
                      #( '/etc/logwatch/scripts/services', [ 'logwatch/tardisd.pl' ]),
                     ],
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
    )
