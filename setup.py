#! /usr/bin/python

from setuptools import setup, find_packages
import sys, os
import Tardis

version = Tardis.__version__

setup(  name                    = 'Tardis-Backup',
        version                 = version,
        description             = "Tardis Backup System",
        packages                = find_packages(exclude=['ez_setup', 'examples', 'tests']),
        include_package_data    = True,
        zip_safe                = False,
        install_requires = ['bson', 'daemonize', 'parsedatetime', 'pycrypto', 'pycurl', 'requests', 'flask', 'tornado', 'termcolor' ],
        data_files = [( '/etc/tardis',              [ 'tardisd.cfg' ]),
                      ( 'schema',                   [ 'schema/tardis.sql' ]),
                      ( '/etc/init.d',              [ 'init/tardisd' ]),
                      ( '/usr/lib/systemd/system',  [ 'init/tardisd.service' ]),
                      ( '/etc/logrotate.d',         [ 'logrotate/tardisd' ])
                     ],
        entry_points = {
                'console_scripts' : [
                    'tardis = Tardis.Client:main',
                    'tardisd = Tardis.Daemon:main',
                    'tardisfs = Tardis.TardisFS:main',
                    'regenerate = Tardis.Regenerate:main',
                    'lstardis = Tardis.List:main',
                    #'tardisremote = Tardis.HttpInterface:tornado',
                ],
        },
    )
