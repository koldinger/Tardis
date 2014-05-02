from setuptools import setup, find_packages
import sys, os

version = '0.1'

setup(  name                    = 'Tardis',
        version                 = version,
        description             = "Demo Pakcage",
        packages                = find_packages(exclude=['ez_setup', 'examples', 'tests']),
        include_package_data    = True,
        zip_safe                = False,
        install_requires = ['bson', 'pycrypto' ],
        entry_points = {
                'console_scripts' : [
                    'tardis = Tardis.TardisClient',
                    'tardisd = Tardis.TardisDaemon',
                    'tardisfs = Tardis.TardisFS',
                    'regenerate = Tardis.Regenerate',
                ],
        },
    )
