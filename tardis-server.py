#! /usr/bin/python

import argparse
import os
import sys
import ConfigParser

defaultConfig = './tardis-server.cfg'

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Tardis Backup Server')

    parser.add_argument('--config', dest='config', default=defaultConfig, help="Location of the configuration file")
    parser.add_argument('--single', dest='single', action='store_true', help='Run a single transaction and quit')
    parser.add_argument('--verbose', '-v', action='count', dest='verbose', help='Increase the verbosity')
    parser.add_argument('--version', action='version', version='%(prog)s 0.1', help='Show the version')

    args = parser.parse_args()
    print args

    configDefaults = {
        'Port' : '9999',
        'BaseDir' : '.',
        'Verbose' : str(args.verbose)
    }

    config = ConfigParser.ConfigParser(configDefaults)
    config.read(args.config)


    print config.get('DEFAULT', 'Port')
    print config.get('DEFAULT', 'BaseDir')
    print config.get('DEFAULT', 'Verbose')
