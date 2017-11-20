#! /usr/bin/python
from Tardis import Defaults, Util, TardisDB, TardisCrypto, CacheDir, librsync, Regenerator, Config, RemoteDB
import sqlite3
import argparse, logging
import os.path
import os
import sys
import base64
import hashlib
import progressbar
import urlparse

logger = None

def reader(quiet):
    import readline
    prompt = '' if quiet else '--> '
    try:
        while True:
            yield raw_input(prompt)
    except EOFError:
        return

def processArgs():
    parser = argparse.ArgumentParser(description='encrypt or decrypt filenames', fromfile_prefix_chars='@', add_help=False)

    (_, remaining) = Config.parseConfigOptions(parser)
    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser, addcrypt=False)

    parser.add_argument('--encrypt', '-e', dest='encrypt', default=False, action='store_true', help='Encrypt names instead of decrypting')
    parser.add_argument('--quiet', '-q', dest='quiet', default=False, action='store_true', help="Only print the translation, not the input strings")

    parser.add_argument('--help', '-h',     action='help');
    parser.add_argument('names',          nargs='*', help="List of pathnames to decrypt")

    Util.addGenCompletions(parser)

    args = parser.parse_args(remaining)

    return args

def main():
    global logger
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('')
    args = processArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog)

    (_, _, crypto) = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname, args.dbdir)

    data = args.names
    if not data:
        tty = os.isatty(0)
        if not tty:
            data = map(str.strip, sys.stdin.readlines())
        else:
            data = reader(args.quiet)

    for i in data:
        if i:
            if not args.quiet:
                print i, " \t => \t",
            try:
                if (args.encrypt):
                    print crypto.encryptPath(i)
                else:
                    print crypto.decryptPath(i)
            except Exception as e:
                print "Caught exception: " + str(e)


if __name__ == "__main__":
    main()
