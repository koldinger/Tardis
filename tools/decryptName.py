#! /usr/bin/python

from Tardis import Defaults, Util, TardisDB, TardisCrypto, CacheDir, librsync, Regenerator, Config
import sqlite3
import argparse, logging
import os.path
import os
import sys
import base64
import hashlib
import sys
import progressbar

logger = None


def processArgs():
    parser = argparse.ArgumentParser(description='encrypt or decrypt filenames', fromfile_prefix_chars='@', add_help=False)

    (_, remaining) = Config.parseConfigOptions(parser)
    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser, addcrypt=False)

    parser.add_argument('--help', '-h',     action='help');
    parser.add_argument('names',          nargs='*', help="List of pathnames to decrypt")

    args = parser.parse_args(remaining)

    return args

def main():
    global logger
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('')
    args = processArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog)

    crypto = TardisCrypto.TardisCrypto(password, args.client)

    path = os.path.join(args.database, args.client, args.dbname)
    db = TardisDB.TardisDB(path, backup=False)

    Util.authenticate(db, args.client, password)
    (f, c) = db.getKeys()
    crypto.setKeys(f, c)

    for i in args.names:
        print "=>", crypto.decryptPath(i)

if __name__ == "__main__":
    main()
