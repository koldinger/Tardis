#! /usr/bin/python
# -*- coding: utf-8 -*-

import os
import os.path
import sys
import argparse
import socket
import TardisDB
import CacheDir
import logging
import subprocess

version = "0.1"

database = "./tardisDB"

class Regenerator:
    def __init__(self, cache, db):
        self.logger = logging.getLogger("Recoverer")
        self.cacheDir = cache
        self.db = db

    def recoverChecksum(self, cksum, bset=False):
        self.logger.debug("Recovering checksum: {}".format(cksum))
        (name, basis) = self.db.getChecksumInfo(cksum)
        if basis:
            input = self.recoverChecksum(basis, bset)
            pipe = subprocess.Popen(["rdiff", "patch", "-", self.cacheDir.path(name)], stdin=input, stdout=subprocess.PIPE)
            return pipe.stdout
        else:
            return self.cacheDir.open(name, "rb")

    def recoverFile(self, filename, bset=False):
        self.logger.debug("Recovering file: {}".format(filename))
        cksum = self.db.getChecksumByPath(filename, bset)
        if cksum:
            return self.recoverChecksum(cksum)
        else:
            self.logger.error("Could not open file {}".format(filename))
            return None


def main():
    logger = logging.getLogger("")
    logger.setLevel(logging.ERROR)

    parser = argparse.ArgumentParser(sys.argv[0], description="Regenerate a Tardis backed file")

    parser.add_argument("--output", "-o", dest="output", help="Output file", default=None)
    parser.add_argument("--database", "-d", help="Path to database directory", dest="database", default=database)
    parser.add_argument("--backup", "-b", help="backup set to use", dest='backup', default=None)
    parser.add_argument("--host", "-H", help="Host to process for", dest='host', default=socket.gethostname())
    parser.add_argument("--checksum", "-c", help="Use checksum instead of filename", dest='cksum', action='store_true', default=False)
    parser.add_argument('--verbose', '-v', action='count', dest='verbose', help='Increase the verbosity')
    parser.add_argument('--version', action='version', version='%(prog)s ' + version, help='Show the version')
    parser.add_argument('files', nargs='+', default=None, help="List of files to regenerate")

    args = parser.parse_args()

    FORMAT = "%(levelname)s : %(name)s : %(message)s"
    #formatter = logging.Formatter("%(levelname)s : %(name)s : %(message)s")
    #handler = logging.StreamHandler(stream=sys.stderr)
    #handler.setFormatter(formatter)
    #logger.addHandler(handler)
    logging.basicConfig(stream=sys.stderr, format=FORMAT)

    baseDir = os.path.join(args.database, args.host)
    dbName = os.path.join(baseDir, "tardis.db")
    tardis = TardisDB.TardisDB(dbName, backup=False, prevSet=args.backup)
    cache = CacheDir.CacheDir(baseDir)

    r = Regenerator(cache, tardis)

    if args.output:
        output = file(args.output, "wb")
    else:
        output = sys.stdout

    for i in args.files:
        f = None
        if args.cksum:
            f = r.recoverChecksum(i)
        else:
            f = r.recoverFile(i)

        if f != None:
            x = f.read(16 * 1024)
            while x:
                output.write(x)
                x = f.read(16 * 1024)
            f.close()

if __name__ == "__main__":
    sys.exit(main())
