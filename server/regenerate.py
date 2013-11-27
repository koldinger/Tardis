#! /usr/bin/python

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

def recoverChecksum(cksum, db, cacheDir):
    logger.debug("Recovering checksum: {}".format(cksum))
    (name, basis) = db.getChecksumInfo(cksum)
    if basis:
        input = recoverChecksum(basis, db, cacheDir)
        pipe = subprocess.Popen(["rdiff", "patch", "-", cacheDir.path(name)], stdin=input, stdout=subprocess.PIPE)
        return pipe.stdout
    else:
        return cacheDir.open(name, "rb")

def recoverFile(filename, db, cacheDir):
    logger.debug("Recovering file: {}".format(filename))
    info = db.getFileInfoByPath(filename)
    if info:
        return recoverChecksum(info["checksum"], db, cacheDir)
    else:
        logger.error("Could not open file {}".format(filename))
        return None

logger = logging.getLogger("")

if __name__ == "__main__":
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
    logger.setLevel(logging.DEBUG)
    logging.basicConfig(stream=sys.stderr, format=FORMAT)

    baseDir = os.path.join(args.database, args.host)
    dbName = os.path.join(baseDir, "tardis.db")
    db = TardisDB.TardisDB(dbName, backup=False, prevSet=args.backup)

    cacheDir = CacheDir.CacheDir(baseDir)

    if args.output:
        output = file(args.output, "wb")
    else:
        output = sys.stdout

    for i in args.files:
        f = None
        if args.cksum:
            f = recoverChecksum(i, db, cacheDir)
        else:
            f = recoverFile(i, db, cacheDir)

        x = f.read(16 * 1024)
        while x:
            output.write(x)
            x = f.read(16 * 1024)

        f.close()
