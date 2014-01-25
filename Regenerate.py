import os
import os.path
import types
import sys
import argparse
import socket
import TardisDB
import CacheDir
import logging
import subprocess
import time
from rdiff_backup import librsync
import tempfile
import shutil
import parsedatetime.parsedatetime as pdt

version = "0.1"

database = "./tardisDB"

class Regenerator:
    def __init__(self, cache, db, tempdir="/tmp"):
        self.logger = logging.getLogger("Recoverer")
        self.cacheDir = cache
        self.db = db
        self.tempdir = tempdir

    def recoverChecksum(self, cksum):
        self.logger.debug("Recovering checksum: {}".format(cksum))
        cksInfo = self.db.getChecksumInfo(cksum)
        if cksInfo['basis']:
            basis = self.recoverChecksum(cksInfo['basis'])
            # UGLY.  Put the basis into an actual file for librsync
            if type(basis) is not types.FileType:
                temp = tempfile.TemporaryFile()
                shutil.copyfileobj(basis, temp)
                basis = temp
            #librsync.patch(basis, self.cacheDir.open(cksum, "rb"), output)
            output = librsync.PatchedFile(basis, self.cacheDir.open(cksum, "rb"))
            #output.seek(0)
            return output
        else:
            return self.cacheDir.open(cksum, "rb")

    def recoverFile(self, filename, bset=False):
        self.logger.debug("Recovering file: {}".format(filename))
        cksum = self.db.getChecksumByPath(filename, bset)
        if cksum:
            return self.recoverChecksum(cksum)
        else:
            self.logger.error("Could not open file {}".format(filename))
            return None


def main():
    parser = argparse.ArgumentParser(sys.argv[0], description="Regenerate a Tardis backed file")

    parser.add_argument("--output", "-o", dest="output", help="Output file", default=None)
    parser.add_argument("--database", "-d", help="Path to database directory", dest="database", default=database)
    parser.add_argument("--backup", "-b", help="backup set to use", dest='backup', default=None)
    parser.add_argument("--date", "-D",   help="Regenerate as of date", dest='date', default=None)
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
    logger = logging.getLogger("")
    logger.setLevel(logging.ERROR)

    baseDir = os.path.join(args.database, args.host)
    dbName = os.path.join(baseDir, "tardis.db")
    tardis = TardisDB.TardisDB(dbName, backup=False)
    cache = CacheDir.CacheDir(baseDir)

    r = Regenerator(cache, tardis)

    bset = False

    if args.date:
        cal = pdt.Calendar()
        (then, success) = cal.parse(args.date)
        if success:
            timestamp = time.mktime(then)
            bsetInfo = tardis.getBackupSetInfoForTime(timestamp)
            if bsetInfo and bsetInfo['backupset'] != 1:
                bset = bsetInfo['backupset']
            else:
                logger.critical("No backupset at date: %s (%s)", args.date, time.asctime(then))
                sys.exit(1)
        else:
            logger.critical("Could not parse date string: %s", args.date)
            sys.exit(1)
    elif args.backup:
        bsetInfo = tardis.getBackupSetInfo(args.backup)
        if bsetInfo:
            bset = bsetInfo['backupset']
        else:
            logger.critical("No backupset at for name: %s", args.backup)
            sys.exit(1)

    if args.output:
        output = file(args.output, "wb")
    else:
        output = sys.stdout

    for i in args.files:
        f = None
        if args.cksum:
            f = r.recoverChecksum(i)
        else:
            f = r.recoverFile(i, bset)

        if f != None:
            x = f.read(16 * 1024)
            while x:
                output.write(x)
                x = f.read(16 * 1024)
            f.close()

if __name__ == "__main__":
    sys.exit(main())
