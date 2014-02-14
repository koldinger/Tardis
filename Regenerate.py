# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2014, Eric Koldinger, All Rights Reserved.
# kolding@washington.edu
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import os
import os.path
import types
import sys
import argparse
import socket
import TardisDB
import TardisCrypto
import CacheDir
import logging
import subprocess
import time
from rdiff_backup import librsync
import tempfile
import shutil
import parsedatetime as pdt

version = "0.1"

database = "./tardisDB"

class Regenerator:
    def __init__(self, cache, db, crypt=None, tempdir="/tmp"):
        self.logger = logging.getLogger("Recoverer")
        self.cacheDir = cache
        self.db = db
        self.tempdir = tempdir
        self.crypt = crypt

    def decryptFile(self, filename, size, iv):
        if self.crypt == None:
            raise Exception("Encrypted file.  No password specified")
        cipher = self.crypt.getContentCipher(iv)
        outfile = tempfile.TemporaryFile()
        infile = self.cacheDir.open(filename, 'rb')
        outfile.write(cipher.decrypt(infile.read()))
        outfile.truncate(size)
        outfile.seek(0)
        return outfile

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
            if cksInfo['iv']:
                patchfile = self.decryptFile(cksum, cksInfo['deltasize'], cksInfo['iv'])
            else:
                patchfile = self.cacheDir.open(cksum, 'rb')
            output = librsync.PatchedFile(basis, patchfile)
            #output.seek(0)
            return output
        else:
            if cksInfo['iv']:
                return self.decryptFile(cksum, cksInfo['size'], cksInfo['iv'])
            else:
                return self.cacheDir.open(cksum, "rb")

    def recoverFile(self, filename, bset=False, nameEncrypted=False):
        self.logger.debug("Recovering file: {}".format(filename))
        name = filename
        if self.crypt and not nameEncrypted:
            name = self.crypt.encryptPath(filename)
        cksum = self.db.getChecksumByPath(name, bset)
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
    parser.add_argument("--password", "-p", help="Password", dest='password', default=None)
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

    crypt = None

    if args.password:
        crypt = TardisCrypto.TardisCrypto(args.password)

    r = Regenerator(cache, tardis, crypt=crypt)

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
