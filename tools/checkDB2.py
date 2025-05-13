#! /usr/bin/env python3
# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2025, Eric Koldinger, All Rights Reserved.
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

import sys
import argparse
import magic
import os
import io
import json

#from rich.progress import track
from rich.progress import RenderableColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, MofNCompleteColumn, TaskProgressColumn, Progress
from rich.logging import RichHandler

import Tardis
from Tardis import Util
from Tardis import Config
from Tardis import CompressedBuffer

args = None

def processArgs():
    parser = argparse.ArgumentParser(description='Check contents of the DB against the file system', fromfile_prefix_chars='@', formatter_class=Util.HelpFormatter, add_help=False)

    (_, remaining) = Config.parseConfigOptions(parser)

    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    #parser.add_argument('--output', '-o',   default=None, dest='output', required=True,           help='Output file')

    parser.add_argument('--authenticate', '-a', default='none', nargs='?', const='size',
                        dest='authenticate', choices=['none', 'size', 'all'], help='Authenticate files with incorrect sizes')
    parser.add_argument('--output', '-o', default=None, dest='output', type=argparse.FileType('w'), help='Output data')

    parser.add_argument('--verbose', '-v',  action='count', default=0, dest='verbose',                  help='Increase the verbosity')
    parser.add_argument('--version',        action='version', version='%(prog)s ' + Tardis.__versionstring__,    help='Show the version')
    parser.add_argument('--help', '-h',     action='help')

    Util.addGenCompletions(parser)

    return parser.parse_args(remaining)

def numChecksums(tardis):
    rs = tardis.conn.execute("SELECT COUNT(Checksum) FROM Checksums WHERE isFile = 1")
    if rs:
        return rs[0]
    return None

def listChecksums(tardis, chunksize=10000):
    rs = tardis.conn.execute("SELECT Checksum, DiskSize, Basis, Compressed, Encrypted, Added FROM Checksums WHERE isFile = 1 ORDER BY Checksum")

    while data := rs.fetchmany(chunksize):
        for row in data:
            yield(row[0], row[1], row[2], row[3], row[4], row[5])

def decryptHeader(crypt, infile):
   # Get the IV, if it's not specified.
    infile.seek(0, os.SEEK_SET)
    iv = infile.read(crypt.ivLength)

    # Create the cipher
    encryptor = crypt.getContentEncryptor(iv)

    ct = infile.read(64 * 1024)
    pt = encryptor.decrypt(ct, False)
    outstream = io.BytesIO(pt)
    return outstream

def authenticateFile(infile, size, crypt):
    # Get the IV, if it's not specified.
    infile.seek(0, os.SEEK_SET)
    iv = infile.read(crypt.ivLength)

    #logger.debug("Got IV: %d %s", len(iv), binascii.hexlify(iv))

    # Create the cipher
    encryptor = crypt.getContentEncryptor(iv)

    contentSize = size - crypt.ivLength - encryptor.getDigestSize()
    #self.logger.info("Computed Size: %d.  Specified size: %d.  Diff: %d", ctSize, size, (ctSize - size))

    try:
        rem = contentSize
        blocksize = 64 * 1024
        last = False
        while rem > 0:
            readsize = blocksize if rem > blocksize else rem
            if rem <= blocksize:
                last = True
            ct = infile.read(readsize)
            pt = encryptor.decrypt(ct, last)
            if last:
                # ie, we're the last block
                digest = infile.read(encryptor.getDigestSize())
                #logger.debug("Got HMAC Digest: %d %s", len(digest), binascii.hexlify(digest))
                readsize += len(digest)
                try:
                    encryptor.verify(digest)
                except:
                    #logger.debug("HMAC's:  File: %-128s Computed: %-128s", binascii.hexlify(digest), binascii.hexlify(encryptor.digest()))
                    print("HMAC's:  File: %-128s Computed: %-128s", binascii.hexlify(digest), binascii.hexlify(encryptor.digest()))
                    return False
            rem -= readsize
        return True
    except:
        return False

#tardis.log:      text/plain
#tardis.log.br:   application/octet-stream
#tardis.log.bz2:  application/x-bzip2
#tardis.log.gz:   application/gzip
#tardis.log.lzma: application/x-lzma
#tardis.log.xz:   application/x-xz
#tardis.log.zst:  application/x-zstd

def checkCompression(mimetype, compresstype):
    if (compresstype == 'zlib' or compresstype == True or compresstype == 1):
        if mimetype != 'application/zlib':
            return False
    elif compresstype == 'zstd':
        if mimetype != 'application/x-std':
            return False
    elif compresstype == 'bzip':
        if mimetype != 'application/x-bzip2':
            return False
    elif compresstype == 'lzma': 
        if mimetype != 'application/x-lzma' and mimetype != 'application/x-xz':
            return False
    elif not (compresstype == 'none' or compresstype == False):
        print(f"Unknown compression type: {compresstype}")
    return True

missing = []
zero = []
mismatch = []
notdelta = []
notauth = []
badcomp = []
sizes = {}

def checkFile(cache, crypt, db, checksum, authCond):
    info = db.getChecksumInfo(checksum)
    size = info.get('disksize', 0)
    basis = info.get('basis', None)
    compressed = info.get('compressed', None)
    encrypted = info.get('encrypted', None)
    added = info.get('added', 0)


    fsize = cache.size(checksum)
    if not cache.exists(checksum):
        #print(f"{checksum}: does not exist")
        missing.append(checksum)
    elif fsize == 0:
        print(f"{checksum} is empty")
        zero.append(checksum)
    else:
        authenticate = (authCond == 'all')
        if fsize != size:
            print(f"{checksum}: size mismatch Expected: {size}, found {fsize} ({fsize - size})-- {added} -- {basis is not None} ")
            mismatch.append((checksum, size, fsize, compressed))
            sizes.setdefault((fsize - size), []).append(checksum)
            if authCond != 'none':
                authenticate = True

            try:
                instream = decryptHeader(crypt, cache.open(checksum, "rb"))
                uc = CompressedBuffer.UncompressedBufferedReader(instream, compressor="none")
                data = uc.read(256)
                mimetype = magic.from_buffer(data, mime=True)
                if not checkCompression(mimetype, compressed):
                    print(f"{checksum} has wrong compression type.   Expected {compressed}.  Found {mimetype}")
                    badcomp.append((checksum, compressed, mimetype))
            except Exception as e:
                print(f"Caught exception: {compressed} {e}")
                badcomp.append((checksum, compressed, "error"))

        elif basis:
            #print(f"{checksum} -- {compressed} {encrypted}", flush=True)
            instream = decryptHeader(crypt, cache.open(checksum, "rb"))
            uc = CompressedBuffer.UncompressedBufferedReader(instream, compressor=compressed)
            data = uc.read(256)
            kind = magic.from_buffer(data)
            if kind != 'rdiff network-delta data':
                print(f"{checksum}: Not a delta: {kind}")
                notdelta.append((checksum, kind))

        if authenticate:
            with cache.open(checksum, "rb") as f:
                if not authenticateFile(f, fsize, crypt):
                    print(f"{checksum} did not authenticate")
                    notauth.append(checksum)

def main():
    global args
    args = processArgs()

    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog, prompt=f"Password for {args.repo}")
    (tardis, cache, crypt, _) = Util.setupDataConnection(args.repo, password, args.keys)

    count = 0
    #for (checksum, size, basis, compressed, encrypted, added) in track(listChecksums(tardis), description="Processing "):
    #    count += 1
    #    checkFile(cache, crypt, checksum, size, basis, compressed, encrypted, added, args.authenticate)

    numCks = tardis.getChecksumCount(isFile=True)
    checksums = tardis.enumerateChecksums(isFile=True)

    nameCol = RenderableColumn("")
    with Progress(TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TaskProgressColumn(),
                  nameCol,
                  MofNCompleteColumn(),
                  TimeElapsedColumn(),
                  TimeRemainingColumn(),
                  refresh_per_second=2) as progress:

        ckProgress = progress.add_task("Validating: ", total=numCks)

        for cksum in checksums:
            count += 1
            nameCol.renderable = cksum
            checkFile(cache, crypt, tardis, cksum, args.authenticate)
            progress.advance(ckProgress, 1)

    print(f"Files: {count} Missing Files: {len(missing)} Empty: {len(zero)} Size mismatch: {len(mismatch)} Not Delta: {len(notdelta)} Wrong Comp: {len(badcomp)}")
    #for i in sizes:
    #    print(f"   Size: {i}: Count {len(sizes[i])}")

    if args.output:
        out = {
            "missing": missing,
            "empty": zero,
            "size": mismatch,
            "notauth": notauth,
            "notdelta": notdelta,
            "badcomp":  badcomp
            }
        json.dump(out, args.output, indent=2)


    return 0

if __name__ == "__main__":
    sys.exit(main())
