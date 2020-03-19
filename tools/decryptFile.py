#! /usr/bin/env python3
# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2020, Eric Koldinger, All Rights Reserved.
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

from Tardis import Defaults, Util, TardisDB, TardisCrypto, CacheDir, librsync, Regenerator, Config, RemoteDB
import sqlite3
import argparse, logging
import os.path
import os
import sys
import base64
import hashlib
import progressbar
import urllib.parse
import binascii

logger = None

def reader(quiet):
    import readline
    prompt = '' if quiet else '--> '
    try:
        while True:
            yield input(prompt)
    except EOFError:
        return

def decryptFile(infile, outfile, size, crypt, authenticate=True):
    # Get the IV, if it's not specified.
    infile.seek(0, os.SEEK_SET)
    iv = infile.read(crypt.ivLength)

    logger.debug("Got IV: %d %s", len(iv), binascii.hexlify(iv))

    # Create the cipher
    encryptor = crypt.getContentEncryptor(iv)

    contentSize = size - crypt.ivLength - encryptor.getDigestSize()
    #self.logger.info("Computed Size: %d.  Specified size: %d.  Diff: %d", ctSize, size, (ctSize - size))

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
            logger.debug("Got HMAC Digest: %d %s", len(digest), binascii.hexlify(digest))
            readsize += len(digest)
            if authenticate:
                try:
                    encryptor.verify(digest)
                except:
                    logger.debug("HMAC's:  File: %-128s Computed: %-128s", binascii.hexlify(digest), binascii.hexlify(encryptor.digest()))
                    raise RegenerateException("HMAC did not authenticate.")
        outfile.write(pt)
        rem -= readsize

def processArgs():
    parser = argparse.ArgumentParser(description='Decrypt a File', fromfile_prefix_chars='@', add_help=False)

    (_, remaining) = Config.parseConfigOptions(parser)
    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    parser.add_argument('--output', '-o',       type=argparse.FileType('wb'), default=sys.stdout.buffer, help='output file (default: stdout)')
    parser.add_argument('--from_cache', '-c',   default=False, action='store_true', help='Read a cached file')
    parser.add_argument('--noauth', '-n',       default=False, action='store_true', help='Do not authenticate file info')
    parser.add_argument('--help', '-h',   action='help');
    parser.add_argument('name',           nargs=1, help="Pathnames to decrypt")

    Util.addGenCompletions(parser)

    args = parser.parse_args(remaining)

    return args

def main():
    global logger
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('')
    args = processArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog)

    (tardis, cache, crypto) = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname, args.dbdir)

    name = args.name[0]

    if args.from_cache:
        sz = cache.size(name)
        infile = cache.open(name, "rb")
    else:
        st = os.stat(name)
        sz = st.st_size
        infile = open(name, "rb")
    decryptFile(infile, args.output, sz, crypto, authenticate=not args.noauth)

if __name__ == "__main__":
    main()
