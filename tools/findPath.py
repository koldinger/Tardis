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

logger = None

def reader(quiet):
    import readline
    prompt = '' if quiet else '--> '
    try:
        while True:
            yield input(prompt)
    except EOFError:
        return

def processArgs():
    parser = argparse.ArgumentParser(description='Extract paths for a changeset', fromfile_prefix_chars='@', add_help=False)

    (_, remaining) = Config.parseConfigOptions(parser)
    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    parser.add_argument('--encrypt', '-e', dest='encrypt', default=False, action='store_true', help='Encrypt names instead of decrypting')
    parser.add_argument('--quiet', '-q', dest='quiet', default=False, action='store_true', help="Only print the translation, not the input strings")
    parser.add_argument('--backup', '-b', dest='backup', default=None, help='Look in specific backupset')

    parser.add_argument('--help', '-h',     action='help');
    parser.add_argument('checksums',          nargs='*', help="List of checksums to extract")

    Util.addGenCompletions(parser)

    args = parser.parse_args(remaining)

    return args

_paths = {(0, 0): '/'}

def _decryptFilename(name, crypt):
    return crypt.decryptFilename(name) if crypt else name

def _path(db, crypt, bset, inode):
    global _paths
    if inode in _paths:
        return _paths[inode]
    else:
        fInfo = db.getFileInfoByInode(inode, bset)
        if fInfo:
            parent = (fInfo['parent'], fInfo['parentdev'])
            prefix = _path(db, crypt, bset, parent)

            name = _decryptFilename(fInfo['name'], crypt)
            path = os.path.join(prefix, name)
            _paths[inode] = path
            return path
        else:
            return ''

def main():
    global logger
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('')
    args = processArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog)

    (tardis, _, crypto) = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname, args.dbdir)

    if args.backup is not None:
        bsetInfo = Util.getBackupSet(tardis, args.backup)
        if bsetInfo:
            bset = bsetInfo['backupset']
        else:
            logger.critical("No backupset at for name: %s", args.backup)
            sys.exit(1)
    else:
        bset = False

    data = args.checksums
    if not data:
        tty = os.isatty(0)
        if not tty:
            data = list(map(str.strip, sys.stdin.readlines()))
        else:
            data = reader(args.quiet)

    prevInode = None
    for i in data:
        try:
            for finfo in tardis.getFileInfoByChecksum(i, bset):
                inode = (finfo['inode'], finfo['device'])
                if inode == prevInode:
                    next
                prevInode = inode
                if args.quiet:
                    print(_path(tardis, crypto, bset, inode))
                else:
                    print(f"{i} => {_path(tardis, crypto, bset, inode)}")

        except Exception as e:
            print("Caught exception: " + str(e))


if __name__ == "__main__":
    main()
