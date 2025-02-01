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

import argparse
import logging
import os.path
import os
import sys
import functools

from termcolor import cprint, colored

from Tardis import Util, Config

from icecream import ic
ic.enable()

logger = None

def reader(quiet):
    prompt = '' if quiet else '--> '
    try:
        while True:
            yield input(prompt)
    except EOFError:
        return

def processArgs():
    parser = argparse.ArgumentParser(description='Extract paths for a checksum', fromfile_prefix_chars='@', add_help=False)

    (_, remaining) = Config.parseConfigOptions(parser)
    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    parser.add_argument('--quiet', '-q', dest='quiet', default=False, action='store_true', help="Only print the translation, not the input strings")
    parser.add_argument('--backup', '-b', dest='backup', default='Any', help='Look in specific backupset')
    parser.add_argument('--chain', '-c', dest='chain', default=False, action='store_true', help="Print file info on all stages in the chain")
    parser.add_argument('--inchain', '-i', dest='inchain', default=False, action='store_true', help='Find files for which are dependent on this checksum')

    parser.add_argument('--help', '-h',     action='help')
    parser.add_argument('checksums',          nargs='*', help="List of checksums to extract")

    Util.addGenCompletions(parser)

    args = parser.parse_args(remaining)

    return args

def _decryptFilename(name, crypt):
    return crypt.decryptFilename(name) if crypt else name

functools.cache
def _path(db, crypt, bset, inode):
    #ic(inode, bset)
    if inode == (0, 0):
        return '/'

    fInfo = db.getFileInfoByInode(inode, bset)
    if fInfo:
        parent = (fInfo['parent'], fInfo['parentdev'])
        prefix = _path(db, crypt, bset, parent)

        name = _decryptFilename(fInfo['name'], crypt)
        path = os.path.join(prefix, name)
        #_paths[inode] = path
        return path
    return ''

def printFileInfo(checksum, bset, tardis, crypto, quiet):
    for finfo in tardis.getFileInfoByChecksum(checksum, bset):
        prevInode = None
        inode = (finfo['inode'], finfo['device'])
        if inode == prevInode:
            continue
        prevInode = inode
        actual = finfo['firstset']
        if quiet:
            print(_path(tardis, crypto, actual, inode))
        else:
            print(f"{colored(checksum, 'cyan')} => [{finfo['firstset']:5}, {finfo['lastset']:5}] ({finfo['inode']:5}, {finfo['device']:4})\t{colored(_path(tardis, crypto, actual, inode), 'green')}")

def printChainInfo(checksum, tardis):
    info = tardis.getChecksumInfoChain(checksum)
    x = 0
    for j in info:
        print(f"  {colored(x, 'red'):2}: {colored(j['checksum'], 'cyan')} Size: {j['size']:8} File: {bool(j['isfile'])} Compressed: {j['compressed']} Encrypted: {bool(j['encrypted'])} DiskSize: {j['disksize']}")
        x += 1
    print("")

def printParentInfo(checksum, tardis, crypto, bset, quiet, printchain, orig=None):
    if orig is None:
        orig = checksum

    parents = tardis.getChecksumsByBasis(checksum)
    for data in parents:
        parent = data[0]
        print(f"---- {colored(orig, 'red')} -> {colored(parent, 'red')}")
        printFileInfo(parent, bset, tardis, crypto, quiet)
        if printchain:
            printChainInfo(parent, tardis)
        printParentInfo(parent, tardis, crypto, bset, quiet, printchain, orig)
        print("")

def main():
    global logger
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('')
    args = processArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog)

    tardis, _, crypto = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname, args.dbdir)

    if isinstance(args.backup, str) and args.backup.lower() == 'any':
        bset = None
    elif args.backup is not None:
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

    for i in data:
        cprint(f"---- {i}:", 'yellow')
        try:
            printFileInfo(i, bset, tardis, crypto, args.quiet)
            if args.chain:
                printChainInfo(i, tardis)
            if args.inchain:
                printParentInfo(i, tardis, crypto, bset, args.quiet, args.chain)

        except Exception as e:
            print("Caught exception: " + str(e))


if __name__ == "__main__":
    main()
