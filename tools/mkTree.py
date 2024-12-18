#! /usr/bin/env python3
# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2024, Eric Koldinger, All Rights Reserved.
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
import sys
import json

import msgpack

from Tardis import Defaults, Util, Config

logger = None
MAXDEPTH=16

def makeDict(row):
    if row:
        d = {}
        for i in list(row.keys()):
            x = row[i]
            d[i] = x.decode('utf8') if isinstance(x, bytes) else x
        return d
    return None



#dict_keys(['name', 'inode', 'device', 'dir', 'link', 'parent', 'parentdev', 'size', 'mtime', 'ctime', 'atime', 'mode', 'uid', 'gid', 'nlinks', 'firstset', 'lastset', 'checksum', 'chainlength', 'xattrs', 'acl', 'basis', 'encrypted'])
__keys = ['name', 'link', 'dir', 'size', 'mtime', 'ctime', 'atime', 'mode', 'uid', 'gid', 'nlinks', 'checksum', 'chainlength', 'xattrs', 'acl', 'basis', 'encrypted']
def baseData(entry):
    data = dict((k, entry[k]) for k in __keys if entry[k] is not None)
    return data

def processFile(db, entry):
    data =  baseData(entry)
    if entry['chainlength']:
        chain = db.getChecksumInfoChain(entry['checksum'])[1:]
        cdata = list(c['checksum'] for c in chain)
        data['chain'] = cdata
    return data

def processDir(db, dirEntry, backupset=False, depth=0):
    if depth > args.maxdepth:
        return None
    data = baseData(dirEntry)
    entryData = []
    entries = map(makeDict, db.readDirectory((dirEntry['inode'], dirEntry['device']), current=backupset))
    for entry in entries:
        if entry['dir']:
            x = processDir(db, entry, backupset, depth+1)
        else:
            x = processFile(db, entry)
        entryData.append(x)
    data['entries'] = entryData
    return data

def processArgs():
    parser = argparse.ArgumentParser(description='Generate a tree of file information', add_help = False)

    (_, remaining) = Config.parseConfigOptions(parser)
    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    parser.add_argument("--backup", "-b", help="Backup set to use.  Default: %(default)s", dest='backup', default=Defaults.getDefault('TARDIS_RECENT_SET'))
    parser.add_argument('--output', '-o', dest='output', type=argparse.FileType('w'), default=sys.stdout, help='Output file')
    parser.add_argument('--maxdepth', '-d', dest='maxdepth', default=sys.maxsize, type=int, help='Maximum depth to go')
    parser.add_argument('--json', '-j', dest='json', default=False, type=bool, const='True', nargs='?', help='Output in JSON format')
    #parser.add_argument('--compress', '-Z', type=bool, dest='compress', default=False, const=True, nargs="?", help='Compress output using zstd')

    parser.add_argument('--help', '-h',     action='help')

    Util.addGenCompletions(parser)

    args = parser.parse_args(remaining)

    return args

def main():
    global logger, args
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('')

    args = processArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog, allowNone=True)

    db, _, _ = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname, args.dbdir)

    bsetInfo = Util.getBackupSet(db, args.backup)
    if bsetInfo:
        bset = bsetInfo['backupset']
    else:
        logger.critical("No backupset at for name: %s", args.backup)
        sys.exit(1)

    #if args.compress:
    #    zstd = zstandard.ZstdCompressor()
    #    out = zstd.stream_writer(args.output)
    #else:
    #    out = args.output

    info = makeDict(bsetInfo)
    data = []

    root = map(makeDict, db.readDirectory((0, 0), bset))
    for entry in root:
        data.append(processDir(db, entry, bset))
    info['files'] = data

    if args.json:
        json.dump(info, args.output, indent=0)
    else:
        msgpack.dump(info, args.output)

if __name__ == "__main__":
    main()
