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

import time
import sys
import argparse
import magic
import os
import io
import json

import Tardis
from Tardis import Util
from Tardis import TardisCrypto
from Tardis import Config
from Tardis import CacheDir
from Tardis import CompressedBuffer

args = None

def processArgs():
    parser = argparse.ArgumentParser(description='Check contents of the DB against the file system', fromfile_prefix_chars='@', formatter_class=Util.HelpFormatter, add_help=False)

    (_, remaining) = Config.parseConfigOptions(parser)

    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    parser.add_argument('--input', '-i', default=None, dest='input', required=True, type=argparse.FileType('r'), help='Input file')

    #parser.add_argument('--verbose', '-v',  action='count', default=0, dest='verbose',                  help='Increase the verbosity')
    parser.add_argument('--version',        action='version', version='%(prog)s ' + Tardis.__versionstring__,    help='Show the version')
    parser.add_argument('--help', '-h',     action='help')

    return parser.parse_args(remaining)

def main():
    global args
    args = processArgs()

    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog, prompt="Password for %s: " % (args.client))
    (tardis, cache, crypt) = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname, args.dbdir)

    allData = json.load(args.input)
    sizes = allData['size']
    for i in sizes:
        checksum = i[0]
        actualSize = i[2]
        tardis.conn.execute("UPDATE Checksums SET DiskSize = :size WHERE Checksum = :cksum", {'size': actualSize, 'cksum': checksum })

    tardis.conn.commit()

    return 0

if __name__ == "__main__":
    sys.exit(main())
