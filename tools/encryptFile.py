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

import argparse, logging
import os.path
import os
import uuid
import json
import shutil
import traceback

import progressbar

from Tardis import Util, Config, CompressedBuffer

logger = None

class FileSender:
    def __init__(self, output):
        if isinstance(output, str):
            self.output = open(output, "wb")
        else:
            self.output = output

    def sendMessage(self, message):
        if not isinstance(message, dict):
            self.output.write(message)

def processArgs():
    parser = argparse.ArgumentParser(description='Encrypt files for a backup database', add_help = False)

    (_, remaining) = Config.parseConfigOptions(parser)
    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    parser.add_argument('--output', '-o', dest='output', required=True, help="Output directory")
    parser.add_argument('--json', '-j', default=None, dest='input', help='JSON input file')
    parser.add_argument('--signature', '-s', default=False, action='store_true', dest='signature', help='Generate signature file')
    parser.add_argument('--compress-data',  '-Z',   dest='compress', const='zlib', default=None, nargs='?', choices=CompressedBuffer.getCompressors(),
                        help='Compress files')
    parser.add_argument('names',          nargs='*', help="List of pathnames to decrypt")
    parser.add_argument('--help', '-h',   action='help')

    Util.addGenCompletions(parser)

    args = parser.parse_args(remaining)

    return args

def processFile(outdir, crypto, name, compress='none', signature=False):
    outname = str(uuid.uuid1())
    outpath = os.path.join(outdir, outname)
    with open(outpath, "wb") as outfile:
        s = FileSender(outfile)
        with open(name, "rb") as infile:
            size, ck, sig = Util.sendData(s, infile, crypto.getContentEncryptor(), hasher=crypto.getHash(), signature=True, compress=compress)
    newpath = os.path.join(outdir, ck)
    print(name, size, ck, outpath)
    os.rename(outpath, newpath)

    if signature:
        outpath = os.path.join(outdir, ck + ".sig")
        with open(outpath, "wb") as sigfile:
            shutil.copyfileobj(sig, sigfile)

def main():
    global logger
    progressbar.streams.wrap_stderr()
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('')
    args = processArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog, allowNone=False)

    _, _, crypto, _ = Util.setupDataConnection(args.repo, password, args.keys)

    if args.input:
        files = json.load(open(args.input, 'r', encoding='utf8'))
        for x in files:
            try:
                processFile(args.output, crypto, x, args.compress, args.signature)
            except Exception as e:
                print(f"----> {str(e)} Processing {files[x]}")
                traceback.print_exc()

    for name in args.names:
        try:
            processFile(args.output, crypto, name, args.compress, args.signature)
        except Exception as e:
            print(f"----> {str(e)} Processing {name}")
            traceback.print_exc()


if __name__ == "__main__":
    main()
