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

from Tardis import Util, Config 
import argparse
import logging

from icecream import ic

def computeChecksum(name, crypto):
    with open(name, "rb") as file:
        data = file.read()
        hash = crypto.getHash()
        hash.update(data)
        return hash.hexdigest()

def process_args():
    parser = argparse.ArgumentParser(description="Generate checksums from files for a specific job", add_help=True)

    (_, remaining) = Config.parseConfigOptions(parser)

    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)
    parser.add_argument('files', nargs='*', help='List of files to print')

    Util.addGenCompletions(parser)

    return parser.parse_args(remaining)

def main():
    args = process_args()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog, f"Password for {args.client}")
    logging.basicConfig()

    (_, _, crypto) = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname, args.dbdir)

    maxlen = max(map(len, args.files))

    for i in args.files:
        hash = computeChecksum(i, crypto)
        print(f"{i:{maxlen}} :\t{hash}")

if __name__ == "__main__":
    main()
