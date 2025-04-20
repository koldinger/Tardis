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
import sys
from binascii import hexlify

from Tardis import Regenerator, TardisDB, CacheDir, TardisCrypto, Config, Util
#from Tardis.Regenerator import RegenerateException

from icecream import ic

def parseArgs():
    parser = argparse.ArgumentParser(description='Check backup files for integrity', fromfile_prefix_chars='@', add_help=False)
    (_, remaining) = Config.parseConfigOptions(parser)

    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    parser.add_argument("--verbose", "-v", dest='verbosity', action='count', default=0, help="Increase verbosity")
    parser.add_argument("--help", "-h", action='help')
    parser.add_argument(dest='checksums', nargs='+', help="List of checksums to validate.   Blank = all")

    args = parser.parse_args(remaining)
    return  args

def doWrite(out, data):
    #ic(hexlify(data))
    out.write(data)
    return(len(data))

def main():
    args = parseArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog)
    tardis, cache, crypto = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname, args.dbdir)
    logger = Util.setupLogging(args.verbosity)


    ivSize = crypto.ivLength

    for file in args.checksums:
        try:
            info = tardis.getChecksumInfo(file)
            #ic(info)

            logger.info("Adding digest to %s", file)
            old = file + ".bak"
            cache.move(file, old)
            infile = cache.open(old, "rb")
            outfile = cache.open(file, "wb")

            data = infile.read()
            iv = data[0:ivSize]
            #ic(hexlify(data))
            
            decrypt = crypto.getContentCipher(iv)
            encrypt = crypto.getContentEncryptor(iv)
            plain = decrypt.decrypt(data[ivSize:])

            numBytes = 0

            numBytes += doWrite(outfile, iv)
            ct = encrypt.encrypt(plain)
            numBytes += doWrite(outfile, ct)
            numBytes += doWrite(outfile, encrypt.finish())
            dig = encrypt.digest()
            numBytes += doWrite(outfile, dig)
            #ic(numBytes)

            tardis.updateChecksumFile(file, True, info['size'], None, None, info['compressed'], numBytes, 0)

            infile.close()
            outfile.close()
        except Exception as e:
            logger.error("Got exception processing %s: %s", file, str(e))

        


if __name__ == "__main__":
    sys.exit(main())
