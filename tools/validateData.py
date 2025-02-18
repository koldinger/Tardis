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
import hmac
import sys

from rich.progress import RenderableColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, MofNCompleteColumn, TaskProgressColumn, Progress
from rich.logging import RichHandler

from Tardis import Regenerator, TardisDB, CacheDir, TardisCrypto, Config, Util
from Tardis.Regenerator import RegenerateException

checked = {}

def parseArgs():
    parser = argparse.ArgumentParser(description='Check backup files for integrity', fromfile_prefix_chars='@', add_help=False)
    (_, remaining) = Config.parseConfigOptions(parser)

    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    parser.add_argument("--authenticate", "-a", dest='authenticate', default=True, action=argparse.BooleanOptionalAction, help="Use internal authentication, Default: %(default)s")
    parser.add_argument("--verbose", "-v", dest='verbosity', action='count', default=0, help="Increase verbosity")
    parser.add_argument("--help", "-h", action='help')
    parser.add_argument(dest='checksums', nargs='*', help="List of checksums to validate.   Blank = all")

    args = parser.parse_args(remaining)
    return  args

def validateFile(cksum, regen, internal, tardis, crypto, logger):
    logger.info("Checking %s", cksum)
    dataLen = 0
    try:
        info = tardis.getChecksumInfo(cksum)
        hash = crypto.getHash()
        f = regen.recoverChecksum(cksum, authenticate=internal)
        while x := f.read(1024 * 1024):
            hash.update(x)
            dataLen += len(x)

        if not hmac.compare_digest(hash.hexdigest(), cksum):
            logger.error(f"{cksum} MAC does not match checksum: {hash.hexdigest()}")
        if dataLen != info['size']:
            logger.error(f"{cksum} size {dataLen} does not match specified size {info['size']}")
    except RegenerateException:
        logger.error(f"{cksum} did not authenticate")
    except Exception as e:
        logger.error("Unexpected exception: %s", str(e))
    
def main():
    args = parseArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog)
    tardis, cache, crypto = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname, args.dbdir)
    logger = Util.setupLogging(args.verbosity, handler=RichHandler(show_time=False, show_path=False))

    regen = Regenerator.Regenerator(cache, tardis, crypto)

    if args.checksums:
        checksums = args.checksums
        numCks = len(checksums)
    else:
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

        for i in checksums:
            nameCol.renderable = i
            validateFile(i, regen, args.authenticate, tardis, crypto, logger)
            progress.advance(ckProgress, 1)


if __name__ == "__main__":
    sys.exit(main())
