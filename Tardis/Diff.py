# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2015, Eric Koldinger, All Rights Reserved.
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

import os, os.path
import sys
import difflib
import argparse
import logging
import urlparse
import time

import termcolor
import parsedatetime

import Tardis
import Util
import TardisDB
import TardisCrypto
import Regenerate
import CacheDir
import Defaults

args = None

current = Defaults.getDefault('TARDIS_RECENT_SET')

def parseArgs():
    isatty = os.isatty(sys.stdout.fileno())
    global args
    database = Defaults.getDefault('TARDIS_DB')
    hostname = Defaults.getDefault('TARDIS_CLIENT')
    dbname   = Defaults.getDefault('TARDIS_DBNAME')

    parser = argparse.ArgumentParser(description="Diff files in Tardis", formatter_class=Util.HelpFormatter)

    #parser.add_argument("--checksum", "-c", help="Use checksum instead of filename", dest='cksum', action='store_true', default=False)

    parser.add_argument("--database", "-d", help="Path to database directory (Default: %(default)s)", dest="database", default=database)
    parser.add_argument("--dbname", "-N",   help="Name of the database file (Default: %(default)s)", dest="dbname", default=dbname)
    parser.add_argument("--client", "-C",   help="Client to process for (Default: %(default)s)", dest='client', default=hostname)

    parser.add_argument("--backup",       nargs='+', dest='backup', default=[current], help="Backup set(s) to use")

    pwgroup = parser.add_mutually_exclusive_group()
    pwgroup.add_argument('--password',      dest='password', default=None, nargs='?', const=True,   help='Encrypt files with this password')
    pwgroup.add_argument('--password-file', dest='passwordfile', default=None,      help='Read password from file')
    pwgroup.add_argument('--password-url',  dest='passwordurl', default=None,       help='Retrieve password from the specified URL')
    pwgroup.add_argument('--password-prog', dest='passwordprog', default=None,      help='Use the specified command to generate the password on stdout')

    parser.add_argument('--crypt',          dest='crypt', default=True, action=Util.StoreBoolean, help='Are files encyrpted, if password is specified. Default: %(default)s')
    parser.add_argument('--color',          dest='color', default=isatty, action=Util.StoreBoolean, help='Use colors')

    diffgroup = parser.add_mutually_exclusive_group()
    diffgroup.add_argument('--unified', '-u',  dest='unified', type=int, default=0, nargs='?', const=3,          help='Generate unified diff')
    diffgroup.add_argument('--context', '-c',  dest='context', type=int, default=5, nargs='?', const=5,          help='Generate context diff')
    diffgroup.add_argument('--ndiff', '-n',    dest='ndiff',   default=False, action='store_true',               help='Generate NDiff style diff')

    parser.add_argument('--reduce-path', '-R',  dest='reduce',  default=0, const=sys.maxint, type=int, nargs='?',   metavar='N',
                        help='Reduce path by N directories.  No value for "smart" reduction')

    parser.add_argument('--verbose', '-v', action='count', dest='verbose', help='Increase the verbosity')
    parser.add_argument('--version',            action='version', version='%(prog)s ' + Tardis.__versionstring__, help='Show the version')
    parser.add_argument('files',    nargs='+', default=None,                 help="File to diff")

    args = parser.parse_args()

    #print args
    return args

def setupLogging():
    global logger
    logging.basicConfig(level=logging.WARNING)
    logger = logging.getLogger('')
    pass

def setupFiles(filename, cache, db, crypt):
    pass

def setcolor(line):
    if args.color:
        if line:
            c = line[0]
            if c == '-':
                color = 'red'
            elif c == '+':
                color = 'green'
            elif c == '!':
                color = 'yellow'
            elif c == '?':
                color = 'cyan'
            else:
                color = 'white'
        else:
            color = 'white'
    else:
        color = 'white'

    return color

def runDiff(f1, f2, name, then, now):
    l1 = f1.readlines()
    l2 = f2.readlines()
    #l1 = map(str.rstrip, l1)
    #l2 = map(str.rstrip, l2)

    if args.ndiff:
        diffs = difflib.ndiff(l1, l2)
    elif args.unified:
        diffs = difflib.unified_diff(l1, l2, name, name, then, now, n = args.unified)
    else:
        diffs = difflib.context_diff(l1, l2, name, name, then, now, n = args.context)

    for line in diffs:
        line = line.rstrip()
        termcolor.cprint(line, setcolor(line))

def getBackupSet(db, bset):
    bsetInfo = None
    # First, try as an integer
    try:
        bset = int(bset)
        bsetInfo = db.getBackupSetInfoById(bset)
    except:
        # Else, let's look it up based on name
        if bset  == current:
            bsetInfo = db.lastBackupSet()
        else:
            bsetInfo = db.getBackupSetInfo(bset)
        if not bsetInfo:
            # still nothing, hm, let's try a date format
            cal = parsedatetime.Calendar()
            (then, success) = cal.parse(bset)
            if success:
                timestamp = time.mktime(then)
                logger.info("Using time: %s", time.asctime(then))
                bsetInfo = db.getBackupSetInfoForTime(timestamp)
                if bsetInfo and bsetInfo['backupset'] != 1:
                    bset = bsetInfo['backupset']
                    logger.debug("Using backupset: %s %d for %s", bsetInfo['name'], bsetInfo['backupset'], bset)
                else:
                    # Weed out the ".Initial" set
                    logger.critical("No backupset at date: %s (%s)", args.date, time.asctime(then))
                    bsetInfo = None
            else:
                logger.critical("Could not parse string: %s", bset)
    return bsetInfo

def main():
    try:
        parseArgs()
        setupLogging()

        if len(args.backup) > 2:
            logger.error(args.backup)
            logger.error("Too many backups (%d) specified.  Only one or two allowed", len(args.backup))
            sys.exit(1)

        crypt = None
        password = Util.getPassword(args.password, args.passwordfile, args.passwordurl, args.passwordprog, prompt="Password for %s: " % (args.client))
        args.password = None
        if password:
            crypt = TardisCrypto.TardisCrypto(password, args.client)
        password = None

        token = None
        if crypt:
            token = crypt.createToken()
        if not args.crypt:
            crypt = None

        try:
            loc = urlparse.urlparse(args.database)
            if (loc.scheme == 'http') or (loc.scheme == 'https'):
                tardis = RemoteDB.RemoteDB(args.database, args.client, token=token)
                cache = tardis
            else:
                #print args.database, loc.path, args.client
                baseDir = os.path.join(loc.path, args.client)
                cache = CacheDir.CacheDir(baseDir, create=False)
                dbPath = os.path.join(baseDir, args.dbname)
                tardis = TardisDB.TardisDB(dbPath, token=token)
        except Exception as e:
            logger.critical("Unable to connect to database: %s", str(e))
            logger.exception(e)
            sys.exit(1)

        bsets = []
        for i in args.backup:
            bset = getBackupSet(tardis, i)
            if bset:
                logger.debug("Got backupset %s", str(bset))
                logger.debug("backupset: %s", bset['backupset'])
                bsets.append(bset)
            else:
                sys.exit(1)

        if len(bsets) == 1:
            bsets.append(None)

        r = Regenerate.Regenerator(cache, tardis, crypt)
        then = time.asctime(time.localtime(float(bsets[0]['starttime'])))
        if bsets[1]:
            now = time.asctime(time.localtime(float(bsets[1]['starttime'])))
        else:
            now = time.asctime()

        for f in args.files:
            path = os.path.abspath(f)
            p1 = Util.reducePath(tardis, bsets[0]['backupset'], path, args.reduce, crypt)
            logger.debug("Recovering %d %s", bsets[0]['backupset'], p1)
            f1 = r.recoverFile(p1, bsets[0]['backupset'])
            if not f1:
                logger.error("Could not open %s (%s) in backupset %s (%d)", path, p1, bsets[0]['name'], bsets[0]['backupset'])
                continue

            if bsets[1] is not None:
                p2 = Util.reducePath(tardis, bsets[1]['backupset'], path, args.reduce, crypt)
                logger.debug("Recovering %d %s", bsets[1]['backupset'], p2)
                f2 = r.recoverFile(p2, bsets[1]['backupset'])
                if not f1:
                    logger.error("Could not open %s (%s) in backupset %s (%d)", path, p2, bsets[1]['name'], bsets[1]['backupset'])
                    continue
            else:
                logger.debug("Opening %s", path)
                try:
                    f2 = file(path, "rb")
                except IOError as e:
                    logger.error("Could not open %s: %s", path, str(e))
                    continue

            runDiff(f1, f2, f, then, now)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error("Caught exception: %s", str(e))
        #logger.exception(e)

if __name__ == "__main__":
    main()
