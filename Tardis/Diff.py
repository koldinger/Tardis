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

    parser.add_argument("--database", "-D", help="Path to database directory (Default: %(default)s)", dest="database", default=database)
    parser.add_argument("--dbname", "-N",   help="Name of the database file (Default: %(default)s)", dest="dbname", default=dbname)
    parser.add_argument("--client", "-C",   help="Client to process for (Default: %(default)s)", dest='client', default=hostname)

    parser.add_argument("--backup", '-b',   nargs='+', dest='backup', default=[current], help="Backup set(s) to use (Default: %(default)s)")

    pwgroup = parser.add_mutually_exclusive_group()
    pwgroup.add_argument('--password', '-P',        dest='password', default=None, nargs='?', const=True,       help='Encrypt files with this password')
    pwgroup.add_argument('--password-file', '-F',   dest='passwordfile', default=None,                          help='Read password from file.  Can be a URL (HTTP/HTTPS or FTP)')
    pwgroup.add_argument('--password-prog',         dest='passwordprog', default=None,                          help='Use the specified command to generate the password on stdout')

    parser.add_argument('--crypt',                  dest='crypt',   default=True, action=Util.StoreBoolean,     help='Are files encrypted, if password is specified. Default: %(default)s')
    parser.add_argument('--keys',                   dest='keys',    default=None,                               help='Load keys from file.')

    parser.add_argument('--color',                  dest='color',   default=isatty, action=Util.StoreBoolean,   help='Use colors')

    diffgroup = parser.add_mutually_exclusive_group()
    diffgroup.add_argument('--unified', '-u',  dest='unified', type=int, default=0, nargs='?', const=3,         help='Generate unified diff')
    diffgroup.add_argument('--context', '-c',  dest='context', type=int, default=5, nargs='?', const=5,         help='Generate context diff')
    diffgroup.add_argument('--ndiff', '-n',    dest='ndiff',   default=False, action='store_true',              help='Generate NDiff style diff')

    parser.add_argument('--reduce-path', '-R',  dest='reduce',  default=0, const=sys.maxint, type=int, nargs='?',   metavar='N',
                        help='Reduce path by N directories.  No value for "smart" reduction')

    parser.add_argument('--recurse', '-r',      dest='recurse', default=False, action=Util.StoreBoolean, help='Recurse into directories.  Default: %(default)s');
    parser.add_argument('--list', '-l',         dest='list', default=False, action=Util.StoreBoolean, help='Only list files that differ.  Do not show diffs.  Default: %(default)s')

    parser.add_argument('--verbose', '-v',  action='count', dest='verbose', default=0, help='Increase the verbosity')
    parser.add_argument('--version',        action='version', version='%(prog)s ' + Tardis.__versionstring__, help='Show the version')

    parser.add_argument('files',            nargs='+', default=None,                 help="File to diff")

    args = parser.parse_args()

    #print args
    return args

def setupLogging(verbosity):
    global logger
    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    loglevel = levels[verbosity] if verbosity < len(levels) else logging.DEBUG
    logging.basicConfig(level=loglevel)
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
            elif c == '?' or c == '*':
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
        if args.list:
            color = 'yellow' if args.color else 'white'
            termcolor.cprint('File {} (versions {} and {}) differ.'.format(name, then, now), color)
            break
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
                logger.debug("Using time: %s", time.asctime(then))
                bsetInfo = db.getBackupSetInfoForTime(timestamp)
                if bsetInfo and bsetInfo['backupset'] != 1:
                    bset = bsetInfo['backupset']
                    logger.debug("Using backupset: %s %d for %s", bsetInfo['name'], bsetInfo['backupset'], bset)
                else:
                    # Weed out the ".Initial" set
                    logger.critical("No backupset at date: %s (%s)", bset, time.asctime(then))
                    bsetInfo = None
            else:
                logger.critical("Could not parse string: %s", bset)
    return bsetInfo

def getFileInfo(path, bset, tardis, crypt, reducePath):
    p = Util.reducePath(tardis, bset, path, reducePath, crypt)
    e = crypt.encryptPath(p) if crypt else p
    info = tardis.getFileInfoByPath(e, bset)
    return info, p


def diffDir(path, regenerator, bsets, tardis, crypt, reducePath, now, then, recurse=True):
    # Collect the first directory contents
    (info1, p1) = getFileInfo(path, bsets[0]['backupset'], tardis, crypt, reducePath)
    entries1 = tardis.readDirectory((info1['inode'], info1['device']))
    names1 = ([x['name'] for x in entries1])
    if crypt:
        names1 = map(crypt.decryptFilename, names1)
    names1 = map(lambda x: x.decode('utf-8'), names1)
    names1 = sorted(names1)

    if bsets[1]:
        (info2, p2) = getFileInfo(path, bsets[1]['backupset'], tardis, crypt, reducePath)
        entries2 = tardis.readDirectory((info2['inode'], info2['device']))
        names2 = [x['name'] for x in entries2]
        if crypt:
            names2 = map(crypt.decryptFilename, names2)
        names2 = map(lambda x: x.decode('utf-8'), names2)
        names2 = sorted(names2)
    else:
        names2 = sorted(os.listdir(path))

    for i in names1:
        if i in names2:
            logger.info('Diffing %s', os.path.join(path, i))
            diffFile(os.path.join(path, i), regenerator, bsets, tardis, crypt, reducePath, True, now, then)
        else:
            logger.info('%s in %s, not in %s', os.path.join(path, i), bsets[0]['name'], 'other')

    for i in names2:
        if i not in names1:
            logger.info('%s in %s, not in %s', os.path.join(path, i), 'other', bsets[0]['name'])

def diffFile(fName, regenerator, bsets, tardis, crypt, reducePath, recurse, now, then):
    """
    Diff two files, either both from the database, or one from the database, and one from the 
    actual filesystem
    """
    path = os.path.abspath(fName)

    # Process the first file
    (info1, p1) = getFileInfo(path, bsets[0]['backupset'], tardis, crypt, reducePath)
    if info1:
        dir1 = info1['dir']
    else:
        logger.error("%s does not exist in backupset %s", path, bsets[0]['name'])
        return

    if bsets[1] is not None:
        #  if bsets[1], then we're looking into two in the backup.
        #  Process the second one
        (info2, p2) = getFileInfo(path, bsets[1]['backupset'], tardis, crypt, reducePath)
        if info2:
            dir2 = info1['dir']
        else:
            logger.error("%s does not exist in backupset %s", path, bsets[1]['name'])
            return
    else:
        dir2 = os.path.isdir(path)

    if dir1 != dir2:
        logger.error("%s Is directory in one, but not other", path)
        return
    elif dir1:
        logger.info("%s is a directory", path)
        if args.recurse:
            diffDir(path, regenerator, bsets, tardis, crypt, reducePath, now, then)
        return
    else:
        logger.debug("Recovering %d %s", bsets[0]['backupset'], path)
        #f1 = regenerator.recoverFile(p1, bsets[0]['backupset'])
        f1 = regenerator.recoverChecksum(info1['checksum'])
        if not f1:
            logger.error("Could not open %s (%s) in backupset %s (%d)", path, p1, bsets[0]['name'], bsets[0]['backupset'])
            return

        if bsets[1] is not None:
            logger.debug("Recovering %d %s", bsets[1]['backupset'], path)
            f2 = regenerator.recoverChecksum(info2['checksum'])
            if not f2:
                logger.error("Could not open %s (%s) in backupset %s (%d)", path, p2, bsets[1]['name'], bsets[1]['backupset'])
                return
        else:
            logger.debug("Opening %s", path)
            try:
                f2 = file(path, "rb")
            except IOError as e:
                logger.error("Could not open %s: %s", path, str(e))
                return

    runDiff(f1, f2, fName, then, now)

def main():
    try:
        parseArgs()
        setupLogging(args.verbose)

        if len(args.backup) > 2:
            logger.error(args.backup)
            logger.error("Too many backups (%d) specified.  Only one or two allowed", len(args.backup))
            sys.exit(1)

        password = Util.getPassword(args.password, args.passwordfile, args.passwordprog, prompt="Password for %s: " % (args.client))
        args.password = None
        (tardis, cache, crypt) = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname)
        password = None

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
        then = time.asctime(time.localtime(float(bsets[0]['starttime']))) + '  (' + bsets[0]['name'] + ')'
        if bsets[1]:
            now = time.asctime(time.localtime(float(bsets[1]['starttime']))) + '  (' + bsets[1]['name'] + ')'
        else:
            now = time.asctime() + '  (filesystem)'

        for f in args.files:
            if bsets[1] is None and os.path.isdir(f):
                diffDir(f, r, bsets, tardis, crypt, reducePath, now, then, recurse=args.recurse)
            else:
                diffFile(f, r, bsets, tardis, crypt, args.reduce, args.recurse, now, then)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error("Caught exception: %s", str(e))
        logger.exception(e)

if __name__ == "__main__":
    main()
