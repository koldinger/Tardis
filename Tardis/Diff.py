# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2016, Eric Koldinger, All Rights Reserved.
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

import os
import os.path
import sys
import difflib
import argparse
import logging
import time

import termcolor
import parsedatetime
import binaryornot.check

import Tardis
import Tardis.Util as Util
import Tardis.Regenerator as Regenerator
import Tardis.Defaults as Defaults
import Tardis.Config as Config

logger = None
args = None

current = Defaults.getDefault('TARDIS_RECENT_SET')

def parseArgs():
    isatty = os.isatty(sys.stdout.fileno())
    global args

    parser = argparse.ArgumentParser(description='Diff files between current and a Tardis backup, or multiple Tardis versions', fromfile_prefix_chars='@', formatter_class=Util.HelpFormatter, add_help=False)
    (args, remaining) = Config.parseConfigOptions(parser)

    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    parser.add_argument("--backup", '-b',   nargs='+', dest='backup', default=[current], help="Backup set(s) to use (Default: %(default)s)")

    parser.add_argument('--color',                  dest='color',   default=isatty, action=Util.StoreBoolean,   help='Use colors')

    diffgroup = parser.add_mutually_exclusive_group()
    diffgroup.add_argument('--unified', '-u',  dest='unified', type=int, default=0, nargs='?', const=3,         help='Generate unified diff')
    diffgroup.add_argument('--context', '-c',  dest='context', type=int, default=5, nargs='?', const=5,         help='Generate context diff')
    diffgroup.add_argument('--ndiff', '-n',    dest='ndiff',   default=False, action='store_true',              help='Generate NDiff style diff')

    parser.add_argument('--reduce-path', '-R',  dest='reduce',  default=0, const=sys.maxint, type=int, nargs='?',   metavar='N',
                        help='Reduce path by N directories.  No value for "smart" reduction')

    parser.add_argument('--binary', '-B',       dest='binary', default=False, action=Util.StoreBoolean, help='Print differences in binary files.  Default: %(default)s')
    parser.add_argument('--recurse', '-r',      dest='recurse', default=False, action=Util.StoreBoolean, help='Recurse into directories.  Default: %(default)s')
    parser.add_argument('--list', '-l',         dest='list', default=False, action=Util.StoreBoolean, help='Only list files that differ.  Do not show diffs.  Default: %(default)s')

    parser.add_argument('--verbose', '-v',  action='count', dest='verbose', default=0, help='Increase the verbosity')
    parser.add_argument('--version',        action='version', version='%(prog)s ' + Tardis.__versionstring__, help='Show the version')
    parser.add_argument('--help', '-h',     action='help')
    parser.add_argument('files',            nargs='+', default=None,                 help="File to diff")

    args = parser.parse_args(remaining)

    #print args
    return args

def setupLogging(verbosity):
    global logger
    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    loglevel = levels[verbosity] if verbosity < len(levels) else logging.DEBUG
    logging.basicConfig(level=loglevel)
    logger = logging.getLogger('')

def setcolor(line):
    if args.color:
        if line:
            c = line[0]
            if c == '-':
                color = 'red'
            elif c == '+':
                color = 'green'
            elif c == '!' or c == '@':
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

def isBinary(lines, numLines = 128):
    lineNo = 0
    numLines = min(numLines, len(lines))
    while lineNo < numLines:
        if binaryornot.check.is_binary_string(lines[lineNo]):
            return True
        lineNo += 1
    return False

def runDiff(f1, f2, name, then, now):
    l1 = f1.readlines()
    l2 = f2.readlines()

    # If we only want to list files, just see if the 
    if args.list and l1 != l2:
        color = 'yellow' if args.color else 'white'
        termcolor.cprint('File {} (versions {} and {}) differs.'.format(name, then, now), color)
        return

    if not args.binary and (isBinary(l1) or isBinary(l2)):
        if l1 != l2:
            color = 'yellow' if args.color else 'white'
            termcolor.cprint('Binary file {} (versions {} and {}) differs.'.format(name, then, now), color)
        return

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
    logger.info("Diffing directory: %s", path)
    # Collect the first directory contents
    (info1, _) = getFileInfo(path, bsets[0]['backupset'], tardis, crypt, reducePath)
    if not info1:
        logger.error("No data available for %s", path)
        return  

    entries1 = tardis.readDirectory((info1['inode'], info1['device']))
    names1 = ([x['name'] for x in entries1])
    if crypt:
        names1 = map(crypt.decryptFilename, names1)
    names1 = map(lambda x: x.decode('utf-8'), names1)
    names1 = sorted(names1)

    if bsets[1]:
        (info2, _) = getFileInfo(path, bsets[1]['backupset'], tardis, crypt, reducePath)
        entries2 = tardis.readDirectory((info2['inode'], info2['device']))
        names2 = [x['name'] for x in entries2]
        if crypt:
            names2 = map(crypt.decryptFilename, names2)
        names2 = map(lambda x: x.decode('utf-8'), names2)
        names2 = sorted(names2)
        otherName = bsets[1]['name']
    else:
        names2 = sorted(os.listdir(path))
        otherName = 'filesystem'

    missing = 'magenta' if args.color else 'white'


    for i in names1:
        if i in names2:
            logger.info('Diffing %s', os.path.join(path, i))
            diffFile(os.path.join(path, i), regenerator, bsets, tardis, crypt, reducePath, True, now, then)
        else:
            termcolor.cprint('{} in {}, not in {}'.format(os.path.join(path, i), bsets[0]['name'], otherName), missing)

    for i in names2:
        if i not in names1:
            termcolor.cprint('{} in {}, not in {}'.format(os.path.join(path, i), otherName, bsets[0]['name']), missing)

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
        (tardis, cache, crypt) = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname, args.dbdir)
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

        r = Regenerator.Regenerator(cache, tardis, crypt)
        then = time.asctime(time.localtime(float(bsets[0]['starttime']))) + '  (' + bsets[0]['name'] + ')'
        if bsets[1]:
            now = time.asctime(time.localtime(float(bsets[1]['starttime']))) + '  (' + bsets[1]['name'] + ')'
        else:
            now = time.asctime() + '  (filesystem)'

        for f in args.files:
            if bsets[1] is None and os.path.isdir(f):
                diffDir(os.path.abspath(f), r, bsets, tardis, crypt, args.reduce, now, then, recurse=args.recurse)
            else:
                diffFile(f, r, bsets, tardis, crypt, args.reduce, args.recurse, now, then)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error("Caught exception: %s", str(e))
        logger.exception(e)

if __name__ == "__main__":
    main()
