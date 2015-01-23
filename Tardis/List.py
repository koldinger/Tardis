#! /usr/bin/python
import sys
import logging
import os
import os.path
import stat
import termcolor
import argparse
import fnmatch
import pwd
import grp
import time
import parsedatetime

import TardisDB
import TardisCrypto
import Util

columns = None
columnfmt = None
args = None
curcolor = None
backupSets = []

line = ''

"""
Add some characters to a line to be printed.  If eol is True, print the line and restart.
If color is not None, print in that color (if color enabled)
"""
def doprint(string='', color=None, eol=False):
    global line
    if args.colors and color:
        line += termcolor.colored(string, color)
    else:
        line += string

    #print "Line so far: ", line
    if eol:
        print line.rstrip()     # clear out any trailing spaces
        line=''

"""
Collect information about a file in all the backupsets
"""
def collectFileInfo(filename, tardis, crypt):
    lookup = crypt.encryptPath(filename) if crypt else filename

    fInfos = {}
    lInfo = None
    for bset in backupSets:
        if lInfo and lInfo['firstset'] <= bset['backupset'] <= lInfo['lastset']:
            fInfos[bset] = lInfo
        else:
            lInfo = tardis.getFileInfoByPath(lookup, bset['backupset'])
            fInfos[bset] = lInfo
    return fInfos

"""
Build a hash of hashes.  Outer hash is indexed by backupset, inner by filename
"""
def collectDirContents(tardis, dirlist, crypt):
    contents = {}
    for (bset, finfo) in dirlist:
        x = tardis.readDirectory((finfo['inode'], finfo['device']), bset['backupset'])
        dirInfo = {}
        for y in x:
            name = crypt.decryptFilename(y['name']) if crypt else y['name']
            dirInfo[name] = y
        contents[bset] = dirInfo
    return contents

"""
Extract a list of file names from file contents.  Names will contain a single entry
for each name encountered.
"""
def getFileNames(contents):
    names = set()
    for bset in backupSets:
        if bset in contents:
            lnames = set(contents[bset].keys())
            names = names.union(lnames)
    return names

"""
Extract a list of fInfos corresponding to each backupset, based on the name list.
"""
def getInfoByName(contents, name):
    fInfo = {}
    for bset in backupSets:
        if bset in contents:
            d = contents[bset]
            f = d.setdefault(name, None)
            fInfo[bset] = f
        else:
            fInfo[bset] = None

    return fInfo

_groups = {}
_users = {}

def getGroupName(gid):
    if gid in _groups:
        return _groups[gid]
    else:
        group = grp.getgrgid(gid)
        if group:
            name = group.gr_name
            _groups[gid] = name
            return name
        else:
            return None

def getUserId(uid):
    if uid in _users:
        return _users[uid]
    else:
        user = pwd.getpwuid(uid)
        if user:
            name = user.pw_name
            _users[uid] = name
            return name
        else:
            return None

_now = time.time()
_yearago = _now - (365 * 24 * 3600)

def formatTime(then):
    if then > _yearago:
        fmt = '%b %d %H:%M'
    else:
        fmt = '%b %d, %Y'
    return time.strftime(fmt, time.localtime(then))


column = 0

def printit(info, name, color, gone):
    global column
    annotation = ''
    if args.annotate and info is not None:
        if info['dir']:
            annotation = '/'
        elif info['link']:
            annotation = '@'
        elif info['mode'] & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            annotation = '*'
    name = name + annotation
    if gone:
        name = '(' + name + ')'

    if column == 0:
        doprint('  ')

    if args.cksums:
        if info and info['checksum']:
            cksum = info['checksum']
        else:
            cksum = ''

    if args.long:
        if gone:
            doprint('  %s' % (name), color, eol=True)
        else:
            mode = Util.filemode(info['mode'])
            group = getGroupName(info['gid'])
            owner = getUserId(info['uid'])
            mtime = formatTime(info['mtime'])
            if info['size'] is not None:
                if args.human:
                    size = Util.fmtSize(info['size'])
                else:
                    size = "%8d" % info['size']
            else:
                size = ''
            doprint('  %9s %-8s %-8s %8s %12s ' % (mode, owner, group, size, mtime))
            if args.cksums:
                doprint(' %32s ' % (cksum))
            doprint('%s' % (name), color, eol=True)
    elif args.cksums:
        doprint(columnfmt % name, color)
        doprint(cksum, eol=True)
    else:
        column += 1
        if column == columns:
            eol = True
            column = 0
        else:
            eol = False
        doprint(columnfmt % name, color, eol=eol)

def printVersions(fInfos):
    global column
    pInfo = None        # Previous version's info
    lSet  = None
    column = 0

    for bset in backupSets:
        info = fInfos[bset]
        color = None
        new = False
        gone = False

        # If there was no previous version, or the checksum has changed, we're new
        if (info is None) and (pInfo is None):
            # file didn't exist here or previously.  Just skip
            continue
        if (info is None) and pInfo is not None:
            # file disappeared.
            color = 'red'
            gone = True
        elif (pInfo is None) or (info['checksum'] != pInfo['checksum']) or \
            (args.checktimes and (info['mtime'] != pInfo['mtime'] or info['ctime'] != pInfo['ctime'])):
            color = 'blue'
            new = True
        elif (info['inode'] != pInfo['inode']):
            color = 'cyan'
            new = True
        else:
            pass

        pInfo = info
        if new:
            lSet = bset

        # Skip out if we're not printing something here
        # Bascially we stay if we're print everything or it's a new file
        # OR if we're printing deletions and we disappered
        if args.recent or not ((args.all or new) or (args.deletions and gone)):
            continue
        
        name = bset['name']
        printit(info, name, color, gone)

    if args.recent:
        printit(fInfos[lSet], lSet['name'], 'blue', False)

    if column != 0:
        doprint(eol=True)

def processFile(filename, fInfos, tardis, crypt, depth=0, first=False):
    numFound = sum([1 for i in fInfos if fInfos[i] is not None])
    if args.headers or (numFound == 0):
        doprint('%s' % filename, 'green')
        if numFound == 0:
            doprint(' Not found', 'red')
        doprint('', eol=True)

    if args.versions:
        printVersions(fInfos)

    dirs = [(x, fInfos[x]) for x in backupSets if fInfos[x] and fInfos[x]['dir'] == 1]
    if len(dirs) and depth < args.maxdepth:
        contents = collectDirContents(tardis, dirs, crypt)
        #print contents
        names = getFileNames(contents)
        for name in sorted(names):
            if not args.hidden and name.startswith('.'):
                # skip hidden files, ie, starts with .
                continue
            fInfo = getInfoByName(contents, name)
            processFile(name, fInfo, tardis, crypt, depth+1)

def findSet(name):
    for i in backupSets:
        if i['name'] == name:
            return i['backupset']
    doprint("Could not find backupset %s" % name, color='red', eol=True)
    return -1

"""
Prune backupsets to only those in the specified range.
"""
def pruneBackupSets(startRange, endRange):
    global backupSets
    newsets = backupSets[:]
    for i in backupSets:
        if not (startRange <= i['backupset'] <= endRange):
            newsets.remove(i)
    backupSets = newsets

"""
Parse and check the range varables, and prune the set appopriately.
"""
def pruneBackupSetsByRange():
    range = args.range.split(':')
    if len(range) > 2:
        doprint("Invalid range '%s'" % args.range, color='red', eol=True)
        sys.exit(1)
    if range[0]:
        try:
            startRange = int(range[0])
        except ValueError:
            startRange = findSet(range[0])
            if startRange == -1:
                sys.exit(1)
    else:
        startRange = 0

    if range[1]:
        try:
            endRange = int(range[1])
        except ValueError:
            endRange = findSet(range[1])
            if endRange == -1:
                sys.exit(1)
    else:
        endRange = sys.maxint

    if endRange < startRange:
        doprint("Invalid range.  Start must be before end", color='red', eol=True)
        sys.exit(1)

    pruneBackupSets(startRange, endRange)

"""
Parse and check the date range variable, and prune the range appropriately.
"""
def pruneBackupSetsByDateRange(tardis):
    global backupSets
    cal = parsedatetime.Calendar()
    range = args.daterange.split(':')
    if len(range) > 2:
        doprint("Invalid range '%s'" % args.daterange, color='red', eol=True)
        sys.exit(1)
    if range[0]:
        (then, success) = cal.parse(range[0])
        if success:
            startTime = time.mktime(then)
            startSet = tardis.getBackupSetInfoForTime(startTime)
            if startSet:
                # Get the backupset, then add 1.  Backupset will be the LAST backupset before
                # the start time, so 1 larger should be the first backupset after that.
                # I think
                startRange=startSet['backupset'] + 1
            else:
                startRange = 0
        else:
            doprint("Invalid time: %s" % range[0], color='red', eol=True)
            sys.exit(1)
    else:
        startRange = 0

    if range[1]:
        (then, success) = cal.parse(range[1])
        if success:
            endTime = time.mktime(then)
            endSet = tardis.getBackupSetInfoForTime(endTime)
            if endSet:
                endRange = endSet['backupset']
            else:
                endRange = sys.maxint
        else:
            doprint("Invalid time: %s" % range[1], color='red', eol=True)
            sys.exit(1)
    else:
        endRange = sys.maxint

    doprint("Starttime: " + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(startTime)), color='green', eol=True)
    doprint("EndTime:   " + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(endTime)), color='green', eol=True)

    if startTime > endTime:
        doprint("Invalid time range: end before start", color='red', eol='True')
        sys.exit(1)

    pruneBackupSets(startRange, endRange)
        
"""
Calculate display parameters, including creating the list of backupsets that we want to process
"""
def setupDisplay(tardis, crypt):
    global columns, columnfmt
    global backupSets

    backupSets = list(tardis.listBackupSets())
    if args.range:
        pruneBackupSetsByRange()
    elif args.daterange:
        pruneBackupSetsByDateRange(tardis)


    bsetNames = map(lambda x: x['name'], backupSets)
    longestName = max(map(len, bsetNames))

    if args.columns:
        columns = args.columns
    else:
        if os.isatty(sys.stdout.fileno()):
            height, width = Util.getTerminalSize()
            columns = width / (longestName + 4)
        else:
            columns = 1

    columnfmt = "%%-%ds  " % (longestName + 2)

def processArgs():
    isatty = os.isatty(sys.stdout.fileno())

    parser = argparse.ArgumentParser(description='List Tardis File Versions', fromfile_prefix_chars='@', formatter_class=Util.HelpFormatter)
    parser.add_argument('--database', '-D', dest='database', default=Util.getDefault('TARDIS_DB'),      help="Database to use.  Default: %(default)s")
    parser.add_argument('--client', '-C',   dest='client',   default=Util.getDefault('TARDIS_CLIENT'),  help="Client to list on.  Default: %(default)s")

    parser.add_argument('--long', '-l',     dest='long',     default=False, action='store_true',        help='Use long listing format.')
    parser.add_argument('--hidden', '-a',   dest='hidden',   default=False, action='store_true',        help='Show hidden files.')
    parser.add_argument('--annotate', '-F', dest='annotate', default=False, action='store_true',        help='Annotate files based on type.')
    parser.add_argument('--human', '-H',    dest='human',    default=False, action='store_true',        help='Format sizes for easy reading')
    parser.add_argument('--maxdepth', '-d', dest='maxdepth', type=int, default=1, nargs='?', const=0,   help='Maxdepth to recurse directories.  0 for none')
    parser.add_argument('--checksums', '-c',dest='cksums',   default=False, action='store_true',        help='Print checksums.')
    parser.add_argument('--full',           dest='full',     default=False, action=Util.StoreBoolean,   help='Use full pathnames in listing. Default: %(default)s')
    parser.add_argument('--versions',       dest='versions', default=True,  action=Util.StoreBoolean,   help='Display versions of files.')
    parser.add_argument('--all',            dest='all',      default=False, action='store_true',        help='Show all versions of a file. Default: %(default)s')
    parser.add_argument('--deletions',      dest='deletions',default=True,  action=Util.StoreBoolean,   help='Show deletions. Default: %(default)s')
    parser.add_argument('--times',          dest='checktimes', default=False, action=Util.StoreBoolean, help='Use file time changes when determining diffs. Default: %(default)s')
    parser.add_argument('--headers',        dest='headers',  default=True,  action=Util.StoreBoolean,   help='Show headers. Default: %(default)s')
    parser.add_argument('--colors',         dest='colors',   default=isatty, action=Util.StoreBoolean,  help='Use colors. Default: %(default)s')
    parser.add_argument('--columns',        dest='columns',  type=int, default=None ,                   help='Number of columns to display')
    parser.add_argument('--dbname',         dest='dbname',   default=Util.getDefault('TARDIS_DBNAME'),  help="Name of the database file. Default: %(default)s")
    parser.add_argument('--recent',     dest='recent',   default=False, action=Util.StoreBoolean,       help='Show only the most recent version of a file. Default: %(default)s')

    rangegrp = parser.add_mutually_exclusive_group()
    rangegrp.add_argument('--range',      dest='range',   default=None,                                   help="Use a range of backupsets.  Format: 'Start:End' Start and End can be names or backupset numbers.  Either value can be left off to indicate the first or last set respectively")
    rangegrp.add_argument('--dates',      dest='daterange', default=None,                                 help="Use a range of dates for the backupsets.  Format: 'Start:End'.  Start and End are names which can be intepreted liberally.  Either can be left off to indicate the first or last set respectively")

    passgroup= parser.add_argument_group("Password/Encryption specification options")
    pwgroup = passgroup.add_mutually_exclusive_group()
    pwgroup.add_argument('--password', '-p',dest='password', default=None, nargs='?', const=True,       help='Encrypt files with this password')
    pwgroup.add_argument('--password-file', dest='passwordfile', default=None,                          help='Read password from file')
    pwgroup.add_argument('--password-url',  dest='passwordurl', default=None,                           help='Retrieve password from the specified URL')
    pwgroup.add_argument('--password-prog', dest='passwordprog', default=None,                          help='Use the specified command to generate the password on stdout')

    parser.add_argument('directories', nargs='*', default='.',                                          help='List of directories/files to list')

    return parser.parse_args()

def main():
    global args
    args = processArgs()

    FORMAT = "%(levelname)s : %(message)s"
    logging.basicConfig(stream=sys.stderr, format=FORMAT, level=logging.INFO)
    logger = logging.getLogger("")

    # Load any password info
    password = Util.getPassword(args.password, args.passwordfile, args.passwordurl, args.passwordprog)
    args.password = None

    token = None
    crypt = None
    if password:
        crypt = TardisCrypto.TardisCrypto(password)
        token = crypt.createToken()
    password = None

    dbfile = os.path.join(args.database, args.client, args.dbname)
    tardis = TardisDB.TardisDB(dbfile, backup=False, token=token)

    setupDisplay(tardis, crypt)

    for d in args.directories:
        d = os.path.abspath(d)
        fInfo = collectFileInfo(d, tardis, crypt)
        processFile(d, fInfo, tardis, crypt)

if __name__ == "__main__":
    main()
