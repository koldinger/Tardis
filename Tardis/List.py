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

import Tardis
import TardisDB
import RemoteDB
import TardisCrypto
import Util
import Defaults

columns = None
columnfmt = None
args = None
curcolor = None
logger = None
backupSets = []

line = ''

colors = {
    'gone'      :  'red',
    'changed'   :  'cyan',
    'moved'     :  'blue',
    'header'    :  'green',
    'name'      :  None,
    'error'     :  'red',
    'default'   :  None
}

def setColors(s):
    global colors
    groups = s.split(':')
    groups = map(str.strip, groups)
    for g in groups:
        x = g.split('=')
        name = x[0]
        c = map(str.strip, x[1].split(','))
        c = map(lambda x: None if x.lower() == 'none' else x, c)
        if len(c) == 1:
            colors[name] = c[0]
        else:
            colors[name] = tuple(c)

def doprint(string='', color=None, eol=False):
    """
    Add some characters to a line to be printed.  If eol is True, print the line and restart.
    Color can either be a color (red, blue, green, etc), or a tuple.
    If it's a tuple, the first element is the color, the second is a background color ('on_white', 'on_blue', etc),
    and any remaining values are attributes ('blink', 'underline') etc.
    See the termcolor package for lists of colors
    """
    global line
    if args.colors and color:
        if isinstance(color, str):
            line += termcolor.colored(string, color)
        else:
            line += termcolor.colored(string, color[0], color[1], attrs=list(color[2:]))
    else:
        line += string

    #print "Line so far: ", line
    if eol:
        print line.rstrip()     # clear out any trailing spaces
        line=''

def flushLine():
    """
    Flush the line out, if there is one being built.
    """
    global line
    if line:
        print line.rstrip()     # clear out any trailing spaces
        line=''

def makeFakeRootInfo():
    fInfos = {}
    fSet = backupSets[0]
    lSet = backupSets[-1]
    for bset in backupSets:
        fInfos[bset['backupset']] = {
            "name"          : '',
            "inode"         : 0,
            "device"        : 0,
            "dir"           : 1,
            "link"          : 0,
            "parent"        : 0,
            "parentdev"     : 0,
            "size"          : 0,
            "mtime"         : 0,
            "ctime"         : 0,
            "atime"         : 0,
            "mode"          : 0755,
            "uid"           : 0,
            "gid"           : 0,
            "nlinks"        : 1,
            "firstset"      : fSet['backupset'],
            "lastset"       : lSet['backupset'],
            "checksum"      : None,
            "chainlength"   : 0,
            "xattrs"        : None,
            "acl"           : None
        }
    return fInfos

def collectFileInfo(filename, tardis, crypt):
    """
    Collect information about a file in all the backupsets
    Note that we sometimes need to reduce the pathlength.  It's done here, on a directory
    by directory basis.
    """
    lookup = crypt.encryptPath(filename) if crypt else filename

    fInfos = {}
    lInfo = None
    if filename == '/':
        fInfos = makeFakeRootInfo()
    else:
        for bset in backupSets:
            temp = lookup
            if args.reduce:
                temp = Util.reducePath(tardis, bset['backupset'], temp, args.reduce)     # No crypt, as we've already run that to get to lookup

            if lInfo and lInfo['firstset'] <= bset['backupset'] <= lInfo['lastset']:
                fInfos[bset['backupset']] = lInfo
            else:
                lInfo = tardis.getFileInfoByPath(temp, bset['backupset'])
                fInfos[bset['backupset']] = lInfo

    return fInfos

def collectDirContents(tardis, dirlist, crypt):
    """
    Build a hash of hashes.  Outer hash is indexed by backupset, inner by filename
    Note: This is very inefficient.  You basically query for the same information over and over.
    Because of this, we use collectDirContents2 instead.  This function is left here for documentation
    purposes primarily.
    """
    contents = {}
    names = set()
    for (bset, finfo) in dirlist:
        x = tardis.readDirectory((finfo['inode'], finfo['device']), bset['backupset'])
        dirInfo = {}
        for y in x:
            name = crypt.decryptFilename(y['name']) if crypt else y['name']
            dirInfo[name] = y
            names.add(name)
        contents[bset['backupset']] = dirInfo
    return contents, names

def collectDirContents2(tardis, dirList, crypt):
    """
    Do the same thing as collectDirContents, just a lot faster, relying on the structure of the DB.
    Create a set of directory "ranges", a range being a set of entries in the dirlist that a: all have
    the same inode, and b: span a contiguous range of backupsets in the backupsets list (ie, if there are 3
    backupsets in the range in backupsets, there also must be the same three entries in the dirlist).  Then
    query any directory entries that exist in here, and span each one over the approriate portions of the
    range.  Repeat for each range.
    """
    contents = {}
    for (x, y) in dirList:
        contents[x['backupset']] = {}
    names = set()
    ranges = []
    dirRange = []
    prev = None
    dirHash = dict([(x['backupset'], y) for (x,y) in dirList])
    # Detect the ranges
    for bset in backupSets:
        d = dirHash.setdefault(bset['backupset'])
        # If we don't have an entry here, the range ends.
        # OR if the inode is different from the previous 
        if prev and ((not d) or (prev['inode'] != d['inode']) or (prev['device'] != d['device'])):
            if len(dirRange):
                ranges.append(dirRange)
                dirRange = []
        if d:
            dirRange.append(bset)
        prev = d
    if len(dirRange):
        ranges.append(dirRange)

    # Now, for each range, populate 
    for r in ranges:
        first = r[0]['backupset']
        last  = r[-1]['backupset']
        dinfo = dirHash[first]
        #print "Reading for (%d, %d) : %d => %d" %(dinfo['inode'], dinfo['device'], first, last)
        x = tardis.readDirectoryForRange((dinfo['inode'], dinfo['device']), first, last)
        for y in x:
            name = crypt.decryptFilename(y['name']) if crypt else y['name']
            names.add(name)
            for bset in r:
                if (y['firstset'] <= bset['backupset'] <= y['lastset']):
                    contents[bset['backupset']][name] = y

    # and return what we've discovered
    return (contents, names)


def getFileNames(contents):
    """
    Extract a list of file names from file contents.  Names will contain a single entry
    for each name encountered.
    """
    names = set()
    for bset in backupSets:
        if bset['backupset'] in contents:
            lnames = set(contents[bset['backupset']].keys())
            names = names.union(lnames)
    return names

def getInfoByName(contents, name):
    """
    Extract a list of fInfos corresponding to each backupset, based on the name list.
    """
    fInfo = {}
    for bset in backupSets:
        if bset['backupset'] in contents:
            d = contents[bset['backupset']]
            f = d.setdefault(name, None)
            fInfo[bset['backupset']] = f
        else:
            fInfo[bset['backupset']] = None

    return fInfo

""" 
Get group and user names.  Very unixy
"""
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

"""
Format time.  If we're less that a year before now, print the time as Jan 12, 02:17, if earlier,
then Jan 12, 2014.  Same as ls.
"""
_now = time.time()
_yearago = _now - (365 * 24 * 3600)
def formatTime(then):
    if then > _yearago:
        fmt = '%b %d %H:%M'
    else:
        fmt = '%b %d, %Y'
    return time.strftime(fmt, time.localtime(then))


column = 0

"""
The actual work of printing the data.
"""
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
    if args.chnlen:
        if info and info['chainlength'] is not None:
            chnlen = "%-3d" % int(info['chainlength'])
        else:
            chnlen = ''
    if args.inode:
        if info and info['inode'] is not None:
            inode = "%8d" % int(info['inode'])
        else:
            inode = ''

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
                    size = Util.fmtSize(info['size'], formats=['','KB','MB','GB', 'TB', 'PB'])
                else:
                    size = "%8d" % info['size']
            else:
                size = ''
            doprint('  %9s %-8s %-8s %8s %12s ' % (mode, owner, group, size, mtime), color=colors['name'])
            if args.inode:
                doprint(' %8s ' % (inode))
            if args.cksums:
                doprint(' %32s ' % (cksum))
            if args.chnlen:
                doprint(' %-3s ' % (chnlen))
            doprint('%s' % (name), color, eol=True)
    elif args.cksums or args.chnlen or args.inode:
        doprint(columnfmt % name, color)
        if args.inode:
            doprint(' ' + inode, color=colors['name'])
        if args.cksums:
            doprint(' ' + cksum, color=colors['name'])
        if args.chnlen:
            doprint(' ' + chnlen, color=colors['name'])
        doprint('', eol=True)
    else:
        column += 1
        if column == columns:
            eol = True
            column = 0
        else:
            eol = False
        doprint(columnfmt % name, color, eol=eol)

def printVersions(fInfos, filename):
    """
    Print info about each version of the file that exists
    Doesn't actually do the printing, but calls printit to do it.
    """
    global column
    pInfo = None        # Previous version's info
    lSet  = None
    column = 0

    for bset in backupSets:
        info = fInfos[bset['backupset']]
        color = None
        new = False
        gone = False

        # If there was no previous version, or the checksum has changed, we're new
        if (info is None) and (pInfo is None):
            # file didn't exist here or previously.  Just skip
            continue
        if (info is None) and pInfo is not None:
            # file disappeared.
            color = colors['gone']
            gone = True
        elif (pInfo is None) or (info['checksum'] != pInfo['checksum']) or \
            (args.checktimes and (info['mtime'] != pInfo['mtime'] or info['ctime'] != pInfo['ctime'])):
            color = colors['changed']
            new = True
        elif (info['inode'] != pInfo['inode']):
            color = colors['moved']
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
        
        printit(info, bset['name'], color, gone)

    if args.recent:
        printit(fInfos[lSet['backupset']], lSet['name'], colors['changed'], False)

    flushLine()

def processFile(filename, fInfos, tardis, crypt, depth=0, first=True, fmt='%s', eol=True):
    """
    Collect information about a file, across all the backup sets
    Print a header for the file.
    """

    # Count the number of non-null entries
    numFound = len([i for i in fInfos if fInfos[i] is not None])

    # Print the header
    if args.headers or (numFound == 0) or args.recent or not first:
        color = colors['header'] if first else colors['name']
        doprint(fmt % filename, color)
        if numFound == 0:
            doprint(' Not found', colors['error'])
        if (numFound == 0) or args.versions or eol:
            flushLine()

    if args.versions:
        printVersions(fInfos, filename)

    if depth < args.maxdepth:
        dirs = [(x, fInfos[x['backupset']]) for x in backupSets if fInfos[x['backupset']] and fInfos[x['backupset']]['dir'] == 1]
        if len(dirs):
            (contents, names) = collectDirContents2(tardis, dirs, crypt)
            if not args.hidden:
                names = [n for n in names if not n.startswith('.')]
            (numCols, fmt) = computeColumnWidth(names)
            #(contents, names) = collectDirContents(tardis, dirs, crypt)
            #names = getFileNames(contents)
            column = 0
            #for name in sorted(names, key=str.lower, reverse=args.reverse):
            for name in sorted(names, key=lambda x: x.lower().lstrip('.'), reverse=args.reverse):
                fInfo = getInfoByName(contents, name)
                column += 1
                eol = True if ((column % numCols) == 0) else False
                processFile(name, fInfo, tardis, crypt, depth+1, first=False, fmt=fmt, eol=eol)
            flushLine()

def findSet(name):
    for i in backupSets:
        if i['name'] == name:
            return i['backupset']
    doprint("Could not find backupset %s" % name, color=colors['error'], eol=True)
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
        doprint("Invalid range '%s'" % args.range, color=colors['error'], eol=True)
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
        doprint("Invalid range.  Start must be before end", color=colors['error'], eol=True)
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
        doprint("Invalid range '%s'" % args.daterange, color=colors['error'], eol=True)
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
            doprint("Invalid time: %s" % range[0], color=colors['error'], eol=True)
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
            doprint("Invalid time: %s" % range[1], color=colors['error'], eol=True)
            sys.exit(1)
    else:
        endRange = sys.maxint

    doprint("Starttime: " + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(startTime)), color=colors['header'], eol=True)
    doprint("EndTime:   " + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(endTime)), color=colors['header'], eol=True)

    if startTime > endTime:
        doprint("Invalid time range: end before start", color=colors['error'], eol='True')
        sys.exit(1)

    pruneBackupSets(startRange, endRange)


"""
Given a list of names, compute the columns widths
"""
def computeColumnWidth(names):
    if len(names) == 0:
        return (1, '%s')
    longestName = max(map(len, names))

    if args.columns:
        columns = args.columns
    else:
        if os.isatty(sys.stdout.fileno()):
            height, width = Util.getTerminalSize()
            columns = width / (longestName + 4)
        else:
            columns = 1

    fmt = "%%-%ds  " % (longestName + 2)

    return (columns, fmt)

"""
Calculate display parameters, including creating the list of backupsets that we want to process
"""
def setupDisplay(tardis):
    global columns, columnfmt
    global backupSets

    backupSets = list(tardis.listBackupSets())
    if args.range:
        pruneBackupSetsByRange()
    elif args.daterange:
        pruneBackupSetsByDateRange(tardis)

    bsetNames = map(lambda x: x['name'], backupSets)

    (columns, columnfmt) = computeColumnWidth(bsetNames)

def globPath(path, tardis, crypt, first=0):
    """
    Glob a path.  Only globbs the first 
    """
    logger.debug("Globbing %s", path)
    if not Util.isMagic(path):
        return [path]
    comps = path.split(os.sep)
    results = []
    for i in range(first, len(comps)):
        if Util.isMagic(comps[i]):
            currentPath = os.path.join('/', *comps[:i])
            pattern = comps[i]
            logger.debug("Globbing in component %d of %s: %s %s", i, path, currentPath, pattern)
            # Collect info about the current path (without the globb pattern)
            fInfos = collectFileInfo(currentPath, tardis, crypt)
            # Collect any directories in that poth
            dirs = [(x, fInfos[x['backupset']]) for x in backupSets if fInfos[x['backupset']] and fInfos[x['backupset']]['dir'] == 1]
            # And cons up the names which are in those directories
            (data, names) = collectDirContents2(tardis, dirs, crypt)
            # Filter down any that match
            matches = fnmatch.filter(names, pattern)
            # Put the paths back together
            globbed = sorted([os.path.join('/', currentPath, match, *comps[i+1:]) for match in matches])
            logger.debug("Globbed %s: %s", path, globbed)
            # And repeat.
            for j in globbed:
                results += globPath(j, tardis, crypt, i + 1)
            break

    return  results

def processArgs():
    isatty = os.isatty(sys.stdout.fileno())

    parser = argparse.ArgumentParser(description='List Tardis File Versions', fromfile_prefix_chars='@', formatter_class=Util.HelpFormatter)
    parser.add_argument('--database', '-D', dest='database', default=Defaults.getDefault('TARDIS_DB'),      help="Database to use.  Default: %(default)s")
    parser.add_argument('--client', '-C',   dest='client',   default=Defaults.getDefault('TARDIS_CLIENT'),  help="Client to list on.  Default: %(default)s")

    parser.add_argument('--long', '-l',     dest='long',     default=False, action='store_true',        help='Use long listing format.')
    parser.add_argument('--hidden', '-a',   dest='hidden',   default=False, action='store_true',        help='Show hidden files.')
    parser.add_argument('--reverse', '-r',   dest='reverse',   default=False, action='store_true',      help='Reverse the sort order')
    parser.add_argument('--annotate', '-F', dest='annotate', default=False, action='store_true',        help='Annotate files based on type.')
    parser.add_argument('--human', '-H',    dest='human',    default=False, action='store_true',        help='Format sizes for easy reading')
    parser.add_argument('--maxdepth', '-d', dest='maxdepth', type=int, default=1, nargs='?', const=0,   help='Maxdepth to recurse directories.  0 for none')
    parser.add_argument('--checksums', '-c',dest='cksums',   default=False, action='store_true',        help='Print checksums.')
    parser.add_argument('--chainlen', '-L', dest='chnlen',   default=False, action='store_true',        help='Print chainlengths.')
    parser.add_argument('--inode', '-i',    dest='inode',    default=False, action='store_true',        help='Print inode numbers')
    #parser.add_argument('--full',           dest='full',     default=False, action=Util.StoreBoolean,   help='Use full pathnames in listing. Default: %(default)s')
    parser.add_argument('--versions',       dest='versions', default=True,  action=Util.StoreBoolean,   help='Display versions of files.')
    parser.add_argument('--all',            dest='all',      default=False, action='store_true',        help='Show all versions of a file. Default: %(default)s')
    parser.add_argument('--deletions',      dest='deletions',default=True,  action=Util.StoreBoolean,   help='Show deletions. Default: %(default)s')
    parser.add_argument('--times',          dest='checktimes', default=False, action=Util.StoreBoolean, help='Use file time changes when determining diffs. Default: %(default)s')
    parser.add_argument('--headers',        dest='headers',  default=True,  action=Util.StoreBoolean,   help='Show headers. Default: %(default)s')
    parser.add_argument('--colors',         dest='colors',   default=isatty, action=Util.StoreBoolean,  help='Use colors. Default: %(default)s')
    parser.add_argument('--columns',        dest='columns',  type=int, default=None ,                   help='Number of columns to display')
    parser.add_argument('--dbname',         dest='dbname',   default=Defaults.getDefault('TARDIS_DBNAME'),  help="Name of the database file. Default: %(default)s")
    parser.add_argument('--recent',         dest='recent',   default=False, action=Util.StoreBoolean,   help='Show only the most recent version of a file. Default: %(default)s')
    parser.add_argument('--glob',           dest='glob',    default=False, action=Util.StoreBoolean,    help='Glob filenames')

    parser.add_argument('--reduce',         dest='reduce',  default=0,type=int, const=sys.maxint, nargs='?',    help='Reduce paths by N directories.  No value for smart reduction')
    parser.add_argument('--realpath',       dest='realpath', default=True, action=Util.StoreBoolean,    help='Use the full path, expanding symlinks to their actual path components')

    rangegrp = parser.add_mutually_exclusive_group()
    rangegrp.add_argument('--range',      dest='range',   default=None,                                   help="Use a range of backupsets.  Format: 'Start:End' Start and End can be names or backupset numbers.  Either value can be left off to indicate the first or last set respectively")
    rangegrp.add_argument('--dates',      dest='daterange', default=None,                                 help="Use a range of dates for the backupsets.  Format: 'Start:End'.  Start and End are names which can be intepreted liberally.  Either can be left off to indicate the first or last set respectively")

    passgroup= parser.add_argument_group("Password/Encryption specification options")
    pwgroup = passgroup.add_mutually_exclusive_group()
    pwgroup.add_argument('--password', '-P',dest='password', default=None, nargs='?', const=True,       help='Encrypt files with this password')
    pwgroup.add_argument('--password-file', dest='passwordfile', default=None,                          help='Read password from file')
    pwgroup.add_argument('--password-url',  dest='passwordurl', default=None,                           help='Retrieve password from the specified URL')
    pwgroup.add_argument('--password-prog', dest='passwordprog', default=None,                          help='Use the specified command to generate the password on stdout')

    passgroup.add_argument('--crypt',       dest='crypt',action=Util.StoreBoolean, default=True,        help='Encrypt data.  Only valid if password is set')
    passgroup.add_argument('--keys',        dest='keys', default=None,                                  help='Load keys from file.')

    parser.add_argument('--version',            action='version', version='%(prog)s ' + Tardis.__versionstring__,    help='Show the version')

    parser.add_argument('directories', nargs='*', default='.',                                          help='List of directories/files to list')

    return parser.parse_args()


def main():
    global args, logger
    try:
        args = processArgs()

        FORMAT = "%(levelname)s : %(message)s"
        logging.basicConfig(stream=sys.stderr, format=FORMAT, level=logging.INFO)
        logger = logging.getLogger("")

        setColors(Defaults.getDefault('TARDIS_LS_COLORS'))

        # Load any password info
        password = Util.getPassword(args.password, args.passwordfile, args.passwordurl, args.passwordprog, prompt="Password for %s: " % (args.client))
        args.password = None

        (tardis, cache, crypt) = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname)

        setupDisplay(tardis)

        if args.headers:
            doprint("Client: %s    DB: %s" %(args.client, args.database), color=colors['name'], eol=True)

        if args.glob:
            directories = []
            for d in args.directories:
                if not Util.isMagic(d):
                    directories.append(d)
                else:
                    directories += globPath(os.path.abspath(d), tardis, crypt)
        else:
            directories = args.directories

        for d in directories:
            d = os.path.abspath(d)
            if args.realpath:
                d = os.path.realpath(d)
            fInfo = collectFileInfo(d, tardis, crypt)
            processFile(d, fInfo, tardis, crypt)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error("Caught exception: %s", str(e))
        logger.exception(e)

if __name__ == "__main__":
    main()
