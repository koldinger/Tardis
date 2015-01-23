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

import TardisDB
import TardisCrypto
import Util

columns = None
columnfmt = None
args = None
curcolor = None
backupSets = []

line = ''

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

def collectDirContents(tardis, dirlist, crypt):
    contents = set()
    for (bset, finfo) in dirlist:
        x = tardis.readDirectory((finfo['inode'], finfo['device']), bset['backupset'])
        if x:
            if args.hidden:
                dir = set([y['name'] for y in x])
            else:
                dir = set([y['name'] for y in x if not y['name'].startswith('.')])
            if crypt:
                dir = set(map(crypt.decryptFilename, dir))
            #print dir
            contents = contents.union(dir)
    #print contents
    return contents

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

def formatTime(then):
    return time.strftime('%b %d, %Y', time.localtime(then))

def printVersions(fInfos):
    pInfo = None        # Previous version's info
    lInfo = None        # all versions info
    column = 0

    for bset in backupSets:
        info = fInfos[bset]
        color = None
        new = False
        gone = False

        # If there was no previous version, or the checksum has changed, we're new
        if (info is None) and (pInfo is None):
            # file didn't exist here or previously.  Just quit
            #print "Nothing to see here"
            continue
        if (info is None) and pInfo is not None:
            # file disappeared.
            #print "Disappeared"
            color = 'red'
            gone = True
        elif (pInfo is None) or (info['checksum'] != pInfo['checksum']):
            #print "New"
            color = 'blue'
            new = True
        elif (info['inode'] != pInfo['inode']):
            #print "Changed inode"
            color = 'cyan'
            new = True
        else:
            pass

        pInfo = info
        if info:
            lInfo = info

        # Skip out if we're not printing something here
        # Bascially we stay if we're print everything or it's a new file
        # OR if we're printing deletions and we disappered
        if not ((args.all or new) or (args.deletions and gone)):
            continue
        
        annotation = ''
        if args.annotate and info is not None:
            if info['dir']:
                annotation = '/'
            elif info['link']:
                annotation = '@'
            elif info['mode'] & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                annotation = '*'

        if column == 0:
            doprint('  ')

        name = bset['name'] + annotation
        if gone:
            name = '(' + name + ')'

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

    if column != 0:
        doprint(eol=True)

def processFile(filename, tardis, crypt, depth=0, first=False):
    lookup = crypt.encryptPath(filename) if crypt else filename

    fInfos = {}
    lInfo = None
    for bset in backupSets:
        if lInfo and lInfo['firstset'] <= bset['backupset'] <= lInfo['lastset']:
            fInfos[bset] = lInfo
        else:
            lInfo = tardis.getFileInfoByPath(lookup, bset['backupset'])
            fInfos[bset] = lInfo
        #print bset, ": ", fInfos[bset]

    numFound = sum([1 for i in fInfos if fInfos[i] is not None])
    if args.headers or (numFound == 0):
        doprint('%s' % filename, 'green')
        if numFound == 0:
            doprint(' Not found', 'red')
        doprint('', eol=True)

    # List of backupsets which contain either 
    #dirs  = [x for x in backupSets if fInfos[x] and fInfos[x]['dir'] == 1]
    #files = [x for x in backupSets if fInfos[x] and fInfos[x]['dir'] == 0]

    #print "Dirs: ", dirs
    #print "Files: ", files

    if args.versions:
        printVersions(fInfos)

    dirs = [(x, fInfos[x]) for x in backupSets if fInfos[x] and fInfos[x]['dir'] == 1]
    if len(dirs) and depth < args.maxdepth:
        dirs  = [(x, fInfos[x]) for x in backupSets if fInfos[x] and fInfos[x]['dir'] == 1]
        contents = sorted(collectDirContents(tardis, dirs, crypt))
        for i in contents:
            processFile(os.path.join(filename, i), tardis, crypt, depth + 1, False)
        #print contents

def doList(tardis, crypt):
    global columns, columnfmt
    global backupSets

    backupSets = list(tardis.listBackupSets())
    bsetNames = map(lambda x: x['name'], backupSets)
    #bsetIDs   = map(lambda x: x['backupset'], backupSets)
    longestName = max(map(len, bsetNames))
    #print len(bsetNames), longestName

    if args.columns:
        columns = args.columns
    else:
        if os.isatty(sys.stdout.fileno()):
            height, width = Util.getTerminalSize()
            columns = width / (longestName + 4)
        else:
            columns = 1

    columnfmt = "%%-%ds  " % (longestName + 2)
    #print "Width: %d Columns %d Columnfmt %s" % (width, columns, columnfmt)

    for d in args.directories:
        #if args.glob:
        #    f = collectGlob(d)
        #    for j in f:
        #        processFile(j, tardis, crypt)
        #else:
        d = os.path.abspath(d)
        processFile(d, tardis, crypt)


def processArgs():
    isatty = os.isatty(sys.stdout.fileno())

    parser = argparse.ArgumentParser(description='List Tardis File Versions', fromfile_prefix_chars='@', formatter_class=Util.HelpFormatter)
    parser.add_argument('--database', '-d', dest='database', default=Util.getDefault('TARDIS_DB'),      help="Database to use.  Default: %(default)s")
    parser.add_argument('--client', '-c',   dest='client',   default=Util.getDefault('TARDIS_CLIENT'),  help="Client to list on.  Default: %(default)s")

    parser.add_argument('--colors',     dest='colors',   default=isatty, action=Util.StoreBoolean,      help='Use colors. Default: %(default)s')
    parser.add_argument('--glob',       dest='glob',     default=True,  action=Util.StoreBoolean,       help='Glob filenames.  Default: %(default)s')
    parser.add_argument('--checksums',  dest='cksums',   default=False, action=Util.StoreBoolean,       help='Print checksums. Default: %(default)s')
    parser.add_argument('--full',       dest='full',     default=False, action=Util.StoreBoolean,       help='Use full pathnames in listing. Default: %(default)s')
    parser.add_argument('--long',       dest='long',     default=False, action=Util.StoreBoolean,       help='Use long listing format. Default: %(default)s')
    parser.add_argument('--deletions',  dest='deletions',default=True,  action=Util.StoreBoolean,       help='Show deletions. Default: %(default)s')
    parser.add_argument('--hidden',     dest='hidden',   default=False, action=Util.StoreBoolean,       help='Show hidden files. Default: %(default)s')
    parser.add_argument('--versions',   dest='versions', default=True,  action=Util.StoreBoolean,       help='Display versions of files.  Most useful when not displaying versions of files and listing directories.')
    parser.add_argument('--recent',     dest='recent',   default=False, action=Util.StoreBoolean,       help='Show only the most recent version of a file. Default: %(default)s')
    parser.add_argument('--annotate',   dest='annotate', default=False, action=Util.StoreBoolean,       help='Default: %(default)s')
    parser.add_argument('--all',        dest='all',      default=False, action=Util.StoreBoolean,       help='Show all versions of a file. Default: %(default)s')
    parser.add_argument('--headers',    dest='headers',  default=True, action=Util.StoreBoolean,        help='Show headers. Default: %(default)s')
    parser.add_argument('--columns',    dest='columns',  type=int, default=None,                        help='Number of columns to display')
    parser.add_argument('--human',      dest='human',    default=False, action=Util.StoreBoolean,       help='Format sizes for easy reading')

    parser.add_argument('--maxdepth',   dest='maxdepth', type=int, default=1,                           help='Maxdepth to recurse directories.  0 for none')
    parser.add_argument('--dbname',     dest='dbname',   default=Util.getDefault('TARDIS_DBNAME'),      help="Name of the database file. Default: %(default)s")

    passgroup= parser.add_argument_group("Password/Encryption specification options")
    pwgroup = passgroup.add_mutually_exclusive_group()
    pwgroup.add_argument('--password',      dest='password', default=None, nargs='?', const=True,       help='Encrypt files with this password')
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

    doList(tardis, crypt)

if __name__ == "__main__":
    main()
