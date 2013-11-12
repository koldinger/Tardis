#! /usr/bin/env python
# coding: latin1

import os, sys
import os.path
import socket
import fnmatch
import socket
from stat import *
import json
import argparse
import time
from Connection import JsonConnection

excludeFile         = ".tardis-excludes"
localExcludeFile    = ".tardis-local-excludes"
globalExcludeFile   = "/etc/tardis/excludes"

globalExcludes      = []
cvsExcludes         = ["RCS", "SCCS", "CVS", "CVS.adm", "RCSLOG", "cvslog.*", "tags", "TAGS", ".make.state", ".nse_depinfo",
                       "*~", "#*", ".#*", ",*", "_$*", "*$", "*.old", "*.bak", "*.BAK", "*.orig", "*.rej", ".del-*", "*.a",
                       "*.olb", "*.o", "*.obj", "*.so", "*.exe", "*.Z", "*.elc", "*.ln", "core", ".svn/", ".git/", ".hg/", ".bzr/"]
verbosity           = 0
version             = "0.1"

conn                = None

stats = { 'dirs' : 0, 'files' : 0, 'links' : 0, 'messages' : 0, 'bytes' : 0, 'backed' : 0 }

def filelist(dir, excludes):
    files = os.listdir(dir)
    for p in excludes:
        remove = [x for x in fnmatch.filter(files, p)]
        if len(remove):
            files = list(set(files) - set(remove))
    for f in files:
        yield f

def handleAckDir():

    return


def processDir(top, excludes=[], max=0):
    if verbosity:
        print "Dir: %s Excludes: %s" %(top, excludes)
    s = os.lstat(top)
    if not S_ISDIR(s.st_mode):
        return

    stats['dirs'] += 1;

    # Process an exclude file which will be passed on down to the receivers
    exFile = os.path.join(top, excludeFile)
    try:
        with open(exFile) as f:
            newExcludes = [x.rstrip('\n') for x in f.readlines()]
            newExcludes.extend(excludes)
            excludes = newExcludes
    except IOError as e:
        pass
    localExcludes = excludes

    # Add a list of local files to exclude.  These won't get passed to lower directories
    lexFile = os.path.join(top, excludeFile)
    try:
        with open(lexFile) as f:
            localExcludes = list(excludes)
            localExcludes.extend( [x.rstrip('\n') for x in f.readlines()] )
    except:
        pass

    dir = {}
    files = []
    dir['message']  = 'DIR'
    dir['files']    = files
    dir['path']     = os.path.abspath(top)
    dir['inode']    = s.st_ino

    subdirs = []
    for f in filelist(top, localExcludes):
        pathname = os.path.join(top, f)
        try:
            s = os.lstat(pathname)
            mode = s.st_mode
            file = {}
            file['name']    = unicode(f.decode('utf8', 'ignore'))
            file['inode']   = s.st_ino
            file['inode']   = s.st_ino
            if S_ISLNK(mode):
                stats['links'] += 1
                file['link'] = os.readlink(pathname)
                files.append(file)
            elif S_ISREG(mode) or S_ISDIR(mode):
                stats['files'] += 1
                stats['backed'] += s.st_size
                file['dir']     = S_ISDIR(mode)
                file['nlinks']  = s.st_nlink
                file['size']    = s.st_size
                file['mtime']   = s.st_mtime
                file['ctime']   = s.st_ctime
                file['atime']   = s.st_atime
                file['mode']    = s.st_mode
                file['uid']     = s.st_uid
                file['gid']     = s.st_gid
                files.append(file)
                if S_ISDIR(mode):
                    subdirs.append(pathname)
            else:
                # Unknown file type, print a message
                if verbose:
                    print 'Skipping %s' % pathname
        except IOError as e:
            print "Error processing %s: %s" % (pathname, str(e))
        except:
            print "Error processing %s: %s" % (pathname, sys.exc_info()[0])

    return (dir, subdirs, excludes)


def recurseTree(top, depth=0, excludes=[]):
    newdepth = 0
    if depth > 0:
        newdepth = depth - 1

    try:
        (message, subdirs, subexcludes) = processDir(top, excludes, max=64)

        conn.send(message)
        response = conn.receive()

        # Make sure we're not at maximum depth
        if depth != 1:
            for pathname in subdirs:
                recurseTree(pathname, newdepth, subexcludes)

    except (IOError, OSError) as e:
        print e


if __name__ == '__main__':

    defaultBackupSet = time.strftime("Backup_%Y-%m-%d-%H:%M:%S")
    parser = argparse.ArgumentParser(description='Tardis Backup Client')

    parser.add_argument('--verbose', '-v', action='count', dest='verbose', help='Increase the verbosity')
    parser.add_argument('--server', '-s', dest='server', default='localhost', help='Set the destination server')
    parser.add_argument('--port', '-p', type=int, dest='port', default=9999, help='Set the destination server port')
    parser.add_argument('--name', '-n', dest='name', default=defaultBackupSet, help='Set the backup name')
    parser.add_argument('--cvs-ignore', action='store_true', dest='cvs', help='Ignore files like CVS')
    parser.add_argument('--maxdepth', '-d', type=int, dest='maxdepth', default=0, help='Maximum depth to search')
    parser.add_argument('--stats', action='store_true', dest='stats', help='Print stats about the transfer')
    parser.add_argument('--version', action='version', version='%(prog)s ' + version, help='Show the version')
    parser.add_argument('directories', nargs='*', default='.', help="List of files to sync")

    args = parser.parse_args()
    #print args

    verbosity=args.verbose

    conn = JsonConnection(args.server, args.port, args.name)

    if verbosity:
        print "Session: %s" % conn.getSessionId()

    for x in args.directories:
        recurseTree(x, depth=args.maxdepth)

    conn.close()

    if args.stats:
        print stats
