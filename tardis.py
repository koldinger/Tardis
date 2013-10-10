#! /usr/bin/env python
# coding: latin1

import os, sys
import fnmatch
from stat import *
import json
import argparse

excludeFile         = ".tardis-excludes"
localExcludeFile    = ".tardis-local-excludes"
globalExcludeFile   = "/etc/tardis/excludes"

globalExcludes      = []
verbosity           = 0
version             = "0.1"

stats = { 'dirs' : 0, 'files' : 0, 'links' : 0, 'messages' : 0, 'bytes' : 0 }

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

def sendMessage(message):
    x = json.dumps(message)
    if verbosity > 1:
        print json.dumps(message, indent=4, sort_keys=True)
    stats['messages'] += 1
    stats['bytes'] += len(x)
    return

def processDir(top, excludes=[]):
    if verbosity:
        print "Dir: %s Excludes: %s" %(top, excludes)
    s = os.stat(top)
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
    localExcludes = list(excludes)

    # Add a list of local files to exclude.  These won't get passed to lower directories
    lexFile = os.path.join(top, excludeFile)
    try:
        with open(lexFile) as f:
            localExcludes.extend( [x.rstrip('\n') for x in f.readlines()] )
    except:
        pass

    dir = {}
    files = []
    dir['message']  = 'DIR'
    dir['files']    = files
    dir['name']     = top
    dir['inode']    = s.st_ino

    subdirs = []
    for f in filelist(top, localExcludes):
        pathname = os.path.join(top, f)
        try:
            s = os.stat(pathname)
            mode = s.st_mode
            if S_ISLNK(mode):
                stats['links'] += 1
                file = {}
                file['name'] = f
                file['link'] = os.readlink(f)
                files.append(file)
            elif S_ISREG(mode) or S_ISDIR(mode):
                stats['files'] += 1
                file = {}
                file['name']    = unicode(f.decode('utf8', 'ignore'))
                file['dir']     = S_ISDIR(mode)
                file['inode']   = s.st_ino
                file['nlinks']  = s.st_nlink
                file['size']    = s.st_size
                file['mtime']   = s.st_mtime
                file['mode']    = s.st_mode
                file['uid']     = s.st_uid
                file['gid']     = s.st_gid
                files.append(file)
                if S_ISDIR(mode):
                    subdirs.append(pathname)
            else:
                # Unknown file type, print a message
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
        (message, subdirs, subexcludes) = processDir(top, excludes)

        sendMessage(message)
        handleAckDir()

        # Make sure we're not at maximum depth
        if depth != 1:
            for pathname in subdirs:
                recurseTree(pathname, newdepth, subexcludes)

    except (IOError, OSError) as e:
        print e


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Tardis Backup Client')

    parser.add_argument('--verbose', '-v', action='count', dest='verbose', help='Increase the verbosity')
    parser.add_argument('--server', '-s', dest='server', default='localhost', help='Set the destination server')
    parser.add_argument('--port', '-p', type=int, dest='port', default=9999, help='Set the destination server port')
    parser.add_argument('--maxdepth', '-d', type=int, dest='maxdepth', default=0, help='Maximum depth to search')
    parser.add_argument('--stats', action='store_true', dest='stats', help='Print stats about the transfer')
    parser.add_argument('--version', action='version', version='%(prog)s ' + version, help='Show the version')
    parser.add_argument('directories', nargs='*', default='.', help="List of files to sync")

    args = parser.parse_args()
    print args

    verbosity=args.verbose

    for x in args.directories:
        recurseTree(x, depth=args.maxdepth)

    if args.stats:
        print stats
