#! /urs/bin/python

import os, sys
import fnmatch
from stat import *
import json

excludeFile         = ".tardis-excludes"
localExcludeFile    = ".tardis-local-excludes"
globalExcludeFile   = "/etc/tardis/excludes"

globalExcludes      = []

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
    stats['messages'] += 1
    x = json.dumps(message)
    stats['bytes'] += len(x)
    return

def processDir(top, excludes=[]):
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
            if S_ISDIR(mode):
                subdirs.append(pathname)
            if S_ISLNK(mode):
                stats['links'] += 1
                file = {}
                file['name'] = f
                file['link'] = os.readlink(f)
                files.append(file)
            elif S_ISREG(mode) or S_ISDIR(mode):
                stats['files'] += 1
                file = {}
                file['name']    = f
                file['dir']     = S_ISDIR(mode)
                file['inode']   = s.st_ino
                file['nlinks']  = s.st_nlink
                file['size']    = s.st_size
                file['mtime']   = s.st_mtime
                file['mode']    = s.st_mode
                file['uid']     = s.st_uid
                file['gid']     = s.st_gid
                files.append(file)
            else:
                # Unknown file type, print a message
                print 'Skipping %s' % pathname
        except IOError as e:
            print "Error processing %s: %s" % (pathname, str(e))

    return (dir, subdirs, excludes)


def recurseTree(top, excludes=[]):
    try:
        (message, subdirs, subexcludes) = processDir(top, excludes)

        sendMessage(message)
        handleAckDir()

        for pathname in subdirs:
            recurseTree(pathname, subexcludes)

    except (IOError, OSError) as e:
        print e


if __name__ == '__main__':
    sys.argv.pop(0)

    print sys.argv
    for x in sys.argv:
        recurseTree(x)

    print stats
