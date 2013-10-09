#! /urs/bin/python
import os, sys
from stat import *
import json

def procdir(dir, excludes):
    for i in os.listdir(dir):
        if not i in excludes:
            yield i

def walktree(top, excludes=[]):
    print "Dir: %s Excludes: %s" %(top, excludes)
    s = os.stat(top)
    if not S_ISDIR(s.st_mode):
        return

    t_excludes = os.path.join(top, ".tardis-excludes");
    try:
        with open(t_excludes) as f:
            newExcludes = [x.rstrip('\n') for x in f.readlines()]
            print newExcludes
            newExcludes.extend(excludes)
            print newExcludes
            excludes = newExcludes
    except IOError as e:
        #print e
        pass

    dir = {}
    files = []
    dir['files'] = files
    dir['name'] = top
    dir['inode'] = s.st_ino

    subdirs = []
    for f in procdir(top, excludes):
        pathname = os.path.join(top, f)
        s = os.stat(pathname)
        mode = s.st_mode
        if S_ISDIR(mode):
            subdirs.append(pathname)
        if S_ISREG(mode) or S_ISDIR(mode):
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
    if len(files) > 0:
        #print json.dumps(dir, sort_keys=True, indent=2)
        print json.dumps(dir)

    for pathname in subdirs:
        walktree(pathname, excludes)

if __name__ == '__main__':
    sys.argv.pop(0)
    print sys.argv
    for x in sys.argv:
        walktree(x)
