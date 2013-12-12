#! /usr/bin/env python
# coding: utf8

import os, sys
import os.path
import socket
import fnmatch
from stat import *
import json
import argparse
import time
import base64
import traceback
import subprocess
import hashlib
import tempfile
import cStringIO
from Connection import JsonConnection
from functools import partial

excludeFile         = ".tardis-excludes"
localExcludeFile    = ".tardis-local-excludes"
globalExcludeFile   = "/etc/tardis/excludes"

#encoding            = "binary"
#encoder             = lambda x : return x
#encoder             = lambda x : return x
encoding            = "base64"
encoder             = base64.encodestring
decoder             = base64.decodestring

globalExcludes      = []
cvsExcludes         = ["RCS", "SCCS", "CVS", "CVS.adm", "RCSLOG", "cvslog.*", "tags", "TAGS", ".make.state", ".nse_depinfo",
                       "*~", "#*", ".#*", ",*", "_$*", "*$", "*.old", "*.bak", "*.BAK", "*.orig", "*.rej", ".del-*", "*.a",
                       "*.olb", "*.o", "*.obj", "*.so", "*.exe", "*.Z", "*.elc", "*.ln", "core", ".svn/", ".git/", ".hg/", ".bzr/"]
verbosity           = 0
version             = "0.1"

conn                = None

stats = { 'dirs' : 0, 'files' : 0, 'links' : 0, 'messages' : 0, 'bytes' : 0, 'backed' : 0 }

inodeDB             = {}

def filelist(dir, excludes):
    files = os.listdir(dir)
    for p in excludes:
        remove = [x for x in fnmatch.filter(files, p)]
        if len(remove):
            files = list(set(files) - set(remove))
    for f in files:
        yield f

def sendData(file):
    num = 0
    for chunk in iter(partial(file.read, args.chunksize), ''):
        data = encoder(chunk)
        chunkMessage = { "chunk" : num, "data": data }
        conn.send(chunkMessage)
        stats["bytes"] += len(data)
        num += 1

def processDelta(inode):
    if inode in inodeDB:
        (fileInfo, pathname) = inodeDB[inode]
        message = {
            "message" : "SGR",
            "inode" : inode
            }
        if verbosity > 3:
            print "Send: %s" % str(message)
        conn.send(message)
        sigmessage = conn.receive()
        if verbosity > 3:
            print "Receive: %s" % str(sigmessage)

        oldchksum = sigmessage["checksum"]
        sig = decoder(sigmessage["signature"])

        with tempfile.NamedTemporaryFile() as temp:
            temp.write(sig)
            temp.flush()

            pipe = subprocess.Popen(["rdiff", "delta", temp.name, pathname], stdout=subprocess.PIPE)
            (delta, err) = pipe.communicate()

            temp.close()

        pipe = subprocess.Popen(["rdiff", "signature", pathname], stdout=subprocess.PIPE)
        (sigdelta, err) = pipe.communicate()

        m = hashlib.md5()
        with open(pathname, "rb") as file:
            for chunk in iter(partial(file.read, args.chunksize), ''):
                m.update(chunk)
        checksum = m.hexdigest()

        message = {
            "message": "DEL",
            "inode": inode,
            "size": len(delta),
            "checksum": checksum,
            "basis": oldchksum,
            "encoding": encoding
            }
        if verbosity > 3:
            print "Send: %s" % str(message)
        conn.send(message)

        x = cStringIO.StringIO(delta)
        sendData(x)
        x.close()

        response = conn.receive()
        if verbosity > 3:
            print "Receive %s" % str(response)

        """
        message = {
            "message": "SIG",
            "inode": inode,
            "size": len(sigdelta),
            "checksum": checksum,
            "basis": oldchksum,
            "encoding": encoding
            }
        if verbosity > 3:
            print "Send: %s" % str(message)
        conn.send(message)
        
        x = cStringIO.StringIO(sigdelta)
        sendData(x)
        x.close()
        
        response = conn.receive()
        if verbosity > 3:
            print "Receive %s" % str(response)
        """

def sendContent(inode):
    if inode in inodeDB:
        (fileInfo, pathname) = inodeDB[inode]
        if pathname:
            mode = fileInfo["mode"]
            if S_ISDIR(mode):
                return
            message = {
                "message" : "CON",
                "inode" : inode,
                "size" : fileInfo["size"],
                "encoding" : encoding,
                "pathname" : pathname
                }
            if verbosity > 3:
                print "Send: %s" % str(message)
            conn.send(message)

            if S_ISLNK(mode):
                # It's a link.  Send the contents of readlink
                chunk = os.readlink(pathname)
                data = encoder(chunk)
                chunkMessage = {"data": data }
                conn.send(chunkMessage)
            else:
                with open(pathname, "rb") as file:
                    sendData(file)
            response = conn.receive()
            if verbosity > 3:
                print "Receive %s" % str(response)
    else:
        print "Error: Unknown inode {}".format(inode)

def handleAckDir(message):
    content = message["content"]
    done    = message["done"]
    delta   = message["delta"]
    cksum   = message["cksum"]

    if verbosity > 1: print "Processing AKDIR: Up-to-date: %d New Content: %d Delta: %d ChkSum: %d" % (len(done), len(content), len(delta), len(cksum))
    for i in done:
        del inodeDB[i]

    for i in content:
        if verbosity > 1:
            (x, name) = inodeDB[i]
            if "size" in x:
                size = x["size"]
            else:
                size = 0;
            print "File: [N]: %s %d" % (name, size)
        sendContent(i)
        del inodeDB[i]

    for i in delta:
        if verbosity > 1:
            (x, name) = inodeDB[i]
            print "File: [D]: %s" % (name)
        processDelta(i)
        del inodeDB[i]

    for i in cksum:
        if verbosity > 1:
            (x, name) = inodeDB[i]
            print "File: [C]: %s" % (name)
        # sendChecksum(i)
        del inodeDB[i]

    if verbosity > 1:
        print "----- AckDir complete"

    return

def makeDirHeader(dir):
    pass

def mkFileInfo(dir, name):
    file = None
    pathname = os.path.join(dir, name)
    s = os.lstat(pathname)
    mode = s.st_mode
    if S_ISREG(mode) or S_ISDIR(mode) or S_ISLNK(mode):
        file =  {
            'name':   unicode(name.decode('utf8', 'ignore')),
            'inode':  s.st_ino,
            'dir':    S_ISDIR(mode),
            'nlinks': s.st_nlink,
            'size':   s.st_size,
            'mtime':  s.st_mtime,
            'ctime':  s.st_ctime,
            'atime':  s.st_atime,
            'mode':   s.st_mode,
            'uid':    s.st_uid,
            'gid':    s.st_gid
            }

        inodeDB[s.st_ino] = (file, pathname)
    else:
        if verbosity:
            print "Skipping non standard file: {}".format(pathname)
    return file
    
def processDir(dir, excludes=[], max=0):
    if verbosity:
        print "Dir: {}".format(str(dir))
    if verbosity > 2:
        print "   Excludes: {}".format(str(excludes))
    stats['dirs'] += 1;

    # Process an exclude file which will be passed on down to the receivers
    exFile = os.path.join(dir, excludeFile)
    try:
        with open(exFile) as f:
            newExcludes = [x.rstrip('\n') for x in f.readlines()]
            newExcludes.extend(excludes)
            excludes = newExcludes
    except IOError as e:
        pass
    localExcludes = excludes

    # Add a list of local files to exclude.  These won't get passed to lower directories
    lexFile = os.path.join(dir, excludeFile)
    try:
        with open(lexFile) as f:
            localExcludes = list(excludes)
            localExcludes.extend( [x.rstrip('\n') for x in f.readlines()] )
    except:
        pass

    files = []

    subdirs = []
    for f in filelist(dir, localExcludes):
        try:
            file = mkFileInfo(dir, f)
            if file:
                mode = file["mode"]
                if S_ISLNK(mode):
                    stats['links'] += 1
                elif S_ISREG(mode) or S_ISDIR(mode):
                    stats['files'] += 1
                    stats['backed'] += file["size"]
                if S_ISDIR(mode):
                    subdirs.append(os.path.join(dir, f))
                files.append(file)
        except IOError as e:
            print "Error processing %s: %s" % (os.path.join(dir, f), str(e))
        except:
            print "Error processing %s: %s" % (os.path.join(dir, f), sys.exc_info()[0])
            traceback.print_exc()

    return (files, subdirs, excludes)


def recurseTree(dir, top, depth=0, excludes=[]):
    newdepth = 0
    if depth > 0:
        newdepth = depth - 1

    try:
        s = os.lstat(dir)
        if not S_ISDIR(s.st_mode):
            return

        (files, subdirs, subexcludes) = processDir(dir, excludes, max=64)

        message = {
            'message': 'DIR',
            'path':  os.path.relpath(dir, top),
            'inode':  s.st_ino
        }

        chunkNum = 0
        for x in range(0, len(files), args.dirslice):
            if verbosity > 1:
                print "---- Generating chunk {} ----".format(chunkNum)
            chunkNum += 1
            chunk = files[x : x + args.dirslice]
            message["files"] = chunk
            if verbosity > 1:
                print "---- Sending chunk ----"
                if verbosity > 3:
                    print "Send: %s" % str(message)
            conn.send(message)
            if verbosity > 1:
                print "---- Waiting for ACKDir----"
            response = conn.receive()
            if verbosity > 3:
                print "Receive: %s" % str(response)
            handleAckDir(response)


        # Make sure we're not at maximum depth
        if depth != 1:
            for subdir in sorted(subdirs):
                recurseTree(subdir, top, newdepth, subexcludes)

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
    parser.add_argument('--chunksize', type=int, dest='chunksize', default=16536, help='Chunk size for sending data')
    parser.add_argument('--dirslice', type=int, dest='dirslice', default=100, help='Maximum number of directory entries per message')
    parser.add_argument('--stats', action='store_true', dest='stats', help='Print stats about the transfer')
    parser.add_argument('--version', action='version', version='%(prog)s ' + version, help='Show the version')
    parser.add_argument('directories', nargs='*', default='.', help="List of files to sync")

    args = parser.parse_args()
    #print args

    verbosity=args.verbose

    conn = JsonConnection(args.server, args.port, args.name)

    if verbosity:
        print "Session: %s" % conn.getSessionId()

    # send a fake root directory
    files = []
    message = {
        'message': 'DIR',
        'files':  files,
        'path':  None,
        'inode':  0
        }
    for x in args.directories:
        if x == ".":
            y = os.getcwd()
        else:
            y = os.path.abspath(x)
        (dir, name) = os.path.split(y)
        file = mkFileInfo(dir, name)
        if file:
            files.append(file)

    # and send it.
    if verbosity > 3:
        print "Send: %s" % str(message)
    conn.send(message)
    response = conn.receive()
    if verbosity > 3:
        print "Receive: %s" % str(response)
    handleAckDir(response)

    for x in args.directories:
        recurseTree(x, x, depth=args.maxdepth)

    conn.close()

    if args.stats:
        print stats
