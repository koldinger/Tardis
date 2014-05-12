# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2014, Eric Koldinger, All Rights Reserved.
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

import os, sys
import os.path
import socket
import fnmatch
from stat import *
import json
import argparse
import time
import datetime
import base64
import traceback
import subprocess
import hashlib
import tempfile
import cStringIO
from rdiff_backup import librsync
from Connection import JsonConnection, BsonConnection
from functools import partial

import TardisCrypto

excludeFile         = ".tardis-excludes"
localExcludeFile    = ".tardis-local-excludes"
globalExcludeFile   = "/etc/tardis/excludes"

starttime           = None

encoding            = None
encoder             = None
decoder             = None

purgePriority       = None
purgeTime           = None

globalExcludes      = []
cvsExcludes         = ["RCS", "SCCS", "CVS", "CVS.adm", "RCSLOG", "cvslog.*", "tags", "TAGS", ".make.state", ".nse_depinfo",
                       "*~", "#*", ".#*", ",*", "_$*", "*$", "*.old", "*.bak", "*.BAK", "*.orig", "*.rej", ".del-*", "*.a",
                       "*.olb", "*.o", "*.obj", "*.so", "*.exe", "*.Z", "*.elc", "*.ln", "core", ".svn/", ".git/", ".hg/", ".bzr/"]
verbosity           = 0
version             = "0.1"

ignorectime         = False

conn                = None
args                = None
conn                = None
targetDir           = None
targetStat          = None

cloneDirs           = []
cloneContents       = {}
batchDirs           = []

crypt               = None

stats = { 'dirs' : 0, 'files' : 0, 'links' : 0, 'messages' : 0, 'bytes' : 0, 'backed' : 0 }

inodeDB             = {}

def setEncoder(format):
    if format == 'base64':
        encoding = "base64"
        encoder  = base64.b64encode
        decoder  = base64.b64decode
    elif format == 'bin':
        encoding = "bin"
        encoder = lambda x: x
        decoder = lambda x: x

def filelist(dir, excludes):
    files = os.listdir(dir)
    for p in excludes:
        remove = [x for x in fnmatch.filter(files, p)]
        if len(remove):
            files = list(set(files) - set(remove))
    for f in files:
        yield f

def sendData(file, encrypt, checksum=False):
    """ Send a block of data """
    num = 0
    size = 0
    status = "OK"

    if checksum:
        m = hashlib.md5()
    try:
        for chunk in iter(partial(file.read, args.chunksize), ''):
            if checksum:
                m.update(chunk)
            data = conn.encode(encrypt(chunk))
            chunkMessage = { "chunk" : num, "data": data }
            conn.send(chunkMessage)
            x = len(chunk)
            stats["bytes"] += x
            size += x
            num += 1
    except Exception as e:
        status = "Fail"
    finally:
        message = {"chunk": "done", "size": size, "status": status}
        if checksum:
            ck = m.hexdigest()
            message["checksum"] = m.hexdigest()
        conn.send(message)

    if checksum:
        return ck
    else:
        return None

def processChecksums(inodes):
    """ Generate a delta and send it """
    files = []
    for inode in inodes:
        if inode in inodeDB:
            (fileInfo, pathname) = inodeDB[inode]
            m = hashlib.md5()
            s = os.lstat(pathname)
            mode = s.st_mode
            if S_ISLNK(mode):
                chunk = os.readlink(pathname)
            else:
                with open(pathname, "rb") as file:
                    for chunk in iter(partial(file.read, args.chunksize), ''):
                        m.update(chunk)
            checksum = m.hexdigest()
            files.append({ "inode": inode, "checksum": checksum })
    message = {
        "message": "CKS",
        "files": files
    }

    response = sendAndReceive(message)

    if not response["message"] == "ACKSUM":
        raise Exception
    for i in response["done"]:
        if verbosity > 1:
            if i in inodeDB:
                (x, name) = inodeDB[i]
                print "File: [C]: {}".format(shortPath(name))
        if i in inodeDB:
            del inodeDB[i]
    for i in response["content"]:
        if verbosity > 1:
            if i in inodeDB:
                (x, name) = inodeDB[i]
                if "size" in x:
                    size = x["size"]
                else:
                    size = 0;
                print "File: [N]: {} {}".format(shortPath(name), size)
        sendContent(i)
        if i in inodeDB:
            del inodeDB[i]

def makeEncryptor():
    if crypt:
        iv = crypt.getIV()
        encryptor = crypt.getContentCipher(iv)
        func = lambda x: encryptor.encrypt(crypt.pad(x))
    else:
        iv = None
        func = lambda x: x
    return (func, iv)

def processDelta(inode):
    """ Generate a delta and send it """
    if inode in inodeDB:
        (fileInfo, pathname) = inodeDB[inode]
        message = {
            "message" : "SGR",
            "inode" : inode
        }

        sigmessage = sendAndReceive(message)

        if sigmessage['status'] == 'OK':
            newsig = None
            oldchksum = sigmessage['checksum']

            sigfile = cStringIO.StringIO(conn.decode(sigmessage['signature']))
            delta = librsync.DeltaFile(sigfile, open(pathname, "rb"))

            ### BUG: If the file is being changed, this value and the above may be different.
            m = hashlib.md5()
            filesize = 0
            with open(pathname, "rb") as file:
                for chunk in iter(partial(file.read, args.chunksize), ''):
                    m.update(chunk)
                    filesize += len(chunk)
                if crypt:
                    file.seek(0)
                    newsig = librsync.SigFile(file)
                checksum = m.hexdigest()

                (encrypt, iv) = makeEncryptor()

                message = {
                    "message": "DEL",
                    "inode": inode,
                    "size": filesize,
                    "checksum": checksum,
                    "basis": oldchksum,
                    "encoding": encoding
                }
                if iv:
                    message["iv"] = conn.encode(iv)

                sendMessage(message)
                sendData(delta, encrypt)
                delta.close()
                if newsig:
                    message = {
                        "message" : "SIG",
                        "checksum": checksum
                    }
                if newsig:
                    sendMessage(message)
                    sendData(newsig, lambda x:x)            # Don't bother to encrypt the signature
        else:
            sendContent(inode)

def copyContent(inode):
    (fileInfo, pathname) = inodeDB[inode]
    dest = tempfile.NamedTemporaryFile(delete=False, dir=targetDir)
    mode = fileInfo['mode']
    if S_ISDIR(mode):
        return
    m = hashlib.md5()
    if S_ISLNK(mode):
        data = os.readlink(pathname)
        m.update(data)
        dest.write(data)
        size = len(data)
    else:
        src = open(pathname, 'rb')
        # Now, read the destination and generate the checksum
        # Use the destination file to make sure we have the same data
        size = 0
        for chunk in iter(partial(src.read, args.chunksize), ''):
            dest.write(chunk)
            m.update(chunk)
            size += len(chunk)
        src.close()


    checksum = m.hexdigest()
    os.chown(dest.name, targetStat.st_uid, targetStat.st_gid)

    message = {
        "message"   : "CPY",
        "checksum"  : checksum,
        "inode"     : inode,
        'file'      : dest.name,
        'size'      : size
        }
    sendMessage(message)
    dest.close()

def sendSignature(f):
    pass

def sendContent(inode):
    if inode in inodeDB:
        if targetDir:
            return copyContent(inode)

        checksum = None
        (fileInfo, pathname) = inodeDB[inode]
        if pathname:
            mode = fileInfo["mode"]
            if S_ISDIR(mode):
                return
            (encrypt, iv) = makeEncryptor()
            message = {
                "message" : "CON",
                "inode" : inode,
                "encoding" : encoding,
                "pathname" : pathname
                }
            if iv:
                message["iv"] = conn.encode(iv)
            # Attempt to open the data source
            # Punt out if unsuccessful
            try:
                if S_ISLNK(mode):
                    # It's a link.  Send the contents of readlink
                    #chunk = os.readlink(pathname)
                    x = cStringIO.StringIO(os.readlink(pathname))
                else:
                    x = open(pathname, "rb")
            except IOError as e:
                print "Error: Could not open {}: {}".format(pathname, e)
                return

            # Attempt to send the data.
            try:
                sendMessage(message)
                checksum = sendData(x, encrypt, checksum=True)

                if crypt:
                    x.seek(0)
                    sig = librsync.SigFile(x)
                    message = {
                        "message" : "SIG",
                        "checksum": checksum
                    }
                    sendMessage(message)
                    sendData(sig, lambda x:x)            # Don't bother to encrypt the signature
            except Exception as e:
                print "Caught exception during sending of data {}".format(e)
            finally:
                x.close()
    else:
        print "Error: Unknown inode {}".format(inode)

def handleAckDir(message):
    content = message["content"]
    done    = message["done"]
    delta   = message["delta"]
    cksum   = message["cksum"]

    if verbosity > 2:
        print "Processing ACKDIR: Up-to-date: %3d New Content: %3d Delta: %3d ChkSum: %3d -- %s" % (len(done), len(content), len(delta), len(cksum), shortPath(message['path'], 40))

    for i in done:
        if i in inodeDB:
            del inodeDB[i]

    for i in content:
        if verbosity > 1:
            if i in inodeDB:
                (x, name) = inodeDB[i]
                if "size" in x:
                    size = x["size"]
                else:
                    size = 0;
                print "File: [N]: {} {}".format(shortPath(name), size)
        sendContent(i)
        if i in inodeDB:
            del inodeDB[i]

    for i in delta:
        if verbosity > 1:
			if i in inodeDB:
				(x, name) = inodeDB[i]
				print "File: [D]: {}".format(shortPath(name))
        processDelta(i)
        if i in inodeDB:
            del inodeDB[i]

    # Collect the ACK messages
    if len(cksum) > 0:
        processChecksums(cksum)

    if verbosity > 3:
        print "----- AckDir complete"

    return

def mkFileInfo(dir, name):
    file = None
    pathname = os.path.join(dir, name)
    s = os.lstat(pathname)
    mode = s.st_mode
    if S_ISREG(mode) or S_ISDIR(mode) or S_ISLNK(mode):
        name = unicode(name.decode('utf8', 'ignore'))
        if crypt:
            name = crypt.encryptFilename(name)
        file =  {
            'name':   name,
            'inode':  s.st_ino,
            'dir':    S_ISDIR(mode),
            'link':   S_ISLNK(mode),
            'nlinks': s.st_nlink,
            'size':   s.st_size,
            'mtime':  s.st_mtime,
            'ctime':  s.st_ctime,
            'atime':  s.st_atime,
            'mode':   s.st_mode,
            'uid':    s.st_uid,
            'gid':    s.st_gid,
            'dev':    s.st_dev
            }

        inodeDB[s.st_ino] = (file, pathname)
    else:
        if verbosity:
            print "Skipping special file: {}".format(pathname)
    return file
    
def processDir(dir, dirstat, excludes=[], allowClones=True):
    stats['dirs'] += 1;

    device = dirstat.st_dev

    # Process an exclude file which will be passed on down to the receivers
    newExcludes = loadExcludeFile(os.path.join(dir, excludeFile))
    newExcludes.extend(excludes)
    excludes = newExcludes

    # Add a list of local files to exclude.  These won't get passed to lower directories
    localExcludes = list(excludes)
    localExcludes.extend(loadExcludeFile(os.path.join(dir, localExcludeFile)))

    files = []

    subdirs = []
    for f in filelist(dir, localExcludes):
        try:
            file = mkFileInfo(dir, f)
            if file:
                mode = file["mode"]
                if S_ISLNK(mode):
                    stats['links'] += 1
                elif S_ISREG(mode):
                    stats['files'] += 1
                    stats['backed'] += file["size"]

                if S_ISDIR(mode):
                    if args.crossdev or device == file['dev']:
                        subdirs.append(os.path.join(dir, f))

                files.append(file)
        except IOError as e:
            print "Error processing %s: %s" % (os.path.join(dir, f), str(e))
        except:
            print "Error processing %s: %s" % (os.path.join(dir, f), sys.exc_info()[0])
            traceback.print_exc()

    return (files, subdirs, excludes)

def checkClonable(dir, stat, files, subdirs):
    if (ignorectime is False) and (stat.st_ctime > conn.lastTimestamp):
        return False
    if stat.st_mtime > conn.lastTimestamp:
        return False

    # Now, collect the timestamps of all the files, and determine the maximum
    # If any are greater than the last timestamp, punt
    extend = partial(os.path.join, path)
    if subdirs and len(subdirs):
        times = map(os.lstat, map(extend, subdirs))
        if ignorectime:
            time = max([x.st_mtime for x in times])
        else:
            time = max(map(lambda x: max(x.st_ctime, x.st_mtime), times))
        if time > conn.lastTimestamp:
            return False
    if files and len(files):
        times = map(os.lstat, map(extend, subs))
        if ignorectime:
            time = max([x.st_mtime for x in times])
        else:
            time = max(map(lambda x: max(x.st_ctime, x.st_mtime), times))
        if time > conn.lastTimestamp:
            return False

    return True

def handleAckClone(message):
    if message["message"] != "ACKCLN":
        raise Exception("Expected ACKCLN.  Got {}".format(message["message"]))
    if verbosity > 2:
        print "Processing ACKCLN: Up-to-date: %d New Content: %d" % (len(message['done']), len(message['content']))

    # Process the directories that have changed
    for inode in message["content"]:
        if inode in cloneContents:
            (path, files) = cloneContents[inode]
            if verbosity:
                print "ResyncDir: {}".format(shortPath(path)),
            if len(files) < args.batchdirs:
                if verbosity:
                    print "[Batched]"
                batchDirs.append(makeDirMessage(path, inode, files))
                if len(batchDirs) >= args.batchsize:
                    flushBatchDirs()
            else:
                if verbosity:
                    print
                flushBatchDirs()
                sendDirChunks(path, inode, files)
            del cloneContents[inode]

    # Purge out what hasn't changed
    for inode in message["done"]:
        if inode in cloneContents:
            (path, files) = cloneContents[inode]
            for f in files:
                if f['inode'] in inodeDB:
                    del inodeDB[f['inode']]
            del cloneContents[inode]
        if inode in inodeDB:
            del inodeDB[inode]
        
def sendClones():
    message = {
        'message': 'CLN',
        'clones': cloneDirs
    }
    response = sendAndReceive(message)
    handleAckClone(response)
    del cloneDirs[:]

def flushClones():
    if len(cloneDirs):
        sendClones()

def sendBatchDirs():
    message = {
        'message' : 'BATCH',
        'batch': batchDirs
    }
    if verbosity > 2:
        print "BATCH Starting. {} commands".format(len(batchDirs))

    response = sendAndReceive(message)
    for ack in response['responses']:
        handleAckDir(ack)

    if verbosity > 2:
        print "BATCH Ending."

    del batchDirs[:]

def flushBatchDirs():
    if len(batchDirs):
        sendBatchDirs()

def sendPurge(relative):
    if purgePriority and purgeTime:
        message = {
            'message': 'PRG',
            'priority': purgePriority,
            'time'    : purgeTime,
            'relative': relative
        }

        response = sendAndReceive(message)

def sendDirChunks(path, inode, files):
    message = {
        'message': 'DIR',
        'path':  path,
        'inode':  inode
    }

    chunkNum = 0
    for x in range(0, len(files), args.dirslice):
        if verbosity > 3:
            print "---- Generating chunk {} ----".format(chunkNum)
        chunkNum += 1
        chunk = files[x : x + args.dirslice]
        message["files"] = chunk
        if verbosity > 3:
            print "---- Sending chunk ----"
        response = sendAndReceive(message)
        handleAckDir(response)

def makeDirMessage(path, inode, files):
    message = {
        'files':  files,
        'inode':  inode,
        'path':  path,
        'message': 'DIR',
        }
    return message

def recurseTree(dir, top, depth=0, excludes=[]):
    newdepth = 0
    if depth > 0:
        newdepth = depth - 1

    s = os.lstat(dir)
    if not S_ISDIR(s.st_mode):
        return

    try:
        if verbosity:
            print "Dir: {}".format(shortPath(dir)),
            if verbosity > 2 and len(excludes) > 0:
                print "\n   Excludes: {}".format(str(excludes))

        (files, subdirs, subexcludes) = processDir(dir, s, excludes)

        # Check the max time on all the files.  If everything is before last timestamp, just clone
        cloneable = False
        #print "Checking cloneablity: {} Last {} ctime {} mtime {}".format(dir, conn.lastTimestamp, s.st_ctime, s.st_mtime)
        if (args.clones > 0) and (s.st_ctime < conn.lastTimestamp) and (s.st_mtime < conn.lastTimestamp):
            if len(files) > 0:
                if ignorectime:
                    maxTime = max(x["mtime"] for x in files)
                else:
                    maxTime = max(map(lambda x: max(x["ctime"], x["mtime"]), files))
                #print "Max file timestamp: {} Last Timestamp {}".format(maxTime, conn.lastTimestamp)
            else:
                maxTime = max(s.st_ctime, s.st_mtime)

            if maxTime < conn.lastTimestamp:
                cloneable = True

        if cloneable:
            if verbosity:
                print " [Clone]"

            filenames = sorted([x["name"] for x in files])
            m = hashlib.md5()
            for f in filenames:
                m.update(f.encode('utf8', 'ignore'))

            cloneDirs.append({'inode':  s.st_ino, 'numfiles':  len(files), 'cksum': m.hexdigest()})
            cloneContents[s.st_ino] = (os.path.relpath(dir, top), files)
            flushBatchDirs()
            if len(cloneDirs) >= args.clones:
                flushClones()
        else:
            if len(files) < args.batchdirs:
                if verbosity:
                    print " [Batched]"
                flushClones()
                batchDirs.append(makeDirMessage(os.path.relpath(dir, top), s.st_ino, files))
                if len(batchDirs) >= args.batchsize:
                    flushBatchDirs()
            else:
                if verbosity:
                    print
                flushClones()
                flushBatchDirs()
                sendDirChunks(os.path.relpath(dir, top), s.st_ino, files)

        # Make sure we're not at maximum depth
        if depth != 1:
            for subdir in sorted(subdirs):
                recurseTree(subdir, top, newdepth, subexcludes)

    except (IOError, OSError) as e:
        traceback.print_exc()
    except:
        # TODO: Clean this up
        raise
        traceback.print_exc()

def setBackupName(args):
    """ Calculate the name of the backup set """
    global purgeTime, purgePriority, starttime
    name = args.name
    priority = 1
    keepdays = None
    # If auto is set, pick based on the day of the month, week, or just a daily
    if args.auto:
        if starttime.day == 1:
            args.monthly = True
        elif starttime.weekday() == 0:
            args.weekly = True
        else:
            args.daily = True

    if args.hourly:
        name = 'Hourly-{}'.format(starttime.strftime("%Y-%m-%d:%H:%M"))
        priority = 10
        keepdays = 1
    elif args.daily:
        name = 'Daily-{}'.format(starttime.strftime("%Y-%m-%d"))
        priority = 20
        keepdays = 30
    elif args.weekly:
        name = 'Weekly-{}'.format(starttime.strftime("%Y-%U"))
        priority = 30
        keepdays = 180
    elif args.monthly:
        name = 'Monthly-{}'.format(starttime.strftime("%Y-%m"))
        priority = 40

    # If priority was set, set it here
    if args.priority:
        priority = args.priority

    if args.purge:
        purgePriority = priority
        if args.purgeprior:
            purgePriority = args.purgeprior
        if keepdays:
            purgeTime = keepdays * 3600 * 24        # seconds in days
        if args.purgedays:
            purgeTime = args.purgedays * 3600 * 24
        if args.purgehours:
            purgeTime = args.purgedays * 3600
        if args.purgetime:
            try:
                purgeTime = time.mktime(time.strptime(args.purgetime, "%Y/%m/%d:%H:%M"))
            except ValueError:
                print "Invalid format for --keep-time.  Needs to be YYYY/MM/DD:hh:mm, on a 24-hour clock"
                raise

    return (name, priority)

def loadExcludeFile(name):
    """ Load a list of patterns to exclude from a file. """
    try:
        with open(name) as f:
            excludes = [x.rstrip('\n') for x in f.readlines()]
        return excludes
    except IOError as e:
        #traceback.print_exc()
        return []

# Load all the excludes we might want
def loadExcludes(args):
    if not args.ignoreglobalexcludes:
        globalExcludes.extend(loadExcludeFile(globalExcludeFile))
    if args.cvs:
        globalExcludes.extend(cvsExcludes)
    if args.excludes:
        globalExcludes.extend(args.excludes)
    if args.excludefiles:
        for f in args.excludefiles:
            globalExcludes.extend(loadExcludeFile(f))
    excludeFile         = args.excludefilename
    localExcludeFile    = args.localexcludefilename

def sendMessage(message):
    if verbosity > 4:
        print "Send: %s" % str(message)
    conn.send(message)

def receiveMessage():
    response = conn.receive()
    if verbosity > 4:
        print "Receive: %s" % str(response)
    return response

def sendAndReceive(message):
    sendMessage(message)
    return receiveMessage()

def sendDirEntry(parent, files):
    # send a fake root directory
    message = {
        'message': 'DIR',
        'files':  files,
        'path':  None,
        'inode': parent,
        'files': files
        }

    #for x in map(os.path.realpath, args.directories):
        #(dir, name) = os.path.split(x)
        #file = mkFileInfo(dir, name)
        #if file and file["dir"] == 1:
            #files.append(file)
    #
    # and send it.
    response = sendAndReceive(message)
    handleAckDir(response)

def requestTargetDir():
    global targetDir, targetStat
    message = { "message" : "TMPDIR" }
    response = sendAndReceive(message)
    if response['status'] == 'OK':
        t = response['target']
        if os.path.exists(t):
            targetStat = os.stat(t)
            targetDir = t
        else:
            print "Unable to access target directory {}.  Ignorning copy directive".format(t)

def shortPath(path, width=80):
    if path == None or len(path) <= width:
        return path

    width -= 8
    while len(path) > width:
        try:
            head, path = str.split(path, os.sep, 1)
        except:
            break
    return ".../" + path


def splitDirs(x):
    root, rest = os.path.split(x)
    if root and rest:
        ret = splitDirs(root)
        ret.append(rest)
    elif root:
        if root is '/':
            ret = [root]
        else:
            ret = splitDirs(root)
    else:
        ret = [rest]
    return ret

sentDirs = {}

def makePrefix(root, path):
    """ Create common path directories.  Will be empty, except for path elements to the repested directories. """
    rPath = os.path.relpath(path, root)
    pathDirs = splitDirs(rPath)
    parent = 0
    current = root
    for d in pathDirs:
        dirPath = os.path.join(current, d)
        st = os.lstat(dirPath)
        f = mkFileInfo(current, d)
        if dirPath not in sentDirs:
            sendDirEntry(parent, [f])
            sentDirs[dirPath] = parent
        parent = st.st_ino
        current = dirPath
     
def processCommandLine():
    """ Do the command line thing.  Register arguments.  Parse it. """
    defaultBackupSet = time.strftime("Backup_%Y-%m-%d_%H:%M:%S")
    parser = argparse.ArgumentParser(description='Tardis Backup Client')

    parser.add_argument('--server', '-s',       dest='server', default='localhost',     help='Set the destination server. Default: %(default)s')
    parser.add_argument('--port', '-p',         dest='port', type=int, default=9999,    help='Set the destination server port. Default: %(default)s')
    parser.add_argument('--ssl', '-S',          dest='ssl', action='store_true', default=False,           help='Use SSL connection')

    pwgroup = parser.add_mutually_exclusive_group()
    pwgroup.add_argument('--password',          dest='password', default=None,          help='Encrypt files with this password')
    pwgroup.add_argument('--password-file',     dest='passwordfile', default=None,      help='Read password from file')

    # Create a group of mutually exclusive options for naming the backup set
    namegroup = parser.add_mutually_exclusive_group()
    namegroup.add_argument('--name',   '-n',    dest='name', default=defaultBackupSet,  help='Set the backup name')
    namegroup.add_argument('--hourly', '-H',    dest='hourly', action='store_true',     help='Run an hourly backup')
    namegroup.add_argument('--daily',  '-D',    dest='daily', action='store_true',      help='Run a daily backup')
    namegroup.add_argument('--weekly', '-W',    dest='weekly', action='store_true',     help='Run a weekly backup')
    namegroup.add_argument('--monthly','-M',    dest='monthly', action='store_true',    help='Run a monthly backup')
    namegroup.add_argument('--auto',   '-A',    dest='auto', action='store_true',       help='Automatically name the backup, from daily, weekly, or monthly')

    parser.add_argument('--priority',           dest='priority', type=int, default=None,    help='Set the priority of this backup')
    parser.add_argument('--maxdepth', '-d',     dest='maxdepth', type=int, default=0,       help='Maximum depth to search')
    parser.add_argument('--crossdevice', '-c',  action='store_true', dest='crossdev',       help='Cross devices')
    parser.add_argument('--hostname',           dest='hostname', default=None,              help='Set the hostname')

    parser.add_argument('--basepath',           dest='basepath', default='none', choices=['none', 'common', 'full'],    help="Select style of root path handling Default: %(default)s")

    excgrp = parser.add_argument_group('Exclusion options', 'Options for handling exclusions')
    excgrp.add_argument('--cvs-ignore',         dest='cvs', action='store_true',            help='Ignore files like CVS')
    excgrp.add_argument('--exclude', '-x',      dest='excludes', action='append',           help='Patterns to exclude globally (may be repeated)')
    excgrp.add_argument('--exclude-file', '-X', dest='excludefiles', action='append',       help='Load patterns from exclude file (may be repeated)')
    excgrp.add_argument('--exclude-file-name',  dest='excludefilename', default=excludeFile,                            help='Load recursive exclude files from this.  Default: %(default)s')
    excgrp.add_argument('--local-exclude-file-name',  dest='localexcludefilename', default=localExcludeFile,            help='Load local exclude files from this.  Default: %(default)s')
    excgrp.add_argument('--ignore-global-excludes',   dest='ignoreglobalexcludes', action='store_true', default=False,  help='Ignore the global exclude file')

    comgrp = parser.add_argument_group('Communications options', 'Options for specifying details about the communications protocol.  Mostly for debugging')
    comgrp.add_argument('--clones', '-L',       dest='clones', type=int, default=100,           help='Maximum number of clones per chunk.  0 to disable cloning.  Default: %(default)s')
    comgrp.add_argument('--batchdir', '-B',     dest='batchdirs', type=int, default=16,         help='Maximum size of small dirs to send.  0 to disable batching.  Default: %(default)s')
    comgrp.add_argument('--batchsize',          dest='batchsize', type=int, default=100,        help='Maximum number of small dirs to batch together.  Default: %(default)s')
    comgrp.add_argument('--chunksize',          dest='chunksize', type=int, default=256*1024,   help='Chunk size for sending data.  Default: %(default)s')
    comgrp.add_argument('--dirslice',           dest='dirslice', type=int, default=1000,        help='Maximum number of directory entries per message.  Default: %(default)s')
    comgrp.add_argument('--protocol',           dest='protocol', default="bson", choices=["json", "bson"], help='Protocol for data transfer.  Default: %(default)s')
    parser.add_argument('--copy',               dest='copy', action='store_true',                   help='Copy files directly to target.  Only works if target is localhost')

    parser.add_argument('--purge', '-P',        dest='purge', action='store_true', default=False,   help='Purge old backup sets when backup complete')
    parser.add_argument('--purge-priority',     dest='purgeprior', type=int, default=None,          help='Delete below this priority (Default: Backup priority)')
    prggroup = parser.add_mutually_exclusive_group()
    prggroup.add_argument('--keep-days',        dest='purgedays', type=int, default=None,           help='Number of days to keep')
    prggroup.add_argument('--keep-hours',       dest='purgehours', type=int, default=None,          help='Number of hours to keep')
    prggroup.add_argument('--keep-time',        dest='purgetime', default=None,                     help='Purge before this time.  Format: YYYY/MM/DD:hh:mm')

    parser.add_argument('--version',            action='version', version='%(prog)s ' + version,    help='Show the version')
    parser.add_argument('--stats',              action='store_true', dest='stats',                  help='Print stats about the transfer')
    parser.add_argument('--verbose', '-v',      dest='verbose', action='count',                     help='Increase the verbosity')


    dangergroup = parser.add_argument_group("DANGEROUS", "Dangerous options, use only if you're very knowledgable of Tardis functionality")
    dangergroup.add_argument('--ignore-ctime',      dest='ignorectime', action='store_true', default=False,     help='Ignore CTime when determining clonability')

    parser.add_argument('directories',          nargs='*', default='.', help="List of files to sync")

    return parser.parse_args()

def main():
    global starttime, args, config, conn, verbosity, ignorectime, crypt
    args = processCommandLine()

    starttime = datetime.datetime.now()

    verbosity=args.verbose
    ignorectime = args.ignorectime

    # Figure out the name and the priority of this backupset
    (name, priority) = setBackupName(args)

    # Load the excludes
    loadExcludes(args)

    # Error check the purge parameter.  Disable it if need be
    if args.purge and not purgeTime:
        print "Must specify purge days with this option set"
        args.purge=False

    # Open the connection
    if args.protocol == 'json':
        conn = JsonConnection(args.server, args.port, name, priority, args.ssl, args.hostname)
        setEncoder("base64")
    elif args.protocol == 'bson':
        conn = BsonConnection(args.server, args.port, name, priority, args.ssl, args.hostname)
        setEncoder("bin")

    if verbosity or args.stats:
        print "Name: {} Server: {}:{} Session: {}".format(name, args.server, args.port, conn.getSessionId())

    if args.basepath == 'common':
        rootdir = os.path.commonprefix(map(os.path.realpath, args.directories))
    elif args.basepath == 'full':
        rootdir = '/'
    else:
        rootdir = None

    if args.copy:
        requestTargetDir()

    password = args.password
    args.password = None
    if args.passwordfile:
        with open(args.passwordfile, "r") as f:
            password = f.readline()
    if password:
        crypt = TardisCrypto.TardisCrypto(password)
    password = None

    # Now, do the actual work here.
    for x in map(os.path.realpath, args.directories):
        if rootdir:
            makePrefix(rootdir, x)
        else:
            (d, name) = os.path.split(x)
            f = mkFileInfo(d, name)
            sendDirEntry(0, [f])

    for x in map(os.path.realpath, args.directories):
        if rootdir:
            root = rootdir
        else:
            (d, name) = os.path.split(x)
            root = d

        recurseTree(x, root, depth=args.maxdepth, excludes=globalExcludes)

    # If any clone or batch requests still lying around, send them
    flushClones()
    flushBatchDirs()

    if args.purge:
        if args.purgetime:
            sendPurge(False)
        else:
            sendPurge(True)

    if args.stats:
        connstats = conn.stats
    conn.close()

    endtime = datetime.datetime.now()

    if args.stats:
        print "Runtime: {}".format((endtime - starttime))
        print dict(stats.items() + connstats.items())

if __name__ == '__main__':
    sys.exit(main())