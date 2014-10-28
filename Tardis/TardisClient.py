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
import logging
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
import pycurl
import shlex
from functools import partial

from rdiff_backup import librsync

import TardisCrypto
from Connection import JsonConnection, BsonConnection
import Util

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
version             = "0.4"

ignorectime         = False

conn                = None
args                = None
targetDir           = None
targetStat          = None

cloneDirs           = []
cloneContents       = {}
batchDirs           = []

crypt               = None
logger              = logging.getLogger('')

stats = { 'dirs' : 0, 'files' : 0, 'links' : 0, 'backed' : 0, 'dataSent': 0, 'dataRecvd': 0 , 'new': 0, 'delta': 0}

inodeDB             = {}

class CustomArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super(CustomArgumentParser, self).__init__(*args, **kwargs)

    def convert_arg_line_to_args(self, line):
        for arg in line.split():
            if not arg.strip():
                continue
            if arg[0] == '#':
                break
            yield arg

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
    # First, delete all the files which are "done", ie, matched
    for i in [tuple(x) for x in response['done']]:
        if verbosity > 1:
            if i in inodeDB:
                (x, name) = inodeDB[i]
                logger.debug("File: [C]: %s", Util.shortPath(name))
        if i in inodeDB:
            del inodeDB[i]
    # First, then send content for any files which don't
    # FIXME: TODO: There should be a test in here for Delta's
    for i in [tuple(x) for x in response['content']]:
        if verbosity > 1:
            if i in inodeDB:
                (x, name) = inodeDB[i]
                if "size" in x:
                    size = x["size"]
                else:
                    size = 0;
                logger.debug("File: [N]: %s %d", Util.shortPath(name), size)
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
            sigfile = cStringIO.StringIO()
            #sigfile = cStringIO.StringIO(conn.decode(sigmessage['signature']))
            Util.receiveData(conn.sender, sigfile)
            sigfile.seek(0)

            delta = librsync.DeltaFile(sigfile, open(pathname, "rb"))

            ### BUG: If the file is being changed, this value and the above may be different.
            m = hashlib.md5()
            filesize = 0
            stats['delta'] += 1
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
                    #message["iv"] = conn.encode(iv)
                    message["iv"] = base64.b64encode(iv)

                sendMessage(message)
                compress = True if (args.compress and (filesize > args.mincompsize)) else False
                (sent, ck) = Util.sendData(conn.sender, delta, encrypt, chunksize=args.chunksize, compress=compress, stats=stats)
                delta.close()
                if newsig:
                    message = {
                        "message" : "SIG",
                        "checksum": checksum
                    }
                    sendMessage(message)
                    Util.sendData(conn.sender, newsig, lambda x:x, chunksize=args.chunksize, compress=False, stats=stats)            # Don't bother to encrypt the signature
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
    stats['new'] += 1

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
            filesize = fileInfo["size"]
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
                #message["iv"] = conn.encode(iv)
                message["iv"] = base64.b64encode(iv)
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
                logger.error("Error: Could not open %s: %s", pathname, e)
                return

            # Attempt to send the data.
            try:
                compress = True if (args.compress and (filesize > args.mincompsize)) else False
                sendMessage(message)
                (size, checksum) = Util.sendData(conn.sender, x, encrypt, checksum=True, chunksize=args.chunksize, compress=compress, stats=stats)

                if crypt:
                    x.seek(0)
                    sig = librsync.SigFile(x)
                    message = {
                        "message" : "SIG",
                        "checksum": checksum
                    }
                    sendMessage(message)
                    Util.sendData(conn, sig, lambda x:x, chunksize=args.chunksize, stats=stats)            # Don't bother to encrypt the signature
            except Exception as e:
                logger.error("Caught exception during sending of data: %s", e)
                logger.exception(e)
            finally:
                x.close()
            stats['new'] += 1
    else:
        logger.error("Error: Unknown inode {}".format(inode))

def handleAckDir(message):
    content = message["content"]
    done    = message["done"]
    delta   = message["delta"]
    cksum   = message["cksum"]

    if verbosity > 2:
        logger.debug("Processing ACKDIR: Up-to-date: %3d New Content: %3d Delta: %3d ChkSum: %3d -- %s", len(done), len(content), len(delta), len(cksum), Util.shortPath(message['path'], 40))

    for i in [tuple(x) for x in done]:
        if i in inodeDB:
            del inodeDB[i]

    for i in [tuple(x) for x in content]:
        if verbosity > 1:
            if i in inodeDB:
                (x, name) = inodeDB[i]
                if "size" in x:
                    size = x["size"]
                else:
                    size = 0;
                logger.info("File: [N]: %s %d", Util.shortPath(name), size)
        sendContent(i)
        if i in inodeDB:
            del inodeDB[i]

    for i in [tuple(x) for x in delta]:
        if verbosity > 1:
			if i in inodeDB:
				(x, name) = inodeDB[i]
				logger.info("File: [D]: %s", Util.shortPath(name))
        processDelta(i)
        if i in inodeDB:
            del inodeDB[i]

    # Collect the ACK messages
    if len(cksum) > 0:
        processChecksums([tuple(x) for x in cksum])

def mkFileInfo(dir, name):
    file = None
    pathname = os.path.join(dir, name)
    s = os.lstat(pathname)
    mode = s.st_mode
    if S_ISREG(mode) or S_ISDIR(mode) or S_ISLNK(mode):
        if crypt:
            name = crypt.encryptFilename(name)
        else:
            name = unicode(name.decode('utf8', 'ignore'))
        finfo =  {
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

        inodeDB[(s.st_ino, s.st_dev)] = (finfo, pathname)
    else:
        if verbosity:
            logger.info("Skipping special file: %s", pathname)
        finfo = None
    return finfo
    
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

    try:
        for f in filelist(dir, localExcludes):
            try:
                file = mkFileInfo(dir, f)
                if file and (args.crossdev or device == file['dev']):
                    mode = file["mode"]
                    if S_ISLNK(mode):
                        stats['links'] += 1
                    elif S_ISREG(mode):
                        stats['files'] += 1
                        stats['backed'] += file["size"]

                    if S_ISDIR(mode):
                            subdirs.append(os.path.join(dir, f))

                    files.append(file)
            except (IOError, OSError) as e:
                logger.error("Error processing %s: %s", os.path.join(dir, f), str(e))
            except Exception as e:
                ## Is this necessary?  Fold into above?
                logger.error("Error processing %s: %s", os.path.join(dir, f), str(e))
                #logger.exception(e)
                #traceback.print_exc()
    except (IOError, OSError) as e:
        logger.error("Error reading directory %s: %s" ,dir, str(e))

    return (files, subdirs, excludes)

def handleAckClone(message):
    if message["message"] != "ACKCLN":
        raise Exception("Expected ACKCLN.  Got {}".format(message["message"]))
    if verbosity > 2:
        logger.debug("Processing ACKCLN: Up-to-date: %d New Content: %d", len(message['done']), len(message['content']))

    # Process the directories that have changed
    for i in message["content"]:
        finfo = tuple(i)
        if finfo in cloneContents:
            (path, files) = cloneContents[finfo]
            if len(files) < args.batchdirs:
                if verbosity > 1:
                    logger.debug("ResyncDir: [Batched] %s", Util.shortPath(path))
                (inode, device) = finfo
                batchDirs.append(makeDirMessage(path, inode, device, files))
                if len(batchDirs) >= args.batchsize:
                    flushBatchDirs()
            else:
                if verbosity > 1:
                    logger.debug("ResyncDir: %s", Util.shortPath(path))
                flushBatchDirs()
                sendDirChunks(path, finfo, files)
            del cloneContents[finfo]

    # Purge out what hasn't changed
    for i in message["done"]:
        inode = tuple(i)
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
    logger.debug("BATCH Starting. %s commands", len(batchDirs))

    response = sendAndReceive(message)
    for ack in response['responses']:
        handleAckDir(ack)

    logger.debug("BATCH Ending.")

    del batchDirs[:]

def flushBatchDirs():
    if len(batchDirs):
        sendBatchDirs()

def sendPurge(relative):
    message =  { 'message': 'PRG' }
    if purgePriority:
        message['priority'] = purgPriority
    if purgeTime:
        message.update( { 'time': purgeTime, 'relative': relative })

    response = sendAndReceive(message)

def sendDirChunks(path, inode, files):
    message = {
        'message': 'DIR',
        'path':  path,
        'inode': list(inode)
    }

    chunkNum = 0
    for x in range(0, len(files), args.dirslice):
        if verbosity > 3:
            logger.debug("---- Generating chunk %d ----", chunkNum)
        chunkNum += 1
        chunk = files[x : x + args.dirslice]
        message["files"] = chunk
        if verbosity > 3:
            logger.debug("---- Sending chunk ----")
        response = sendAndReceive(message)
        handleAckDir(response)

def makeDirMessage(path, inode, dev, files):
    message = {
        'files':  files,
        'inode':  [inode, dev],
        'path':   path,
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
        #logger.info("Dir: %s", Util.shortPath(dir))
        logmsg = "Dir: {}".format(Util.shortPath(dir))
        #logger.debug("Excludes: %s", str(excludes))

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
            logmsg += " [Clone]"
            logger.info(logmsg)

            filenames = sorted([x["name"] for x in files])
            m = hashlib.md5()
            for f in filenames:
                m.update(f.encode('utf8', 'ignore'))

            cloneDirs.append({'inode':  s.st_ino, 'dev': s.st_dev, 'numfiles': len(files), 'cksum': m.hexdigest()})
            cloneContents[(s.st_ino, s.st_dev)] = (os.path.relpath(dir, top), files)
            flushBatchDirs()
            if len(cloneDirs) >= args.clones:
                flushClones()
        else:
            if len(files) < args.batchdirs:
                logmsg += " [Batched]"
                logger.info(logmsg)
                flushClones()
                batchDirs.append(makeDirMessage(os.path.relpath(dir, top), s.st_ino, s.st_dev, files))
                if len(batchDirs) >= args.batchsize:
                    flushBatchDirs()
            else:
                logger.info(logmsg)
                flushClones()
                flushBatchDirs()
                sendDirChunks(os.path.relpath(dir, top), (s.st_ino, s.st_dev), files)

        # Make sure we're not at maximum depth
        if depth != 1:
            for subdir in sorted(subdirs):
                recurseTree(subdir, top, newdepth, subexcludes)

    except (OSError) as e:
        logger.error("Error handling directory: %s: %s", dir, str(e))
        #raise
        #traceback.print_exc()
    except (IOError) as e:
        logger.error("Error handling directory: %s: %s", dir, str(e))
        raise
    except Exception as e:
        # TODO: Clean this up
        #logger.exception(e)
        raise
        

def setBackupName(args):
    """ Calculate the name of the backup set """
    global purgeTime, purgePriority, starttime
    name = args.name
    priority = 0
    keepdays = None
    # If auto is set, pick based on the day of the month, week, or just a daily
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
                logger.error("Invalid format for --keep-time.  Needs to be YYYY/MM/DD:hh:mm, on a 24-hour clock")
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
        logger.debug("Send: %s", str(message))
    conn.send(message)

def receiveMessage():
    response = conn.receive()
    if verbosity > 4:
        logger.debug("Receive: %s", str(response))
    return response

def sendAndReceive(message):
    sendMessage(message)
    return receiveMessage()

def sendDirEntry(parent, device, files):
    # send a fake root directory
    message = {
        'message': 'DIR',
        'files': files,
        'path':  None,
        'inode': [parent, device],
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
            logger.error("Unable to access target directory %s.  Ignorning copy directive", t)

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
    rPath     = os.path.relpath(path, root)
    pathDirs  = splitDirs(rPath)
    parent    = 0
    parentDev = 0
    current   = root
    for d in pathDirs:
        dirPath = os.path.join(current, d)
        st = os.lstat(dirPath)
        f = mkFileInfo(current, d)
        if dirPath not in sentDirs:
            sendDirEntry(parent, parentDev, [f])
            sentDirs[dirPath] = parent
        parent    = st.st_ino
        parentDev = st.st_dev
        current   = dirPath

def run_server(args, tempfile):
    server_cmd = shlex.split(args.serverprog) + ['--single', '--local', tempfile]
    #if args.serverargs:
        #server_cmd = server_cmd + args.serverargs
    logger.info("Invoking server: " + str(server_cmd))
    subp = subprocess.Popen(server_cmd)
    time.sleep(.5)
    if subp.poll():
        raise Exception("Subprocess died:" + subp.returncode)
    return subp

def processCommandLine():
    """ Do the command line thing.  Register arguments.  Parse it. """
    defaultBackupSet = time.strftime("Backup_%Y-%m-%d_%H:%M:%S")
    #parser = argparse.ArgumentParser(description='Tardis Backup Client', fromfile_prefix_chars='@')
    # Use the custom arg parser, which handles argument files more cleanly
    parser = CustomArgumentParser(description='Tardis Backup Client', fromfile_prefix_chars='@',
                                  epilog='Options can be specified in files, with the filename specified by an @sign: e.g. "%(prog)s @args.txt" will read arguments from args.txt')

    parser.add_argument('--server', '-s',       dest='server', default='localhost',     help='Set the destination server. Default: %(default)s')
    parser.add_argument('--port', '-p',         dest='port', type=int, default=9999,    help='Set the destination server port. Default: %(default)s')
    parser.add_argument('--ssl', '-S',          dest='ssl', action='store_true', default=False,           help='Use SSL connection.  Default: %(default)s')

    parser.add_argument('--hostname',           dest='hostname', default=socket.gethostname(),            help='Set the hostname.  Default: %(default)s')

    pwgroup = parser.add_mutually_exclusive_group()
    pwgroup.add_argument('--password',          dest='password', default=None,          help='Encrypt files with this password')
    pwgroup.add_argument('--password-file',     dest='passwordfile', default=None,      help='Read password from file')
    pwgroup.add_argument('--password-url',      dest='passwordurl', default=None,       help='Retrieve password from the specified URL')

    parser.add_argument('--compress', '-z',     dest='compress', default=False, action='store_true',    help='Compress files')
    parser.add_argument('--compress-min',       dest='mincompsize', type=int,default=4096,              help='Minimum size to compress')
    """
    parser.add_argument('--compress-ignore-types',  dest='ignoretypes', default=None,                   help='File containing a list of types to ignore')
    parser.add_argument('--comprress-threshold',    dest='compthresh', type=float, default=0.9,         help='Maximum compression ratio to allow')
    """

    locgrp = parser.add_argument_group("Arguments for running server locally under tardis")
    locgrp.add_argument('--local',                      dest='local', action='store_true', default=False,       help='Run server as a local client')
    locgrp.add_argument('--local-server-cmd',           dest='serverprog', default='tardisd --config /etc/tardis/tardisd.cfg',                   help='Local server program to run')
    #locgrp.add_argument('--local-server-arg', '-Y',     dest='serverargs', action='append', default=None,       help='Arguments to add to the server')

    # Create a group of mutually exclusive options for naming the backup set
    namegroup = parser.add_mutually_exclusive_group()
    namegroup.add_argument('--name',   '-n',    dest='name', default=defaultBackupSet,  help='Set the backup name.  Default: %(default)s')
    namegroup.add_argument('--hourly', '-H',    dest='hourly', action='store_true',     help='Run an hourly backup')
    namegroup.add_argument('--daily',  '-D',    dest='daily', action='store_true',      help='Run a daily backup')
    namegroup.add_argument('--weekly', '-W',    dest='weekly', action='store_true',     help='Run a weekly backup')
    namegroup.add_argument('--monthly','-M',    dest='monthly', action='store_true',    help='Run a monthly backup')
    namegroup.add_argument('--auto',   '-A',    dest='auto', action='store_true',       help='Automatically name the backup, from daily, weekly, or monthly')

    parser.add_argument('--priority',           dest='priority', type=int, default=None,    help='Set the priority of this backup')
    parser.add_argument('--maxdepth', '-d',     dest='maxdepth', type=int, default=0,       help='Maximum depth to search')
    parser.add_argument('--crossdevice', '-c',  action='store_true', dest='crossdev',       help='Cross devices')

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
    comgrp.add_argument('--protocol',           dest='protocol', default="bson", choices=["json", "bson", "bsonc"], help='Protocol for data transfer.  Default: %(default)s')
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
    levels = [logging.WARNING, logging.INFO, logging.DEBUG] #, logging.TRACE]

    logging.basicConfig(format="%(message)s")
    logger = logging.getLogger('')
    args = processCommandLine()

    starttime = datetime.datetime.now()

    verbosity=args.verbose if args.verbose else 0
    loglevel = levels[verbosity] if verbosity < len(levels) else logging.DEBUG
    logger.setLevel(loglevel)

    ignorectime = args.ignorectime

    loglevel = levels[verbosity] if verbosity < len(levels) else logging.DEBUG
    logger.setLevel(loglevel)

    try:
        # Figure out the name and the priority of this backupset
        (name, priority) = setBackupName(args)

        # Load the excludes
        loadExcludes(args)

        # Error check the purge parameter.  Disable it if need be
        if args.purge and not (purgeTime is not None or args.auto):
            logger.error("Must specify purge days with this option set")
            args.purge=False

        # Load any password info
        password = Util.getPassword(args.password, args.passwordfile, args.passwordurl)
        args.password = None

        token = None
        if password:
            crypt = TardisCrypto.TardisCrypto(password)
            token = crypt.encryptFilename(args.hostname)
        password = None

        if args.basepath == 'common':
            rootdir = os.path.commonprefix(map(os.path.realpath, args.directories))
        elif args.basepath == 'full':
            rootdir = '/'
        else:
            rootdir = None
    except Exception as e:
        logger.critical("Unable to initialize: %s", (str(e)))
        sys.exit(1)

    # Open the connection
    if args.local:
        tempsocket = os.path.join(tempfile.gettempdir(), "tardis_local_" + str(os.getpid()))
        args.port = tempsocket
        args.server = None
        run_server(args, tempsocket)

    try:
        if args.protocol == 'json':
            conn = JsonConnection(args.server, args.port, name, priority, args.ssl, args.hostname, autoname=args.auto, token=token)
            setEncoder("base64")
        elif args.protocol == 'bson':
            conn = BsonConnection(args.server, args.port, name, priority, args.ssl, args.hostname, autoname=args.auto, token=token, compress=False)
            setEncoder("bin")
        elif args.protocol == 'bsonc':
            conn = BsonConnection(args.server, args.port, name, priority, args.ssl, args.hostname, autoname=args.auto, token=token, compress=True)
            setEncoder("bin")
    except Exception as e:
        logger.critical("Unable to start session with %s:%s: %s", args.server, args.port, str(e))
        #logger.exception(e)
        sys.exit(1)

    if verbosity or args.stats:
        logger.info("Name: {} Server: {}:{} Session: {}".format(conn.getBackupName(), args.server, args.port, conn.getSessionId()))

    # Now, do the actual work here.
    try:
        if args.copy:
            requestTargetDir()

        # First, send any fake directories
        for x in map(os.path.realpath, args.directories):
            if rootdir:
                makePrefix(rootdir, x)
            else:
                (d, name) = os.path.split(x)
                f = mkFileInfo(d, name)
                sendDirEntry(0, 0, [f])

        # Now, process all the actual directories
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

        # Sanity check.
        if len(cloneContents) != 0:
            log.warning("Warning: Some cloned directories not processed")

        if args.purge:
            if args.purgetime:
                sendPurge(False)
            else:
                sendPurge(True)
        conn.close()
    except KeyboardInterrupt:
        logger.warning("Backup Interupted")
    except Exception as e:
        logger.error("Caught exeception: %s", e)
        #logger.exception(e)

    endtime = datetime.datetime.now()

    if args.stats:
        logger.info("Runtime: {}".format((endtime - starttime)))
        logger.info("Backed Up:   Dirs: {:,}  Files: {:,}  Links: {:,}  Total Size: {:}".format(stats['dirs'], stats['files'], stats['links'], Util.fmtSize(stats['backed'])))
        logger.info("Files Sent:  Full: {:,}  Deltas: {:,}".format(stats['new'], stats['delta']))
        if conn is not None:
            connstats = conn.getStats()
            logger.info("Messages:    Sent: {:,} ({:}) Received: {:,} ({:})".format(connstats['messagesSent'], Util.fmtSize(connstats['bytesSent']), connstats['messagesRecvd'], Util.fmtSize(connstats['bytesRecvd'])))
        logger.info("Data Sent:   {:}".format(Util.fmtSize(stats['dataSent'])))

    if args.local:
        os.unlink(tempsocket)

if __name__ == '__main__':
    sys.exit(main())
