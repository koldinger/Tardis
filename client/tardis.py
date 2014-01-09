#! /usr/bin/python
# -*- coding: utf-8 -*-

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
from Connection import JsonConnection, BsonConnection
from functools import partial

excludeFile         = ".tardis-excludes"
localExcludeFile    = ".tardis-local-excludes"
globalExcludeFile   = "/etc/tardis/excludes"

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

conn                = None
args                = None

cloneDirs           = []
cloneContents       = {}

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

def sendData(file, checksum=False):
    """ Send a block of data """
    num = 0
    if checksum:
        m = hashlib.md5()
    for chunk in iter(partial(file.read, args.chunksize), ''):
        if checksum:
            m.update(chunk)
        data = conn.encode(chunk)
        chunkMessage = { "chunk" : num, "data": data }
        conn.send(chunkMessage)
        stats["bytes"] += len(data)
        num += 1
    message = {"chunk": "done"}
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
    if verbosity > 4:
        print "Send: %s" % str(message)
    conn.send(message)
    response = conn.receive()
    if verbosity > 4:
        print "Receive: %s" % str(sigmessage)
    if not response["message"] == "ACKSUM":
        raise Exception
    for i in response["done"]:
        if verbosity > 1:
            if i in inodeDB:
                (x, name) = inodeDB[i]
                print "File: [C]: %s" % name
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
                print "File: [N]: %s %d" % (name, size)
        sendContent(i)
        if i in inodeDB:
            del inodeDB[i]

def processDelta(inode):
    """ Generate a delta and send it """
    if inode in inodeDB:
        (fileInfo, pathname) = inodeDB[inode]
        message = {
            "message" : "SGR",
            "inode" : inode
            }
        if verbosity > 4:
            print "Send: %s" % str(message)
        conn.send(message)
        sigmessage = conn.receive()
        if verbosity > 4:
            print "Receive: %s" % str(sigmessage)

        if sigmessage['status'] == 'OK':
            oldchksum = sigmessage['checksum']
            sig = conn.decode(sigmessage['signature'])

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
            if verbosity > 4:
                print "Send: %s" % str(message)
            conn.send(message)

            x = cStringIO.StringIO(delta)
            sendData(x)
            x.close()

            #response = conn.receive()
            #if verbosity > 4:
                #print "Receive %s" % str(response)
        else:
            sendContent(inode)

def sendContent(inode):
    if inode in inodeDB:
        checksum = None
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
            if verbosity > 4:
                print "Send: %s" % str(message)
            conn.send(message)

            if S_ISLNK(mode):
                # It's a link.  Send the contents of readlink
                #chunk = os.readlink(pathname)
                x = cStringIO.StringIO(os.readlink(pathname))
                checksum = sendData(x, checksum=True)
                x.close()
            else:
                with open(pathname, "rb") as file:
                    checksum = sendData(file, checksum=True)
            #response = conn.receive()
            #if verbosity > 4:
                #print "Receive %s" % str(response)
    else:
        print "Error: Unknown inode {}".format(inode)

def handleAckDir(message):
    content = message["content"]
    done    = message["done"]
    delta   = message["delta"]
    cksum   = message["cksum"]

    if verbosity > 1: print "Processing ACKDIR: Up-to-date: %d New Content: %d Delta: %d ChkSum: %d" % (len(done), len(content), len(delta), len(cksum))
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
                print "File: [N]: %s %d" % (name, size)
        sendContent(i)

    for i in delta:
        if verbosity > 1:
            (x, name) = inodeDB[i]
            print "File: [D]: %s" % (name)
        processDelta(i)

    # Collect the ACK messages
    if len(cksum) > 0:
        processChecksums(cksum)

    if verbosity > 2:
        print "----- AckDir complete"

    return

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
    if stat.st_ctime > conn.lastTimestamp:
        return False
    if stat.st_mtime > conn.lastTimestamp:
        return False
    # Now, collect the timestamps of all the files, and determine the maximum
    # If any are greater than the last timestamp, punt
    extend = partial(os.path.join, path)
    if subdirs and len(subdirs):
        times = map(os.lstat, map(extend, subdirs))
        time = max(map(lambda x: max(x.st_ctime, x.st_mtime), times))
        if time > conn.lastTimestamp:
            return False
    if files and len(files):
        times = map(os.lstat, map(extend, subs))
        time = max(map(lambda x: max(x.st_ctime, x.st_mtime), times))
        if time > conn.lastTimestamp:
            return False

    return True

def handleAckClone(message):
    if message["message"] != "ACKCLN":
        raise Exception("Expected ACKCLN.  Got {}".format(message["message"]))
    for inode in message["content"]:
        if inode in cloneContents:
            (path, files) = cloneContents[inode]
            if verbosity > 1:
                print "ResyncDir: {}".format(str(dir))
            sendDirChunks(path, inode, files)
            del cloneContents[inode]
    for inode in message["done"]:
        if inode in cloneContents:
            del cloneContents[inode]
        
def sendClones():
    message = {
        'message': 'CLN',
        'clones': cloneDirs
    }
    if verbosity > 4:
        print "Send: %s" % str(message)
    conn.send(message)
    response = conn.receive()
    if verbosity > 4:
        print "SC Receive: %s" % str(response)
    handleAckClone(response)
    del cloneDirs[:]

def sendPurge(relative):
    if purgePriority and purgeTime:
        message = {
            'message': 'PRG',
            'priority': purgePriority,
            'time'    : purgeTime,
            'relative': relative
        }
        if verbosity > 4:
            print "Send: %s" % str(message)
        conn.send(message)
        response = conn.receive()
        if verbosity > 4:
            print "Receive: %s" % str(response)

def sendDirChunks(path, inode, files):
    message = {
        'message': 'DIR',
        'path':  path,
        'inode':  inode
    }

    chunkNum = 0
    for x in range(0, len(files), args.dirslice):
        if verbosity > 2:
            print "---- Generating chunk {} ----".format(chunkNum)
        chunkNum += 1
        chunk = files[x : x + args.dirslice]
        message["files"] = chunk
        if verbosity > 2:
            print "---- Sending chunk ----"
            if verbosity > 4:
                print "Send: %s" % str(message)
        conn.send(message)
        if verbosity > 2:
            print "---- Waiting for ACKDir----"
        response = conn.receive()
        if verbosity > 4:
            print "Receive: %s" % str(response)
        handleAckDir(response)

def recurseTree(dir, top, depth=0, excludes=[]):
    newdepth = 0
    if depth > 0:
        newdepth = depth - 1

    s = os.lstat(dir)
    if not S_ISDIR(s.st_mode):
        return

    try:
        if verbosity:
            print "Dir: {}".format(str(dir))
            if verbosity > 2 and len(excludes) > 0:
                print "   Excludes: {}".format(str(excludes))

        (files, subdirs, subexcludes) = processDir(dir, s, excludes)

        # Check the max time on all the files.  If everything is before last timestamp, just clone
        cloneable = False
        #print "Checking cloneablity: {} Last {} ctime {} mtime {}".format(dir, conn.lastTimestamp, s.st_ctime, s.st_mtime)
        if (args.clones > 0) and (s.st_ctime < conn.lastTimestamp) and (s.st_mtime < conn.lastTimestamp) and (len(files) > 0):
            maxTime = max(map(lambda x: max(x["ctime"], x["mtime"]), files))
            #print "Max file timestamp: {} Last Timestamp {}".format(maxTime, conn.lastTimestamp)
            if maxTime < conn.lastTimestamp:
                cloneable = True

        if cloneable:
            if verbosity > 2:
                print "---- Cloning dir {} ----".format(dir)
            filenames = sorted([x["name"] for x in files])
            m = hashlib.md5()
            for f in filenames:
                m.update(f.encode('utf8', 'ignore'))

            cloneDirs.append({'inode':  s.st_ino, 'numfiles':  len(files), 'cksum': m.hexdigest()})
            cloneContents[s.st_ino] = (os.path.relpath(dir, top), files)
            if len(cloneDirs) > args.clones:
                sendClones()
        else:
            if len(cloneDirs):
                sendClones()
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
    global purgeTime, purgePriority
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
        print "PurgeTime: ", purgeTime

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

def processCommandLine():
    defaultBackupSet = time.strftime("Backup_%Y-%m-%d_%H:%M:%S")
    parser = argparse.ArgumentParser(description='Tardis Backup Client')

    parser.add_argument('--server', '-s',       dest='server', default='localhost',     help='Set the destination server')
    parser.add_argument('--port', '-p',         dest='port', type=int, default=9999,    help='Set the destination server port')

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

    excgrp = parser.add_argument_group('Exclusion options', 'Options for handling exclusions')
    excgrp.add_argument('--cvs-ignore',         dest='cvs', action='store_true',            help='Ignore files like CVS')
    excgrp.add_argument('--exclude', '-x',      dest='excludes', action='append',           help='Patterns to exclude globally (may be repeated)')
    excgrp.add_argument('--exclude-file', '-X', dest='excludefiles', action='append',       help='Load patterns from exclude file (may be repeated)')
    excgrp.add_argument('--exclude-file-name',  dest='excludefilename', default=excludeFile,                            help='Load recursive exclude files from this.  Default: %(default)s')
    excgrp.add_argument('--local-exclude-file-name',  dest='localexcludefilename', default=localExcludeFile,            help='Load local exclude files from this.  Default: %(default)s')
    excgrp.add_argument('--ignore-global-excludes',   dest='ignoreglobalexcludes', action='store_true', default=False,  help='Ignore the global exclude file')

    comgrp = parser.add_argument_group('Communications options', 'Options for specifying details about the communications protocol.  Mostly for debugging')
    comgrp.add_argument('--clones', '-L',       dest='clones', type=int, default=100,       help='Maximum number of clones per chunk.  0 to disable cloning.  Default: %(default)s')
    comgrp.add_argument('--chunksize',          dest='chunksize', type=int, default=16536,  help='Chunk size for sending data.  Default: %(default)s')
    comgrp.add_argument('--dirslice',           dest='dirslice', type=int, default=1000,    help='Maximum number of directory entries per message.  Default: %(default)s')
    comgrp.add_argument('--protocol',           dest='protocol', default="bson", choices=["json", "bson"], help='Protocol for data transfer.  Default: %(default)s')

    parser.add_argument('--purge', '-P',        dest='purge', action='store_true', default=False,   help='Purge old backup sets when backup complete')
    parser.add_argument('--purge-priority',     dest='purgeprior', type=int, default=None,          help='Delete below this priority (Default: Backup priority)')
    prggroup = parser.add_mutually_exclusive_group()
    prggroup.add_argument('--keep-days',        dest='purgedays', type=int, default=None,           help='Number of days to keep')
    prggroup.add_argument('--keep-hours',       dest='purgehours', type=int, default=None,          help='Number of hours to keep')
    prggroup.add_argument('--keep-time',        dest='purgetime', default=None,                     help='Purge before this time.  Format: YYYY/MM/DD:hh:mm')

    parser.add_argument('--version',            action='version', version='%(prog)s ' + version,    help='Show the version')
    parser.add_argument('--stats',              action='store_true', dest='stats',                  help='Print stats about the transfer')
    parser.add_argument('--verbose', '-v',      dest='verbose', action='count',                     help='Increase the verbosity')

    parser.add_argument('directories',          nargs='*', default='.', help="List of files to sync")

    return parser.parse_args()

if __name__ == '__main__':

    args = processCommandLine()
    #print args

    starttime = datetime.datetime.now()

    verbosity=args.verbose

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
        conn = JsonConnection(args.server, args.port, name, priority)
        setEncoder("base64")
    elif args.protocol == 'bson':
        conn = BsonConnection(args.server, args.port, name, priority)
        setEncoder("bin")

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
        if file and file["dir"] == 1:
            files.append(file)

    # and send it.
    if verbosity > 4:
        print "Send: %s" % str(message)
    conn.send(message)
    response = conn.receive()
    if verbosity > 4:
        print "Receive: %s" % str(response)
    handleAckDir(response)

    # Now, do the actual work here.
    for x in args.directories:
        recurseTree(x, x, depth=args.maxdepth, excludes=globalExcludes)

    # If any clone requests still lying around, send them
    if len(cloneDirs):
        sendClones()

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
