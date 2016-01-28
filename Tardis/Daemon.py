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

import os
import types
import sys
import pwd, grp
import argparse
import uuid
import logging
import logging.config
import ConfigParser
import SocketServer
import ssl
import hashlib
import base64
import subprocess
import daemonize
import pprint
import tempfile
import shutil
import traceback
import signal
import thread
import threading
import json
from datetime import datetime
import librsync

# For profiling
import cProfile
import StringIO
import pstats

import ConnIdLogAdapter

import Messages
import CacheDir
import TardisDB
import Regenerate
import Util
import Defaults
import Connection

import Tardis

DONE    = 0
CONTENT = 1
CKSUM   = 2
DELTA   = 3
REFRESH = 4                     # Perform a full content update

config = None
args   = None
databaseName    = Defaults.getDefault('TARDIS_DBNAME')
schemaName      = Defaults.getDefault('TARDIS_SCHEMA')
configName      = Defaults.getDefault('TARDIS_DAEMON_CONFIG')
baseDir         = Defaults.getDefault('TARDIS_DB')
portNumber      = Defaults.getDefault('TARDIS_PORT')
pidFileName     = Defaults.getDefault('TARDIS_PIDFILE')
journalName     = Defaults.getDefault('TARDIS_JOURNAL')
timeout         = Defaults.getDefault('TARDIS_TIMEOUT')
logExceptions   = Defaults.getDefault('TARDIS_LOGEXCEPTIONS')

if  os.path.isabs(schemaName):
    schemaFile = schemaName
else:
    parentDir    = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    schemaFile   = os.path.join(parentDir, schemaName)
    # Hack.  Make it look shorter.
    schemaFile = min([schemaFile, os.path.relpath(schemaFile)], key=len)
    #if len(schemaFile) > len(os.path.relpath(schemaFile)):
        #schemaFile = os.path.relpath(schemaFile)

configDefaults = {
    'Port'              : portNumber,
    'BaseDir'           : baseDir,
    'DBName'            : databaseName,
    'Schema'            : schemaFile,
    'LogCfg'            : None,
    'Profile'           : str(False),
    'LogFile'           : None,
    'JournalFile'       : journalName,
    'LogExceptions'     : str(False),
    'AllowNewHosts'     : str(False),
    'RequirePassword'   : str(False),
    'Single'            : str(False),
    'Local'             : None,
    'Verbose'           : '0',
    'Daemon'            : str(False),
    'Umask'             : '027',
    'User'              : None,
    'Group'             : None,
    'SSL'               : str(False),
    'Timeout'           : timeout,
    'CertFile'          : None,
    'KeyFile'           : None,
    'PidFile'           : pidFileName,
    'ReuseAddr'         : str(False),
    'MonthFmt'          : 'Monthly-%Y-%m',
    'WeekFmt'           : 'Weekly-%Y-%U',
    'DayFmt'            : 'Daily-%Y-%m-%d',
    'MonthPrio'         : '40',
    'WeekPrio'          : '30',
    'DayPrio'           : '20',
    'MonthKeep'         : '0',
    'WeekKeep'          : '180',
    'DayKeep'           : '30',
    'MaxDeltaChain'     : '5',
    'MaxChangePercent'  : '50',
    'SaveFull'          : str(False),
    'DBBackups'         : '3'
}

server = None
logger = None

pp = pprint.PrettyPrinter(indent=2, width=200)

logging.TRACE = logging.DEBUG - 1
logging.MSGS  = logging.DEBUG - 2

class InitFailedException(Exception):
    pass

class TardisServerHandler(SocketServer.BaseRequestHandler):
    numfiles = 0
    logger   = None
    sessionid = None
    tempdir = None
    cache   = None
    db      = None
    purged  = False
    statNewFiles = 0
    statUpdFiles = 0
    statDirs     = 0
    statBytesReceived = 0
    statCommands = {}
    address = ''

    def setup(self):
        self.sessionid = str(uuid.uuid1())
        logger = logging.getLogger('Tardis')
        self.idstr= self.sessionid[0:13]   # Leading portion (ie, timestamp) of the UUID.  Sufficient for logging.
        self.logger = ConnIdLogAdapter.ConnIdLogAdapter(logger, {'connid': self.idstr})
        if self.client_address:
            self.address = self.client_address[0]
        else:
            self.address = 'localhost'
        self.logger.info("Request received from: %s Session: %s", self.address, self.sessionid)
        self.tempPrefix = self.sessionid + "-"
        # Not quite sure why I do this here.  But just in case.
        os.umask(self.server.umask)

    def finish(self):
        self.logger.info("Ending session %s from %s", self.sessionid, self.address)

    def setXattrAcl(self, inode, device, xattr, acl):
        self.logger.debug("Setting Xattr and ACL info: %d %s %s", inode, xattr, acl)
        if xattr:
            self.db.setXattrs(inode, device, xattr)
        if acl:
            self.db.setAcl(inode, device, acl)

    def checkFile(self, parent, f, dirhash):
        xattr = None
        acl = None
        """ Process an individual file.  Check to see if it's different from what's there already """
        self.logger.debug("Processing file: %s %s", str(f), str(parent))
        name = f["name"]
        inode = f["inode"]
        device = f["dev"]
        if 'xattr' in f:
            xattr = f['xattr']
        if 'acl' in f:
            acl = f['acl']

        #self.logger.debug("Processing Inode: %8d %d -- File: %s -- Parent: %s", inode, device, name, str(parent))
        #self.logger.debug("DirHash: %s", str(dirhash))
        
        if name in dirhash:
            old = dirhash[name]
        else:
            old = None

        if f["dir"] == 1:
            #self.logger.debug("Is a directory: %s", name)
            if old:
                if (old["inode"] == inode) and (old["device"] == device) and (old["mtime"] == f["mtime"]):
                    self.db.extendFile(parent, f['name'])
                else:
                    self.db.insertFile(f, parent)
                    self.setXattrAcl(inode, device, xattr, acl)
            else:
                self.db.insertFile(f, parent)
                self.setXattrAcl(inode, device, xattr, acl)
            retVal = DONE
        else:
            # Get the last backup information
            #old = self.db.getFileInfoByName(f["name"], parent)
            if old:
                fromPartial = False     # For use with the upcoming result
                #self.logger.debug('Matching against old version for file %s (%d)', name, inode)
            elif not self.lastCompleted:
                # not in this directory, but lets look further in any incomplete sets if there are any
                #self.logger.debug("Looking up file in partial backup(s): %s (%s)", name, inode)
                old = self.db.getFileFromPartialBackup(f)
                if old:
                    fromPartial = old['lastset']
                    self.logger.debug("Found %s in partial backup set: %d", name, old['lastset'])
            if old:
                #self.logger.debug("Comparing versions: New: %s", str(f))
                #self.logger.debug("Comparing version: Old: %s", str(old))

                # Got something.  If the inode, size, and mtime are the same, just keep it
                fsize = f['size']
                osize = old['size']

                if (old["inode"] == inode) and (osize == fsize) and (old["mtime"] == f["mtime"]):
                    #self.logger.debug("Main info matches: %s", name)
                    #if ("checksum" in old.keys()) and not (old["checksum"] is None):
                    if not (old["checksum"] is None):
                        #self.db.setChecksum(inode, device, old['checksum'])
                        if (old['mode'] == f['mode']) and (old['ctime'] == f['ctime']) and (old['xattrs'] == xattr) and (old['acl'] == acl):
                            # nothing has changed, just extend it
                            #self.logger.debug("Extending %s", name)
                            self.db.extendFile(parent, f['name'], old=fromPartial)
                        else:
                            # Some metadata has changed, so let's insert the new record, and set it's checksum
                            #self.logger.debug("Inserting new version %s", name)
                            self.db.insertFile(f, parent)
                            self.db.setChecksum(inode, device, old['checksum'])
                            self.setXattrAcl(inode, device, xattr, acl)
                        retVal = DONE       # we're done either way
                    else:
                        # Otherwise we need a whole new file
                        #self.logger.debug("No checksum: Get new file %s", name)
                        self.db.insertFile(f, parent)
                        self.setXattrAcl(inode, device, xattr, acl)
                        retVal = CONTENT
                #elif (osize == fsize) and ("checksum" in old.keys()) and not (old["checksum"] is None):
                elif (osize == fsize) and not (old["checksum"] is None):
                    #self.logger.debug("Secondary match, requesting checksum: %s", name)
                    # Size hasn't changed, but something else has.  Ask for a checksum
                    self.db.insertFile(f, parent)
                    self.setXattrAcl(inode, device, xattr, acl)
                    retVal = CKSUM
                elif (f["size"] < 4096) or (old["size"] is None) or \
                     not ((old['size'] * self.server.deltaPercent) < f['size'] < (old['size'] * (1.0 + self.server.deltaPercent))) or \
                     ((old["basis"] is not None) and (self.db.getChainLength(old["checksum"]) >= self.server.maxChain)):
                    #self.logger.debug("Third case.  Weirdos: %s", name)
                    # Couple conditions that can cause it to always load
                    # File is less than 4K
                    # Old file had now size
                    # File has changed size by more than a certain amount (typically 50%)
                    # Chain of delta's is too long.
                    self.db.insertFile(f, parent)
                    self.setXattrAcl(inode, device, xattr, acl)
                    retVal = REFRESH
                else:
                    # Otherwise, let's just get the delta
                    #self.logger.debug("Fourth case.  Should be a delta: %s", name)
                    self.db.insertFile(f, parent)
                    self.setXattrAcl(inode, device, xattr, acl)
                    retVal = DELTA
            else:
                # Create a new record for this file
                #self.logger.debug("No file found: %s", name)
                self.db.insertFile(f, parent)
                self.setXattrAcl(inode, device, xattr, acl)
                if f["nlinks"] > 1:
                    # We're a file, and we have hard links.  Check to see if I've already been handled this inode.
                    #self.logger.debug('Looking for file with same inode %d in backupset', inode)
                    # TODO: Check that the file hasn't changed since it was last written. If file is in flux,
                    # it's a problem.
                    checksum = self.db.getChecksumByInode(inode, device, True)
                    if checksum:
                        self.db.setChecksum(inode, device, checksum)
                        retVal = DONE
                    else:
                        retVal = CONTENT
                else:
                    #Check to see if it's been moved or copied
                    #self.logger.debug(u'Looking for similar file: %s (%s)', name, inode)
                    # BUG: Don't we need to extend or insert the file here?
                    old = self.db.getFileInfoBySimilar(f)

                    if old:
                        if (old["name"] == f["name"]) and (old["parent"] == parent) and (old['device'] == f['parentdev']):
                            # If the name and parent ID are the same, assume it's the same
                            #if ("checksum" in old.keys()) and not (old["checksum"] is None):
                            if not (old["checksum"] is None):
                                self.db.setChecksum(inode, device, old['checksum'])
                                retVal = DONE
                            else:
                                retVal = CONTENT
                        else:
                            # otherwise 
                            retVal = CKSUM
                    else:
                        # TODO: Lookup based on inode.
                        #self.logger.debug("No old file.")
                        retVal = CONTENT

        return retVal

    lastDirNode = None
    lastDirHash = {}

    def processDir(self, data):
        """ Process a directory message.  Lookup each file in the previous backup set, and determine if it's changed. """
        #self.logger.debug(u'Processing directory entry: {} : {}'.format(data["path"], str(data["inode"])))

        # Create some sets that we'll collect the inodes into
        # Use sets to remove duplicates due to hard links in a directory
        done = set()
        cksum = set()
        content = set()
        delta = set()
        refresh = set()

        attrs = set()
        # Keep the order
        queues = [done, content, cksum, delta, refresh]

        parentInode = tuple(data['inode'])      # Contains both inode and device in message
        files = data['files']

        dirhash = {}
        oldDir = None

        # Get the old directory info
        # If we're still in the same directory, use cached info
        if self.lastDirNode == parentInode:
            dirhash = self.lastDirHash
        else:
            # Lookup the old directory based on the path
            if data['path']:
                oldDir = self.db.getFileInfoByPath(data['path'], current=False)
            # If found, read that' guys directory
            if oldDir and oldDir['dir'] == 1:
                #### TODO: FIXME: Get actual Device
                dirInode = (oldDir['inode'], oldDir['device'])
            else:
                # Otherwise
                dirInode = parentInode

            directory = self.db.readDirectory(dirInode)
            for i in directory:
                dirhash[i["name"]] = i
            self.lastDirHash = dirhash
            self.lastDirNode = parentInode

            self.logger.debug("Got directory: %s", str(dirhash))

        for f in files:
            inode = f['inode']
            fileId = (f['inode'], f['dev'])
            self.logger.debug('Processing file: %s %s', f['name'], str(fileId))
            res = self.checkFile(parentInode, f, dirhash)
            # Shortcut for this:
            #if res == 0: done.append(inode)
            #elif res == 1: content.append(inode)
            #elif res == 2: cksum.append(inode)
            #elif res == 3: delta.append(inode)
            queues[res].add(fileId)
            if 'xattr' in f:
                xattr = f['xattr']
                # Check to see if we have this checksum
                info = self.db.getChecksumInfo(xattr)
                if (not info) or (info['size'] == -1):
                    attrs.add(xattr)


        response = {
            "message"   : "ACKDIR",
            "status"    : "OK",
            "path"      : data["path"],
            "inode"     : data["inode"],
            "last"      : data["last"],
            "done"      : list(done),
            "cksum"     : list(cksum),
            "content"   : list(content),
            "delta"     : list(delta),
            "refresh"   : list(refresh),
            "xattrs"    : list(attrs)
        }

        return (response, True)

    def processDirHash(self, message):
        checksum = message['hash']
        inode = tuple(message['inode'])
        ckinfo = self.db.getChecksumInfo(checksum)
        if ckinfo:
            cksid = ckinfo['checksumid']
        else:
            cksid = self.db.insertChecksumFile(checksum, size=message['size'], isFile=False)
        self.db.updateDirChecksum(inode, cksid)
        response = {
            "message" : "ACKDHSH",
            "status"  : "OK"
        }
        return (response, False)

    def processSigRequest(self, message):
        """ Generate and send a signature for a file """
        #self.logger.debug("Processing signature request message: %s"format(str(message)))
        (inode, dev) = message["inode"]
        response = None
        chksum = None
        errmsg = None

        ### TODO: Remove this function.  Clean up.
        info = self.db.getFileInfoByInode((inode, dev), current=True)
        if info:
            chksum = self.db.getChecksumByName(info["name"], (info["parent"], info["parentdev"]))      ### Assumption: Current parent is same as old

        if chksum:
            try:
                sigfile = chksum + ".sig"
                if self.cache.exists(sigfile):
                    file = self.cache.open(sigfile, "rb")
                    sig = file.read()       # TODO: Does this always read the entire file?
                    file.close()
                else:
                    rpipe = self.regenerator.recoverChecksum(chksum)
                    #pipe = subprocess.Popen(["rdiff", "signature"], stdin=rpipe, stdout=subprocess.PIPE)
                    #pipe = subprocess.Popen(["rdiff", "signature", self.cache.path(chksum)], stdout=subprocess.PIPE)
                    #(sig, err) = pipe.communicate()
                    # Cache the signature for later use.  Just in case.
                    # TODO: Better logic on this?
                    if rpipe:
                        try:
                            s = librsync.signature(rpipe)
                            sig = s.read()

                            outfile = self.cache.open(sigfile, "wb")
                            outfile.write(sig)
                            outfile.close()

                        except (librsync.LibrsyncError, Regenerate.RegenerateException) as e:
                            self.logger.error("Unable to generate signature for inode: {}, checksum: {}: {}".format(inode, chksum, e))
                # TODO: Break the signature out of here.
                response = {
                    "message": "SIG",
                    "inode": inode,
                    "status": "OK",
                    "encoding": self.messenger.getEncoding(),
                    "checksum": chksum,
                    "size": len(sig) }
                self.messenger.sendMessage(response)
                sigio = StringIO.StringIO(sig)
                Util.sendData(self.messenger, sigio, compress=False)
                return (None, False)
            except Exception as e:
                self.logger.error("Could not recover data for checksum: %s: %s", chksum, str(e))
                errmsg = str(e)

        if response is None:
            response = {
                "message": "SIG",
                "inode": inode,
                "status": "FAIL"
            }
            if errmsg:
                response['errmsg'] = errmsg
        return (response, False)

    def processDelta(self, message):
        """ Receive a delta message. """
        self.logger.debug("Processing delta message: %s", message)
        output  = None
        temp    = None
        checksum = message["checksum"]
        basis    = message["basis"]
        size     = message["size"]          # size of the original file, not the content
        (inode, dev)    = message["inode"]

        deltasize = message['deltasize'] if 'deltasize' in message else None
        #iv = self.messenger.decode(message['iv']) if 'iv' in message else None
        if 'iv' in message:
            iv = message['iv']
        else:
            iv = None

        savefull = self.server.savefull and iv is None
        if self.cache.exists(checksum):
            self.logger.debug("Checksum file %s already exists", checksum)
            # Abort read
        else:
            if not savefull and iv is None:
                chainLength = self.db.getChainLength(basis)
                if chainLength >= self.server.maxChain:
                    self.logger.debug("Chain length %d.  Converting %s (%s) to full save", chainLength, basis, inode)
                    savefull = True
            if savefull:
                # Save the full output, rather than just a delta.  Save the delta to a file
                #output = tempfile.NamedTemporaryFile(dir=self.tempdir, delete=True)
                output = tempfile.SpooledTemporaryFile(dir=self.tempdir, prefix=self.tempPrefix)
            else:
                output = self.cache.open(checksum, "wb")

        #if iv:
        #    output.write(base64.b64decode(iv))

        (bytesReceived, status, deltaSize, deltaChecksum, compressed) = Util.receiveData(self.messenger, output)
        logger.debug("Data Received: %d %s %d %s %d", bytesReceived, status, deltaSize, deltaChecksum, compressed)
        if status != 'OK':
            self.logger.warning("Received invalid status on data reception")
            pass

        if deltasize is None:
            # BUG: should actually be the uncompressed size, but hopefully we won't get here.
            deltasize = bytesReceived

        self.statBytesReceived += bytesReceived

        if output:
            try:
                if savefull:
                    output.seek(0)
                    if compressed:
                        delta = CompressedBuffer.UncompressedBufferedReader(output)
                        # HACK: Monkeypatch the buffer reader object to have a seek function to keep librsync happy.  Never gets called
                        delta.seek = lambda x, y: 0
                    else:
                        delta = output

                    # Process the delta file into the new file.
                    #subprocess.call(["rdiff", "patch", self.cache.path(basis), output.name], stdout=self.cache.open(checksum, "wb"))
                    basisFile = self.regenerator.recoverChecksum(basis)
                    if type(basisFile) != types.FileType:
                        # TODO: Is it possible to get here?  Is this just dead code?
                        temp = basisFile
                        basisFile = tempfile.TemporaryFile(dir=self.tempdir, prefix=self.tempPrefix)
                        shutil.copyfileobj(temp, basisFile)
                    patched = librsync.patch(basisFile, delta)
                    shutil.copyfileobj(patched, self.cache.open(checksum, "wb"))
                    self.db.insertChecksumFile(checksum, iv, size=size, disksize=bytesReceived)
                else:
                    self.db.insertChecksumFile(checksum, iv, size=size, deltasize=deltasize, basis=basis, compressed=compressed, disksize=bytesReceived)

                self.statUpdFiles += 1

                self.logger.debug("Setting checksum for inode %s to %s", inode, checksum)
                self.db.setChecksum(inode, dev, checksum)
            except Exception as e:
                logger.error("Could not insert checksum %s: %s", checksum, str(e))
            output.close()
            # TODO: This has gotta be wrong.

        flush = True if size > 1000000 else False;
        return (None, flush)

    def processSignature(self, message):
        """ Receive a signature message. """
        self.logger.debug("Processing signature message: %s", message)
        output = None
        temp = None
        checksum = message["checksum"]

        # If a signature is specified, receive it as well.
        sigfile = checksum + ".sig"
        if self.cache.exists(sigfile):
            self.logger.debug("Signature file %s already exists", sigfile)
            # Abort read
        else:
            output = self.cache.open(sigfile, "wb")

        (bytesReceived, status, size, checksum, compressed) = Util.receiveData(self.messenger, output)

        if output is not None:
            output.close()

        #self.db.setChecksum(inode, device, checksum)
        return (None, False)

    def processChecksum(self, message):
        """ Process a list of checksums """
        self.logger.debug("Processing checksum message: %s", message)
        done = []
        delta = []
        content = []
        for f in message["files"]:
            (inode, dev) = f["inode"]
            cksum = f["checksum"]
            # Check to see if the checksum exists
            # TODO: Is this faster than checking if the file exists?  Probably, but should test.
            info = self.db.getChecksumInfo(cksum)
            if info and info['size'] != -1:
                self.db.setChecksum(inode, dev, cksum)
                done.append(f['inode'])
            else:
                # FIXME: TODO: If no checksum, should we request a delta???
                #old = self.db.getFileInfoByInode(inode)
                #if old:
                content.append(f['inode'])
        message = {
            "message": "ACKSUM",
            "status" : "OK",
            "done"   : done,
            "content": content,
            "delta"  : delta
            }
        return (message, False)


    def processMeta(self, message):
        """ Check metadata messages """
        metadata = message['metadata']
        done = []
        content = []
        for cksum in metadata:
            info = self.db.getChecksumInfo(cksum)
            if info and info['size'] != -1:
                done.append(cksum)
            else:
                # Insert a placeholder with a negative size
                # But only if we don't already have one, left over from a previous failing build.
                if not info:
                    self.db.insertChecksumFile(cksum, None, -1)
                content.append(cksum)
        message = {
            'message': 'ACKMETA',
            'content': content,
            'done': done
        }
        return (message, False)
    
    def processMetaData(self, message):
        """ Process a content message, including all the data content chunks """
        self.logger.debug("Processing metadata message: %s", message)
        checksum = message['checksum']
        if self.cache.exists(checksum):
            self.logger.debug("Checksum file %s already exists", checksum)
            # Abort read
        else:
            output = self.cache.open(checksum, "w")

        # Removed the below, as we're always sending the base64 encoded string, and storing that in the DB.
        # Would be more compact to store the blob, but we're not doing that now
        #iv = self.messenger.decode(message['iv']) if 'iv' in message else None
        if 'iv' in message:
            iv = message['iv']
            #output.write(base64.b64decode(iv))
        else:
            iv = None

        (bytesReceived, status, size, cks, compressed) = Util.receiveData(self.messenger, output)
        logger.debug("Data Received: %d %s %d %s %s", bytesReceived, status, size, checksum, compressed)

        output.close()

        self.db.updateChecksumFile(checksum, iv, size, compressed=compressed, disksize=bytesReceived)
        self.statNewFiles += 1

        self.statBytesReceived += bytesReceived

        return (None, False)

    def processPurge(self, message):
        self.logger.debug("Processing purge message: {}".format(str(message)))
        prevTime = None
        if 'time' in message:
            if message['relative']:
                prevTime = float(self.db.prevBackupDate) - float(message['time'])
            else:
                prevTime = float(message['time'])
        elif self.serverKeepTime:
            prevTime = float(self.db.prevBackupDate) - float(self.serverKeepTime)

        if 'priority' in message:
            priority = message['priority']
        else:
            priority = self.serverPriority

        # Purge the files
        if prevTime:
            (files, sets) = self.db.purgeSets(priority, prevTime)
            self.logger.info("Purged %d files in %d backup sets", files, sets)
            if files:
                self.purged = True
            return ({"message": "ACKPRG", "status": "OK"}, True)
        else:
            return ({"message": "ACKPRG", "status": "FAIL"}, True)

    def processClone(self, message):
        """ Clone an entire directory """
        done = []
        content = []
        for d in message['clones']:
            inode = d['inode']
            device = d['dev']
            info = self.db.getFileInfoByInode((inode, device), current=False)

            if not info and not self.lastCompleted:
                # Check for copies in a partial directory backup, if some exist and we didn't find one here..
                # This should only happen in rare circumstances, namely if the list of directories to backup
                # has changed, and a directory which is older than the last completed backup is added to the backup.
                info = self.db.getFileInfoByInodeFromPartial((inode, device))

            if info and info['checksum'] is not None:
                numFiles = self.db.getDirectorySize((inode, device))
                if numFiles is not None:
                    logger.debug("Clone info: %s %s %s %s", info['size'], type(info['size']), info['checksum'], type(info['checksum']))
                    if (numFiles == d['numfiles']) and (info['checksum'] == d['cksum']):
                        rows = self.db.cloneDir((inode, device))
                        done.append([inode, device])
                    else:
                        self.logger.debug("No match on clone.  Inode: %d Rows: %d %d Checksums: %s %s", inode, int(info['size']), d['numfiles'], info['checksum'], d['cksum'])
                        content.append([inode, device])
                else:
                    self.logger.debug("Unable to get number of files to process clone (%d %d)", inode, device)
                    content.append([inode, device])
            else:
                self.logger.debug("No info available to process clone (%d %d)", inode, device)
                content.append([inode, device])
        return ({"message" : "ACKCLN", "done" : done, 'content' : content }, True)


    def processContent(self, message):
        """ Process a content message, including all the data content chunks """
        self.logger.debug("Processing content message: %s", message)
        temp = None
        checksum = None
        if "checksum" in message:
            checksum = message["checksum"]
            if self.cache.exists(checksum):
                self.logger.debug("Checksum file %s already exists", checksum)
                # Abort read
            else:
                output = self.cache.open(checksum, "w")
        else:
            temp = tempfile.NamedTemporaryFile(dir=self.tempdir, delete=False, prefix=self.tempPrefix)
            self.logger.debug("Sending output to temporary file %s", temp.name)
            output = temp.file

        # Removed the below, as we're always sending the base64 encoded string, and storing that in the DB.
        # Would be more compact to store the blob, but we're not doing that now
        #iv = self.messenger.decode(message['iv']) if 'iv' in message else None
        if 'iv' in message:
            iv = message['iv']
            #output.write(base64.b64decode(iv))
        else:
            iv = None

        (bytesReceived, status, size, checksum, compressed) = Util.receiveData(self.messenger, output)
        logger.debug("Data Received: %d %s %d %s %s", bytesReceived, status, size, checksum, compressed)

        output.close()

        try:
            if temp:
                if self.cache.exists(checksum):
                    self.logger.debug("Checksum file %s already exists.  Deleting temporary version", checksum)
                    os.remove(temp.name)
                else:
                    #self.logger.debug("Renaming %s to %s",temp.name, self.cache.path(checksum))
                    #self.cache.mkdir(checksum)
                    #os.rename(temp.name, self.cache.path(checksum))
                    self.cache.insert(checksum, temp.name)
                    self.db.insertChecksumFile(checksum, iv, size, compressed=compressed, disksize=bytesReceived)
            else:
                self.db.insertChecksumFile(checksum, iv, size, basis=basis, compressed=compressed, disksize=bytesReceived)

            (inode, dev) = message['inode']

            self.logger.debug("Setting checksum for inode %d to %s", inode, checksum)
            self.db.setChecksum(inode, dev, checksum)
            self.statNewFiles += 1

        except Exception as e:
            logger.error("Could insert checksum %s info: %s", checksum, str(e))
            if self.server.exceptions:
                logger.exception(e)

        self.statBytesReceived += bytesReceived

        #return {"message" : "OK", "inode": message["inode"]}
        flush = False
        if bytesReceived > 1000000:
            flush = True;
        return (None, flush)

    def processBatch(self, message):
        batch = message['batch']
        responses = []
        for mess in batch:
            (response, flush) = self.processMessage(mess)
            responses.append(response)

        response = { 
            'message': 'ACKBTCH',
            'responses': responses
        }
        return (response, True)

    def processSetKeys(self, message):
        filenameKey = message['filenameKey']
        contentKey  = message['contentKey']
        token       = message['token']

        ret = self.db.setKeys(token, filenameKey, contentKey)
        response = {
            'message': 'ACKSETKEYS',
            'response': 'OK' if ret else 'FAIL'
        }
        return (response, True)

    def processMessage(self, message):
        """ Dispatch a message to the correct handlers """
        messageType = message['message']
        # Stats
        self.statCommands[messageType] = self.statCommands.get(messageType, 0) + 1

        if messageType == "DIR":
            (response, flush) = self.processDir(message)
        elif messageType == "DHSH":
            (response, flush) = self.processDirHash(message)
        elif messageType == "SGR":
            (response, flush) = self.processSigRequest(message)
        elif messageType == "SIG":
            (response, flush) = self.processSignature(message)
        elif messageType == "DEL":
            (response, flush) = self.processDelta(message)
        elif messageType == "CON":
            (response, flush) = self.processContent(message)
        elif messageType == "CKS":
            (response, flush) = self.processChecksum(message)
        elif messageType == "CLN":
            (response, flush) = self.processClone(message)
        elif messageType == "BATCH":
            (response, flush) = self.processBatch(message)
        elif messageType == "PRG":
            (response, flush) = self.processPurge(message)
        elif messageType == "META":
            (response, flush) =  self.processMeta(message)
        elif messageType == "METADATA":
            (response, flush) =  self.processMetaData(message)
        elif messageType == "SETKEYS":
            (response, flush) = self.processSetKeys(message)
        else:
            raise Exception("Unknown message type", messageType)

        if response and 'msgid' in message:
            response['respid'] = message['msgid']

        return (response, flush)

    def getDB(self, host, token):
        script = None
        ret = "EXISTING"
        journal = None
        self.basedir = os.path.join(self.server.basedir, host)
        self.cache = CacheDir.CacheDir(self.basedir, 2, 2, create=self.server.allowNew, user=self.server.user, group=self.server.group)
        self.dbfile = os.path.join(self.basedir, self.server.dbname)

        if self.server.journal:
            journal = os.path.join(self.basedir, self.server.journal)

        connid = {'connid': self.idstr }

        if not os.path.exists(self.dbfile):
            if self.server.requirePW and token is None:
                self.logger.warning("No password specified.  Cannot create")
                raise InitFailedException("Password required for creation")
            self.logger.debug("Initializing database for %s with file %s", host, schemaFile)
            script = schemaFile
            ret = "NEW"

        self.db = TardisDB.TardisDB(self.dbfile,
                                    initialize=script,
                                    backup=True,
                                    connid=connid,
                                    token=token,
                                    user=self.server.user,
                                    group=self.server.group,
                                    numbackups=self.server.dbbackups,
                                    journal=journal)

        self.regenerator = Regenerate.Regenerator(self.cache, self.db)
        return ret

    def startSession(self, name, force):
        self.name = name

        # Check if the previous backup session completed.
        prev = self.db.lastBackupSet(completed=False)
        if prev['endtime'] is None:
            if force:
                self.logger.warning("Staring session %s while previous backup still warning: %s", name, prev['name'])
            else:
                raise InitFailedException("Previous backup session still running: {}.  Run with --force to force starting the new backup".format(prev['name']))

        # Mark if the last secssion was completed
        self.lastCompleted = prev['completed']
        self.tempdir = os.path.join(self.basedir, "tmp")
        if not os.path.exists(self.tempdir):
            os.makedirs(self.tempdir)

    def endSession(self):
        try:
            pass
            #if (self.tempdir):
                # Clean out the temp dir
                #`shutil.rmtree(self.tempdir)
        except OSError as error:
            self.logger.warning("Unable to delete temporary directory: %s: %s", self.tempdir, error.strerror)

    def removeOrphans(self):
        # Now remove any leftover orphans
        size = 0
        count = 0
        if self.db:
            # Get a list of orphan'd files
            orphans = self.db.listOrphanChecksums()
            self.logger.debug("Attempting to remove orphans")
            for c in orphans:
                # And remove them each....
                try:
                    path = self.cache.path(c)
                    if os.path.exists(path):
                        s = os.stat(self.cache.path(c))
                        count += 1
                        size += s.st_size
                        self.cache.remove(c)
                    sig = c + ".sig"
                    sigpath = self.cache.path(sig)
                    if os.path.exists(sigpath):
                        s = os.stat(self.cache.path(sig))
                        if s:
                            count += 1
                            size += s.st_size
                        self.cache.remove(sig)
                    self.db.deleteChecksum(c)
                except OSError:
                    self.logger.warning("Unable to remove checksum %s", c)
                except Exception as e:
                    if self.server.exceptions:
                        self.logger.exception(e)
            if count:
                self.purged = True
            return (count, size)

    def calcAutoInfo(self, clienttime):
        """ Calculate a name if autoname is passed in. """
        starttime = datetime.fromtimestamp(clienttime)
        # Figure out if a monthly set has been made.
        name = starttime.strftime(self.server.monthfmt)
        if (self.db.checkBackupSetName(name)):
            return (name, self.server.monthprio, self.server.monthkeep)

        # Figure out if we've tried something this week
        name = starttime.strftime(self.server.weekfmt)
        if (self.db.checkBackupSetName(name)):
            return (name, self.server.weekprio, self.server.weekkeep)

        # Must be daily
        #name = 'Daily-{}'.format(starttime.strftime("%Y-%m-%d"))
        name = starttime.strftime(self.server.dayfmt)
        if (self.db.checkBackupSetName(name)):
            return (name, self.server.dayprio, self.server.daykeep)

        # Oops, nothing worked.  Didn't change the name.
        return (None, None, None)

    def confirmToken(self, token):
        dbToken = self.db.getToken()
        if dbToken:
            if not self.db.checkToken(token):
                if token:
                    self.logger.warning("Login attempt with invalid token: %s", token)
                    raise InitFailedException("Password doesn't match")
                else:
                    self.logger.warning("No token specified for login")
                    raise InitFailedException("Password required for login")
        elif token:
            self.logger.info("Setting token to: %s", token)
            self.db.setToken(token)

    def handle(self):
        printMessages = self.logger.isEnabledFor(logging.TRACE)
        started   = False
        completed = False
        starttime = datetime.now()
        host = ""

        if self.server.profiler:
            self.logger.info("Starting Profiler")
            self.server.profiler.enable()

        try:
            sock = self.request
            sock.settimeout(args.timeout)

            if self.server.ssl:
                sock.sendall(Connection.sslHeaderString)
                sock = ssl.wrap_socket(sock, server_side=True, certfile=self.server.certfile, keyfile=self.server.keyfile)
            else:
                sock.sendall(Connection.headerString)

            message = sock.recv(1024)
            self.logger.debug(message)
            message = message.strip()

            fields = json.loads(message)
            try:
                messType    = fields['message']
                if not messType == 'BACKUP':
                    raise InitFailedException("Unknown message type: {}".format(messType))

                host        = fields['host']
                encoding    = fields['encoding']
                name        = fields['name']
                priority    = fields['priority']
                force       = fields['force']
                version     = fields['version']
                clienttime  = fields['time']
                autoname    = fields['autoname']
                compress    = fields['compress']
                version     = fields['version']
                if 'token' in fields:
                    token = fields['token']
                else:
                    token = None
                self.logger.info("Creating backup for %s: %s (Autoname: %s) %s %s", host, name, str(autoname), version, clienttime)
            except ValueError as e:
                raise InitFailedException("Cannot parse JSON field: {}".format(message))
            except KeyError as e:
                raise InitFailedException(str(e))

            serverName = None
            try:
                new = self.getDB(host, token)
                self.startSession(name, force)
                if priority is None:
                    priority = 0
                self.db.newBackupSet(name, str(self.sessionid), priority, clienttime, version, self.address)
                if autoname:
                    (serverName, serverPriority, serverKeepDays) = self.calcAutoInfo(clienttime)
                    self.logger.debug("Setting name, priority, keepdays to %s", (serverName, serverPriority, serverKeepDays))
                    if serverName:
                        self.serverKeepTime = serverKeepDays * 3600 * 24
                        self.serverPriority = serverPriority
                    else:
                        self.serverKeepTime = None
                        self.serverPriority = None
            except Exception as e:
                message = {"status": "FAIL", "error": str(e)}
                sock.sendall(json.dumps(message))
                if self.server.exceptions:
                    self.logger.exception(e)
                raise InitFailedException(str(e))

            if encoding == "JSON":
                self.messenger = Messages.JsonMessages(sock, compress=compress)
            elif encoding == 'MSGP':
                self.messenger = Messages.MsgPackMessages(sock, compress=compress)
            elif encoding == "BSON":
                self.messenger = Messages.BsonMessages(sock, compress=compress)
            else:
                message = {"status": "FAIL", "error": "Unknown encoding: {}".format(encoding)}
                sock.sendall(json.dumps(message))
                raise InitFailedException("Unknown encoding: ", encoding)

            response = {
                "status": "OK",
                "sessionid": str(self.sessionid),
                "prevDate": str(self.db.prevBackupDate),
                "new": new,
                "name": serverName if serverName else name,
                "clientid": str(self.db.clientId)
                }
            if token:
                filenameKey = self.db.getConfigValue('FilenameKey')
                contentKey  = self.db.getConfigValue('ContentKey')

                if (filenameKey is None) ^ (contentKey is None):
                    self.logger.warning("Name Key and Data Key are both not in the same state. FilenameKey: %s  ContentKey: %s", filenameKey, contentKey)
                
                if filenameKey:
                    response['filenameKey'] = filenameKey
                if contentKey:
                    response['contentKey'] = contentKey

            sock.sendall(json.dumps(response))

            started = True

            #sock.sendall("OK {} {} {}".format(str(self.sessionid), str(self.db.prevBackupDate), serverName if serverName else name))
            done = False;

            while not done:
                flush = False
                message = self.messenger.recvMessage()
                if printMessages:
                    self.logger.log(logging.TRACE, "Received:\n" + str(pp.pformat(message)).encode("utf-8"))
                if message["message"] == "BYE":
                    done = True
                else:
                    (response, flush) = self.processMessage(message)
                    if response:
                        if printMessages:
                            self.logger.log(logging.TRACE, "Sending:\n" + str(pp.pformat(response)))
                        self.messenger.sendMessage(response)
                if flush:
                    self.db.commit()

            self.db.completeBackup()

            if autoname and serverName is not None:
                self.logger.info("Changing backupset name from %s to %s.  Priority is %s", name, serverName, serverPriority)
                self.db.setBackupSetName(serverName, serverPriority)
                #self.db.renameBackupSet(newName, newPriority)
            completed = True
        except InitFailedException as e:
            self.logger.error("Connection initialization failed: %s", e)
            if self.server.exceptions:
                self.logger.exception(e)
        except Exception as e:
            self.logger.error("Caught exception %s: %s", type(e), e)
            if self.server.exceptions:
                self.logger.exception(e)
        finally:
            sock.close()
            if started:
                self.endSession()
            endtime = datetime.now()

            if self.server.profiler:
                self.logger.info("Stopping Profiler")
                self.server.profiler.disable()
                s = StringIO.StringIO()
                sortby = 'cumulative'
                ps = pstats.Stats(self.server.profiler, stream=s).sort_stats(sortby)
                ps.print_stats()
                print s.getvalue()

            if started:
                (count, size) = self.removeOrphans()
                self.logger.info("Connection completed successfully: %s  Runtime: %s", str(completed), str(endtime - starttime))
                self.logger.info("New or replaced files:    %d", self.statNewFiles)
                self.logger.info("Updated files:            %d", self.statUpdFiles)
                self.logger.info("Total file data received: %s (%d)", Util.fmtSize(self.statBytesReceived), self.statBytesReceived)
                self.logger.info("Command breakdown:        %s", self.statCommands)
                self.logger.info("Removed Orphans           %d (%s)", count, Util.fmtSize(size))

                self.logger.debug("Removing orphans")
                self.db.compact()

            if self.db:
                self.db.close(started)

        self.logger.info("Session from %s {%s} Ending: %s: %s", host, self.sessionid, str(completed), str(datetime.now() - starttime))

#class TardisSocketServer(SocketServer.TCPServer):
class TardisSocketServer(SocketServer.ForkingMixIn, SocketServer.TCPServer):
    def __init__(self, args, config):
        self.config = config
        self.args = args

        if args.reuseaddr:
            # Allow reuse of the address before timeout if requested.
            self.allow_reuse_address = True

        SocketServer.TCPServer.__init__(self, ("", args.port), TardisServerHandler)
        setConfig(self, args, config)
        logger.info("TCP Server %s Running: %s", Tardis.__version__, self.dbname)

class TardisDomainSocketServer(SocketServer.UnixStreamServer):
    def __init__(self, args, config):
        self.config = config
        self.args = args
        SocketServer.UnixStreamServer.__init__(self,  args.local, TardisServerHandler)
        setConfig(self, args, config)
        logger.info("Unix Domain Socket %s Server Running: %s", Tardis.__version__, self.dbname)

# HACK.  Operate on an object, but not in the class.
# Want to do this in multiple classes.
def setConfig(self, args, config):
    self.basedir        = config.get('Tardis', 'BaseDir')
    self.savefull       = config.getboolean('Tardis', 'SaveFull')
    self.maxChain       = config.getint('Tardis', 'MaxDeltaChain')
    self.deltaPercent   = float(config.getint('Tardis', 'MaxChangePercent')) / 100.0        # Convert to a ratio

    self.dbname         = args.dbname
    self.allowNew       = args.newhosts
    self.schemaFile     = args.schema
    self.journal        = args.journal

    self.timeout        = args.timeout

    self.requirePW      = config.getboolean('Tardis', 'RequirePassword')

    self.monthfmt       = config.get('Tardis', 'MonthFmt')
    self.monthprio      = config.getint('Tardis', 'MonthPrio')
    self.monthkeep      = Util.getIntOrNone(config, 'Tardis', 'MonthKeep')
    self.weekfmt        = config.get('Tardis', 'WeekFmt')
    self.weekprio       = config.getint('Tardis', 'WeekPrio')
    self.weekkeep       = Util.getIntOrNone(config, 'Tardis', 'WeekKeep')
    self.dayfmt         = config.get('Tardis', 'DayFmt')
    self.dayprio        = config.getint('Tardis', 'DayPrio')
    self.daykeep        = Util.getIntOrNone(config, 'Tardis', 'DayKeep')

    self.dbbackups      = config.getint('Tardis', 'DBBackups')

    self.exceptions     = args.exceptions

    self.umask          = Util.getIntOrNone(config, 'Tardis', 'Umask')

    self.user = None
    self.group = None

    # If the User or Group is set, attempt to determine the users
    # Note, these will throw exeptions if the User or Group is unknown.  Will get
    # passed up.
    if args.user:
        self.user = pwd.getpwnam(args.user).pw_uid
    if args.group:
        self.group = grp.getgrnam(args.group).gr_gid

    # Get SSL set up, if it's been requested.
    self.ssl            = args.ssl
    self.certfile       = args.certfile
    self.keyfile        = args.keyfile

    if args.profile:
        self.profiler = cProfile.Profile()
    else:
        self.profiler = None

def setupLogging():
    levels = [logging.WARNING, logging.INFO, logging.DEBUG, logging.TRACE]

    logging.addLevelName(logging.TRACE, 'Message')
    logging.addLevelName(logging.MSGS,  'MSG')

    if args.logcfg:
        logging.config.fileConfig(args.logcfg)
        logger = logging.getLogger('')
    else:
        logger = logging.getLogger('')
        format = logging.Formatter("%(asctime)s %(levelname)s : %(message)s")

        verbosity = args.verbose

        if args.local:
            # Always send output to stderr for local connections
            handler = logging.StreamHandler()
        elif args.logfile:
            handler = logging.handlers.WatchedFileHandler(args.logfile)
        elif args.daemon:
            handler = logging.handlers.SysLogHandler()
        else:
            handler = logging.StreamHandler()

        handler.setFormatter(format)
        logger.addHandler(handler)

        loglevel = levels[verbosity] if verbosity < len(levels) else logging.DEBUG
        logger.setLevel(loglevel)

    return logger

def run_server():
    global server

    try:
        #server = SocketServer.TCPServer(("", config.getint('Tardis', 'Port')), TardisServerHandler)
        if args.local:
            logger.info("Starting server Socket: %s", args.local);
            server = TardisDomainSocketServer(args, config)
        else:
            logger.info("Starting server Port: %d", config.getint('Tardis', 'Port'));
            server = TardisSocketServer(args, config)

        if args.single:
            server.handle_request()
        else:
            try:
                server.serve_forever()
            except:
                logger.info("Socket server completed")
        logger.info("Ending")
    except Exception as e:
        logger.critical("Unable to run server: {}".format(e))
        if args.exceptions:
            logger.exception(e)

def stop_server():
    logger.info("Stopping server")
    server.shutdown()

def signal_term_handler(signal, frame):
    logger.info("Caught term signal.  Stopping")
    t = threading.Thread(target = shutdownHandler)
    t.start()
    logger.info("Server stopped")

def shutdownHandler():
    stop_server()

def processArgs():
    parser = argparse.ArgumentParser(description='Tardis Backup Server', formatter_class=Util.HelpFormatter, add_help=False)

    parser.add_argument('--config',         dest='config', default=configName, help="Location of the configuration file (Default: %(default)s)")
    (args, remaining) = parser.parse_known_args()

    t = 'Tardis'
    config = ConfigParser.ConfigParser(configDefaults)
    config.add_section(t)                   # Make it safe for reading other values from.
    config.read(args.config)

    parser.add_argument('--port',               dest='port',            default=config.getint(t, 'Port'), type=int, help='Listen on port (Default: %(default)s)')
    parser.add_argument('--dbname',             dest='dbname',          default=config.get(t, 'DBName'), help='Use the database name (Default: %(default)s)')
    parser.add_argument('--schema',             dest='schema',          default=config.get(t, 'Schema'), help='Path to the schema to use (Default: %(default)s)')
    parser.add_argument('--logfile', '-l',      dest='logfile',         default=config.get(t, 'LogFile'), help='Log to file')
    parser.add_argument('--logcfg',             dest='logcfg',          default=config.get(t, 'LogCfg'), help='Logging configuration file');
    parser.add_argument('--verbose', '-v',      dest='verbose',         action='count', default=config.getint(t, 'Verbose'), help='Increase the verbosity (may be repeated)')
    parser.add_argument('--log-exceptions',     dest='exceptions',      action=Util.StoreBoolean, default=config.getboolean(t, 'LogExceptions'), help='Log full exception details')
    parser.add_argument('--allow-new-hosts',    dest='newhosts',        action=Util.StoreBoolean, default=config.getboolean(t, 'AllowNewHosts'),
                                                                        help='Allow new clients to attach and create new backup sets')
    parser.add_argument('--profile',            dest='profile',         default=config.getboolean(t, 'Profile'), help='Generate a profile')

    parser.add_argument('--single',             dest='single',          action=Util.StoreBoolean, default=config.getboolean(t, 'Single'), 
                                                                        help='Run a single transaction and quit')
    parser.add_argument('--local',              dest='local',           default=config.get(t, 'Local'),
                                                                        help='Run as a Unix Domain Socket Server on the specified filename')

    parser.add_argument('--timeout',            dest='timeout',         default=config.getint(t, 'Timeout'), type=float, help='Timeout, in seconds.  0 for no timeout (Default: %(default)s)')
    parser.add_argument('--journal', '-j',      dest='journal',         default=config.get(t, 'JournalFile'), help='Journal file actions to this file (Default: %(default)s)')

    parser.add_argument('--reuseaddr',          dest='reuseaddr',       action=Util.StoreBoolean,default=config.getboolean(t, 'ReuseAddr'),
                                                                        help='Reuse the socket address immediately')

    parser.add_argument('--daemon',             dest='daemon',          action=Util.StoreBoolean, default=config.getboolean(t, 'Daemon'),
                                                                        help='Run as a daemon')
    parser.add_argument('--user',               dest='user',            default=config.get(t, 'User'), help='Run daemon as user.  Valid only if --daemon is set')
    parser.add_argument('--group',              dest='group',           default=config.get(t, 'Group'), help='Run daemon as group.  Valid only if --daemon is set')
    parser.add_argument('--pidfile',            dest='pidfile',         default=config.get(t, 'PidFile'), help='Use this pidfile to indicate running daemon')

    parser.add_argument('--ssl',                dest='ssl',             action=Util.StoreBoolean, default=config.getboolean(t, 'SSL'), help='Use SSL connections')
    parser.add_argument('--certfile',           dest='certfile',        default=config.get(t, 'CertFile'), help='Path to certificate file for SSL connections')
    parser.add_argument('--keyfile',            dest='keyfile',         default=config.get(t, 'KeyFile'), help='Path to key file for SSL connections')

    parser.add_argument('--version',            action='version', version='%(prog)s ' + Tardis.__version__ + ' ' + Tardis.__buildversion__,    help='Show the version')
    parser.add_argument('--help', '-h',         action='help')

    args = parser.parse_args(remaining)
    return(args, config)

def main():
    global logger, args, config
    (args, config) = processArgs()

    # Set up a handler
    signal.signal(signal.SIGTERM, signal_term_handler)
    try:
        logger = setupLogging()
    except Exception as e:
        print >> sys.stderr, "Unable to initialize logging: {}".format(str(e))
        if args.exceptions:
            traceback.print_exc()
        sys.exit(1)

    if args.daemon and not args.local:
        user  = args.user
        group = args.group
        pidfile = args.pidfile
        fds = [h.stream.fileno() for h in logger.handlers if isinstance(h, logging.StreamHandler)]
        logger.info("About to daemonize")

        try:
            daemon = daemonize.Daemonize(app="tardisd", pid=pidfile, action=run_server, user=user, group=group, keep_fds=fds)
            daemon.start()
        except Exception as e:
            logger.critical("Caught Exception on Daemonize call: {}".format(e))
            if args.exceptions:
                logger.exception(e)
    else:
        try:
            run_server()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.critical("Unable to run server: {}".format(e))
            if args.exceptions:
                logger.exception(e)

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        traceback.print_exc()

