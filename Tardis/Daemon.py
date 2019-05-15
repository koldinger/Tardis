# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2019, Eric Koldinger, All Rights Reserved.
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
import string
import pwd
import grp
import argparse
import uuid
import logging
import logging.config
import configparser
import socketserver
import ssl
import pprint
import tempfile
import shutil
import traceback
import signal
import threading
import json
import base64
from datetime import datetime

# For profiling
import cProfile
import io
import pstats

import daemonize
import colorlog

import Tardis
import Tardis.ConnIdLogAdapter as ConnIdLogAdapter
import Tardis.Messages as Messages
import Tardis.CacheDir as CacheDir
import Tardis.TardisDB as TardisDB
import Tardis.Regenerator as Regenerator
import Tardis.Util as Util
import Tardis.Defaults as Defaults
import Tardis.Connection as Connection
import Tardis.CompressedBuffer as CompressedBuffer
import Tardis.librsync as librsync

DONE    = 0
CONTENT = 1
CKSUM   = 2
DELTA   = 3
REFRESH = 4                     # Perform a full content update
LINKED  = 5                     # Check if it's already linked

config = None
args   = None
configSection = 'Daemon'

databaseName    = Defaults.getDefault('TARDIS_DBNAME')
schemaName      = Defaults.getDefault('TARDIS_SCHEMA')
configName      = Defaults.getDefault('TARDIS_DAEMON_CONFIG')
baseDir         = Defaults.getDefault('TARDIS_DB')
dbDir           = Defaults.getDefault('TARDIS_DBDIR')
portNumber      = Defaults.getDefault('TARDIS_PORT')
pidFileName     = Defaults.getDefault('TARDIS_PIDFILE')
journalName     = Defaults.getDefault('TARDIS_JOURNAL')
timeout         = Defaults.getDefault('TARDIS_TIMEOUT')
logExceptions   = Defaults.getDefault('TARDIS_LOGEXCEPTIONS')
skipFile        = Defaults.getDefault('TARDIS_SKIP')

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
    'DBDir'             : dbDir,
    'DBName'            : databaseName,
    'Schema'            : schemaFile,
    'LogCfg'            : '',
    'Profile'           : str(False),
    'LogFile'           : '',
    'JournalFile'       : journalName,
    'LinkBasis'         : str(False),
    'LogExceptions'     : str(False),
    'AllowNewHosts'     : str(False),
    'RequirePassword'   : str(False),
    'Single'            : str(False),
    'Local'             : '',
    'Verbose'           : '0',
    'Daemon'            : str(False),
    'Umask'             : '027',
    'User'              : '',
    'Group'             : '',
    'SSL'               : str(False),
    'Timeout'           : timeout,
    'CertFile'          : '',
    'KeyFile'           : '',
    'PidFile'           : pidFileName,
    'ReuseAddr'         : str(False),
    'Formats'           : 'Monthly-%Y-%m, Weekly-%Y-%U, Daily-%Y-%m-%d',
    'Priorities'        : '40, 30, 20',
    'KeepDays'          : '0, 180, 30',
    'ForceFull'         : '0, 0, 0',
    'MaxDeltaChain'     : '5',
    'MaxChangePercent'  : '50',
    'SaveFull'          : str(False),
    'SkipFileName'      : skipFile,
    'DBBackups'         : '0',
    'CksContent'        : '65536',
    'AutoPurge'         : str(False),
    'SaveConfig'        : str(True),
    'AllowClientOverrides'  :  str(True),
    'AllowSchemaUpgrades'   :  str(False),
}

server = None
logger = None

pp = pprint.PrettyPrinter(indent=2, width=1000)

logging.TRACE = logging.DEBUG - 1
logging.MSGS  = logging.DEBUG - 2

def makeDict(row):
    if row:
        d = {}
        for i in list(row.keys()):
            d[i] = row[i]
        return d
    return None

class InitFailedException(Exception):
    pass

class ProtocolError(Exception):
    pass

class TardisServerHandler(socketserver.BaseRequestHandler):
    numfiles = 0
    logger   = None
    sessionid = None
    tempdir = None
    cache   = None
    db      = None
    purged  = False
    full    = False
    statNewFiles = 0
    statUpdFiles = 0
    statDirs     = 0
    statBytesReceived = 0
    statPurgedFiles = 0
    statPurgedSets = 0
    statCommands = {}
    address = ''
    regenerator = None
    basedir = None
    autoPurge = False
    saveConfig = False
    deltaPercent = 80
    forceFull = False
    saveFull = False
    lastCompleted = None
    maxChain = 0

    def checkMessage(self, message, expected):
        """ Check that a message is of the expected type.  Throw an exception if not """
        if not message['message'] == expected:
            logger.critical("Expected {} message, received {}".format(expected, message['message']))
            raise ProtocolError("Expected {} message, received {}".format(expected, message['message']))

    def setup(self):
        self.statCommands = {}
        self.sessionid = str(uuid.uuid1())
        log            = logging.getLogger('Tardis')
        self.idstr  = self.sessionid[0:13]   # Leading portion (ie, timestamp) of the UUID.  Sufficient for logging.
        self.logger = ConnIdLogAdapter.ConnIdLogAdapter(log, {'connid': self.idstr})
        self.printMessages = True if self.logger.isEnabledFor(logging.TRACE) else False
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
        self.server.rmSession(self.sessionid)

    def setXattrAcl(self, inode, device, xattr, acl):
        self.logger.debug("Setting Xattr and ACL info: %d %s %s", inode, xattr, acl)
        if xattr:
            self.db.setXattrs(inode, device, xattr)
        if acl:
            self.db.setAcl(inode, device, acl)

    def sendMessage(self, message):
        if not 'message' in message:
            self.logger.error("No `message` block in message: %s", message)
        if self.printMessages:
            self.logger.log(logging.TRACE, "Sending:\n" + pp.pformat(message))
        self.messenger.sendMessage(message)

    def recvMessage(self):
        message = self.messenger.recvMessage()
        if self.printMessages:
            self.logger.log(logging.TRACE, "Received:\n" + pp.pformat(message))
        return message

    sizes = set()
    sizesLoaded = False
    def checkForSize(self, size):
        if not self.sizesLoaded:
            self.logger.debug("Loading sizes")
            for i in self.db.getFileSizes(self.server.cksContent):
                self.sizes.add(i[0])
            self.logger.debug("Size loading complete: %d", len(self.sizes))
            self.sizesLoaded = True

        if (size > self.server.cksContent) and (size in self.sizes):
            return CKSUM
        else:
            return CONTENT

    def checkFile(self, parent, f, dirhash):
        """
        Process an individual file.  Check to see if it's different from what's there already
        """
        xattr = None
        acl = None
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
        fromPartial = False

        if f["dir"] == 1:
            #self.logger.debug("Is a directory: %s", name)
            if old:
                if (old["inode"] == inode) and (old["device"] == device) and (old["mtime"] == f["mtime"]):
                    self.db.extendFileInode(parent, (inode, device))
                else:
                    self.db.insertFile(f, parent)
                    self.setXattrAcl(inode, device, xattr, acl)
            else:
                self.db.insertFile(f, parent)
                self.setXattrAcl(inode, device, xattr, acl)
            retVal = DONE
        else:       # Not a directory, it's a file
            # Check to see if there's an updated version.
            if not self.lastCompleted:
                # not in this directory, but lets look further in any incomplete sets if there are any
                #self.logger.debug("Looking up file in partial backup(s): %s (%s)", name, inode)
                tmp = self.db.getFileFromPartialBackup(f)
                if tmp:
                    old = tmp
                    fromPartial = old['lastset']
                    self.logger.debug("Found %s in partial backup set: %d", name, old['lastset'])
            if old:
                #self.logger.debug("Comparing version:  New: %s", str(f))
                #self.logger.debug("Comparing version:  Old: %s", str(makeDict(old)))

                # Got something.  If the inode, size, and mtime are the same, just keep it
                fsize = f['size']
                osize = old['size']

                if (old["inode"] == inode) and (old['device'] == device) and (osize == fsize) and (old["mtime"] == f["mtime"]):
                    #self.logger.debug("Main info matches: %s", name)
                    #if ("checksum" in old.keys()) and not (old["checksum"] is None):
                    if not old["checksum"] is None:
                        #self.db.setChecksum(inode, device, old['checksum'])
                        if (old['mode'] == f['mode']) and (old['ctime'] == f['ctime']) and (old['xattrs'] == xattr) and (old['acl'] == acl):
                            # nothing has changed, just extend it
                            #self.logger.debug("Extending %s", name)
                            self.db.extendFileInode(parent, (inode, device), old=fromPartial)
                        else:
                            # Some metadata has changed, so let's insert the new record, and set it's checksum
                            #self.logger.debug("Inserting new version %s", name)
                            self.db.insertFile(f, parent)
                            self.db.setChecksum(inode, device, old['checksum'])
                            self.setXattrAcl(inode, device, xattr, acl)
                        if self.full and old['chainlength'] != 0:
                            retVal = REFRESH
                        else:
                            retVal = DONE       # we're done either way
                    else:
                        # Otherwise we need a whole new file
                        #self.logger.debug("No checksum: Get new file %s", name)
                        self.db.insertFile(f, parent)
                        self.setXattrAcl(inode, device, xattr, acl)
                        retVal = CONTENT
                #elif (osize == fsize) and ("checksum" in old.keys()) and not (old["checksum"] is None):
                elif (osize == fsize) and (not old["checksum"] is None):
                    #self.logger.debug("Secondary match, requesting checksum: %s", name)
                    # Size hasn't changed, but something else has.  Ask for a checksum
                    self.db.insertFile(f, parent)
                    self.setXattrAcl(inode, device, xattr, acl)
                    retVal = CKSUM
                elif (f["size"] < 4096) or (old["size"] is None) or \
                     not ((old['size'] * self.deltaPercent) < f['size'] < (old['size'] * (1.0 + self.deltaPercent))) or \
                     ((old["basis"] is not None) and (old["chainlength"]) >= self.maxChain):
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
                    if self.full:
                        # Full backup, request the full version anyhow.
                        retVal = CONTENT
                    else:
                        retVal = DELTA
            else:
                # Create a new record for this file
                #self.logger.debug("No file found: %s", name)
                self.db.insertFile(f, parent)
                self.setXattrAcl(inode, device, xattr, acl)
                if f["nlinks"] > 1:
                    # We're a file, and we have hard links.  Check to see if I've already been handled this inode.
                    # self.logger.debug('Looking for file with same inode %d: %s', inode, f['name'])
                    # TODO: Check that the file hasn't changed since it was last written. If file is in flux,
                    # it's a problem.
                    checksum = self.db.getChecksumByInode(inode, device, True)
                    #self.logger.debug('Checksum for inode %d: %s -- %s', inode, f['name'], checksum)
                    if checksum:
                        #self.logger.debug('Setting linked inode %d: %s to checksum %s', inode, f['name'], checksum)
                        self.db.setChecksum(inode, device, checksum)
                        retVal = LINKED             # special value, allowing the caller to determine that this was handled as a link
                    else:
                        #self.logger.debug('No link data found for inode %d: %s.   Requesting new content', inode, f['name'])
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
                            if old["checksum"] is not None:
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
                        retVal = self.checkForSize(f['size'])

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
            if 'path' in data and data['path']:
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
            fileId = (f['inode'], f['dev'])
            self.logger.debug('Processing file: %s %s', f['name'], str(fileId))
            res = self.checkFile(parentInode, f, dirhash)
            # Shortcut for this:
            #if res == 0: done.append(inode)
            #elif res == 1: content.append(inode)
            #elif res == 2: cksum.append(inode)
            #elif res == 3: delta.append(inode)
            if res == LINKED:
                # Determine if this fileid is already in one of the queues
                if not filter(lambda x: fileId in x, queues):
                    queues[DONE].add(fileId)
            else:
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
            cksid = self.db.insertChecksumFile(checksum, encrypted=False, size=message['size'], isFile=False)
        self.db.updateDirChecksum(inode, cksid)
        response = {
            "message" : "ACKDHSH",
            "status"  : "OK"
        }
        return (response, False)

    def processManySigsRequest(self, message):
        inodes = message['inodes']
        for i in inodes:
            (inode, dev) = i
            self.sendSignature(inode, dev)
        response = {
            'message': "SIG",
            'status' : "DONE"
        }
        return(response, True)

    def processSigRequest(self, message):
        """ Generate and send a signature for a file """
        #self.logger.debug("Processing signature request message: %s"format(str(message)))
        (inode, dev) = message["inode"]
        return self.sendSignature(inode, dev)

    def sendSignature(self, inode, dev):
        response = None
        chksum = None
        errmsg = None

        ### TODO: Remove this function.  Clean up.
        info = self.db.getFileInfoByInode((inode, dev), current=True)
        if info:
            chksum = self.db.getChecksumByName(info["name"], (info["parent"], info["parentdev"]))      ### Assumption: Current parent is same as old
        else:
            self.logger.error("No Checksum Info available for %s in (%d, %d)", info['name'], info['parent'], info['parentdev'])

        if chksum:
            try:
                sigfile = chksum + ".sig"
                if self.cache.exists(sigfile):
                    sigfile = self.cache.open(sigfile, "rb")
                    sig = sigfile.read()       # TODO: Does this always read the entire file?
                    sigfile.close()
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

                        except (librsync.LibrsyncError, Regenerator.RegenerateException) as e:
                            self.logger.error("Unable to generate signature for inode: {}, checksum: {}: {}".format(inode, chksum, e))
                # TODO: Break the signature out of here.
                response = {
                    "message": "SIG",
                    "inode": (inode, dev),
                    "status": "OK",
                    "encoding": self.messenger.getEncoding(),
                    "checksum": chksum,
                    "size": len(sig) }
                self.sendMessage(response)
                sigio = io.BytesIO(sig)
                Util.sendData(self.messenger, sigio, compress=None)
                return (None, False)
            except Exception as e:
                self.logger.error("Could not recover data for checksum: %s: %s", chksum, str(e))
                if args.exceptions:
                    logger.exception(e)
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
        encrypted = message.get('encrypted', False)

        savefull = self.server.savefull and not encrypted
        if self.cache.exists(checksum):
            self.logger.debug("Checksum file %s already exists", checksum)
            # Abort read
        else:
            if not savefull:
                chainLength = self.db.getChainLength(basis)
                if chainLength >= self.maxChain:
                    self.logger.debug("Chain length %d.  Converting %s (%s) to full save", chainLength, basis, inode)
                    savefull = True
            if savefull:
                # Save the full output, rather than just a delta.  Save the delta to a file
                #output = tempfile.NamedTemporaryFile(dir=self.tempdir, delete=True)
                output = tempfile.SpooledTemporaryFile(dir=self.tempdir, prefix=self.tempPrefix)
            else:
                output = self.cache.open(checksum, "wb")

        (bytesReceived, status, deltaSize, deltaChecksum, compressed) = Util.receiveData(self.messenger, output)
        self.logger.debug("Data Received: %d %s %d %s %s", bytesReceived, status, deltaSize, deltaChecksum, compressed)
        if status != 'OK':
            self.logger.warning("Received invalid status on data reception")

        if deltasize is None:
            # BUG: should actually be the uncompressed size, but hopefully we won't get here.
            deltasize = bytesReceived

        self.statBytesReceived += bytesReceived

        Util.recordMetaData(self.cache, checksum, size, compressed, encrypted, bytesReceived, basis=basis, logger=self.logger)

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
                    # Can't use isinstance
                    if type(basisFile) != types.FileType:
                        # TODO: Is it possible to get here?  Is this just dead code?
                        temp = basisFile
                        basisFile = tempfile.TemporaryFile(dir=self.tempdir, prefix=self.tempPrefix)
                        shutil.copyfileobj(temp, basisFile)
                    patched = librsync.patch(basisFile, delta)
                    shutil.copyfileobj(patched, self.cache.open(checksum, "wb"))
                    self.db.insertChecksumFile(checksum, encrypted, size=size, disksize=bytesReceived)
                else:
                    if self.server.linkBasis:
                        self.cache.link(basis, checksum + ".basis")
                    self.db.insertChecksumFile(checksum, encrypted, size=size, deltasize=deltasize, basis=basis, compressed=compressed, disksize=bytesReceived)

                # Track that we've added a file of this size.
                self.sizes.add(size)

                self.statUpdFiles += 1

                self.logger.debug("Setting checksum for inode %s to %s", inode, checksum)
                self.db.setChecksum(inode, dev, checksum)
            except Exception as e:
                self.logger.error("Could not insert checksum %s: %s", checksum, str(e))
            output.close()
            # TODO: This has gotta be wrong.

        flush = True if size > 1000000 else False
        return (None, flush)

    def processSignature(self, message):
        """ Receive a signature message. """
        self.logger.debug("Processing signature message: %s", message)
        output = None
        checksum = message["checksum"]

        # If a signature is specified, receive it as well.
        sigfile = checksum + ".sig"
        if self.cache.exists(sigfile):
            self.logger.debug("Signature file %s already exists", sigfile)
            # Abort read
        else:
            output = self.cache.open(sigfile, "wb")

        # TODO: Record these in stats
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
            if info and info['isfile'] and info['size'] >= 0:
                self.db.setChecksum(inode, dev, cksum)
                done.append(f['inode'])
            else:
                # FIXME: TODO: If no checksum, should we request a delta???
                #old = self.db.getFileInfoByInode((inode, dev))
                #if old and old['chainlength'] < self.maxChain:
                    #delta.append(f['inode'])
                #else:
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
        encrypted = message.get('encrypted', False)
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
                    self.db.insertChecksumFile(cksum, encrypted, -1)
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
            output = io.BytesIO()        # Accumulate into a throwaway string
        else:
            output = self.cache.open(checksum, "wb")

        encrypted = message.get('encrypted', False)

        (bytesReceived, status, size, cks, compressed) = Util.receiveData(self.messenger, output)
        self.logger.debug("Data Received: %d %s %d %s %s", bytesReceived, status, size, checksum, compressed)

        output.close()

        self.db.updateChecksumFile(checksum, encrypted, size, compressed=compressed, disksize=bytesReceived)
        self.statNewFiles += 1

        self.statBytesReceived += bytesReceived

        return (None, False)

    def processPurge(self, message = {}):
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
            self.statPurgedSets += sets
            self.statPurgedFiles += files
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
            inoDev = (inode, device)
            info = self.db.getFileInfoByInode(inoDev, current=False)

            if not info and not self.lastCompleted:
                # Check for copies in a partial directory backup, if some exist and we didn't find one here..
                # This should only happen in rare circumstances, namely if the list of directories to backup
                # has changed, and a directory which is older than the last completed backup is added to the backup.
                info = self.db.getFileInfoByInodeFromPartial(inoDev)

            if info and info['checksum'] is not None:
                numFiles = self.db.getDirectorySize(inoDev)
                if numFiles is not None:
                    #logger.debug("Clone info: %s %s %s %s", info['size'], type(info['size']), info['checksum'], type(info['checksum']))
                    if (numFiles == d['numfiles']) and (info['checksum'] == d['cksum']):
                        self.db.cloneDir(inoDev)
                        if self.full:
                            numDeltas = self.db.getNumDeltaFilesInDirectory(inoDev, current=False)
                            if numDeltas > 0:
                                # Oops, there's a delta file in here on a full backup.
                                #self.logger.debug("Inode %d contains %d deltas on full backup.  Requesting refresh.", inode, numDeltas)
                                content.append(inoDev)
                            else:
                                # No delta files for full backup.  We're done
                                done.append(inoDev)
                        else:
                            done.append(inoDev)
                    else:
                        #self.logger.debug("No match on clone.  Inode: %d Rows: %d %d Checksums: %s %s", inode, int(info['size']), d['numfiles'], info['checksum'], d['cksum'])
                        content.append(inoDev)
                else:
                    #self.logger.debug("Unable to get number of files to process clone (%d %d)", inode, device)
                    content.append(inoDev)
            else:
                #self.logger.debug("No info available to process clone (%d %d)", inode, device)
                content.append(inoDev)
        return ({"message" : "ACKCLN", "done" : done, 'content' : content }, True)


    _sequenceNumber = 0

    def processContent(self, message):
        """ Process a content message, including all the data content chunks """
        self.logger.debug("Processing content message: %s", message)
        tempName = None
        checksum = None
        if "checksum" in message:
            checksum = message["checksum"]
            if self.cache.exists(checksum):
                self.logger.debug("Checksum file %s already exists", checksum)
            output = self.cache.open(checksum, "w")
        else:
            #temp = tempfile.NamedTemporaryFile(dir=self.tempdir, delete=False, prefix=self.tempPrefix)
            tempName = os.path.join(self.tempdir, self.tempPrefix + str(self._sequenceNumber))
            self._sequenceNumber += 1
            self.logger.debug("Sending output to temporary file %s", tempName)
            output = open(tempName, 'wb')

        encrypted = message.get('encrypted', False)

        (bytesReceived, status, size, checksum, compressed) = Util.receiveData(self.messenger, output)
        self.logger.debug("Data Received: %d %s %d %s %s", bytesReceived, status, size, checksum, compressed)

        output.close()

        try:
            if tempName:
                if self.cache.exists(checksum):
                    # Error check.  Sometimes files can get into the cachedir without being recorded.
                    ckInfo = self.db.getChecksumInfo(checksum)
                    if ckInfo is None:
                        self.logger.warning("Checksum file %s exists, but no DB entry.  Reinserting", checksum)
                        self.cache.insert(checksum, tempName)
                        self.db.insertChecksumFile(checksum, encrypted, size, compressed=compressed, disksize=bytesReceived)
                    else:
                        if self.full:
                            self.logger.debug("Replacing existing checksum file for %s", checksum)
                            self.cache.insert(checksum, tempName)
                            self.db.updateChecksumFile(checksum, encrypted, size, compressed=compressed, disksize=bytesReceived)
                        else:
                            # Check to make sure it's recorded in the DB.  If not, reinsert
                            self.logger.debug("Checksum file %s already exists.  Deleting temporary version", checksum)
                            os.remove(tempName)
                else:
                    self.cache.insert(checksum, tempName)
                    self.db.insertChecksumFile(checksum, encrypted, size, compressed=compressed, disksize=bytesReceived)
            else:
                self.db.insertChecksumFile(checksum, encrypted, size, compressed=compressed, disksize=bytesReceived)

            (inode, dev) = message['inode']

            self.logger.debug("Setting checksum for inode %d to %s", inode, checksum)
            self.db.setChecksum(inode, dev, checksum)
            self.statNewFiles += 1
            # Record the metadata.  Do it here after we've inserted the file because on a full backup we could overwrite
            # a version which had a basis without updating the base file.
            Util.recordMetaData(self.cache, checksum, size, compressed, encrypted, bytesReceived, logger=self.logger)
        except Exception as e:
            self.logger.error("Could insert checksum %s info: %s", checksum, str(e))
            if self.server.exceptions:
                self.logger.exception(e)

        self.statBytesReceived += bytesReceived

        #return {"message" : "OK", "inode": message["inode"]}
        #flush = True if bytesReceived > 1000000 else False
        return (None, False)

    def processBatch(self, message):
        batch = message['batch']
        responses = []
        for mess in batch:
            (response, _) = self.processMessage(mess, transaction=False)
            if response:
                responses.append(response)

        response = {
            'message': 'ACKBTCH',
            'responses': responses
        }
        return (response, True)

    def processSetKeys(self, message):
        filenameKey = message['filenameKey']
        contentKey  = message['contentKey']
        srpSalt     = message['srpSalt']
        srpVkey     = message['srpVkey']

        ret = self.db.setKeys(srpSalt, srpVkey, filenameKey, contentKey)
        response = {
            'message': 'ACKSETKEYS',
            'response': 'OK' if ret else 'FAIL'
        }
        return (response, True)

    def processClientConfig(self, message):
        if self.saveConfig:
            clientConfig = message['args']
            self.logger.debug("Received client config: %s", clientConfig)
            self.db.setClientConfig(clientConfig)
        response = {
            'message': 'ACKCLICONFIG',
            'saved': self.saveConfig
        }
        return (response, False)

    def processCommandLine(self, message):
        cksum = message['hash']
        self.logger.debug("Received command line")
        ckInfo = self.db.getChecksumInfo(cksum)
        if ckInfo is None:
            self.logger.debug("Inserting command line file")
            f = self.cache.open(cksum, 'wb')
            if type(message['line']) == bytes:
                f.write(message['line'])
            else:
                f.write(bytes(message['line'], 'utf8'))
            cksid = self.db.insertChecksumFile(cksum, message['encrypted'], size=message['size'], disksize=f.tell())
            f.close()
        else:
            cksid = ckInfo['checksumid']
        self.logger.debug("Command Line stored as checksum: %s => %d", cksum, cksid)
        self.db.setCommandLine(cksid)

        response = {
            'message': 'ACKCMDLN'
        }
        return (response, False)

    def processMessage(self, message, transaction=True):
        """ Dispatch a message to the correct handlers """
        messageType = message['message']
        # Stats
        self.statCommands[messageType] = self.statCommands.get(messageType, 0) + 1

        #if transaction:
        #    self.db.beginTransaction()

        if messageType == "DIR":
            (response, flush) = self.processDir(message)
        elif messageType == "DHSH":
            (response, flush) = self.processDirHash(message)
        elif messageType == "SGR":
            (response, flush) = self.processSigRequest(message)
        elif messageType == "SGS":
            (response, flush) = self.processManySigsRequest(message)
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
        elif messageType == "CLICONFIG":
            (response, flush) = self.processClientConfig(message)
        elif messageType == "COMMANDLINE":
            (response, flush) = self.processCommandLine(message)
        elif messageType == "META":
            (response, flush) = self.processMeta(message)
        elif messageType == "METADATA":
            (response, flush) = self.processMetaData(message)
        elif messageType == "SETKEYS":
            (response, flush) = self.processSetKeys(message)
        else:
            raise Exception("Unknown message type", messageType)

        if response and 'msgid' in message:
            response['respid'] = message['msgid']
        self.db.commit()

        return (response, flush)

    def genPaths(self):
        self.basedir    = os.path.join(self.server.basedir, self.client)
        dbdir           = os.path.join(self.server.dbdir, self.client)
        dbname          = self.server.dbname.format({'client': self.client})
        dbfile          = os.path.join(dbdir, dbname)
        return (dbdir, dbfile)

    def getCacheDir(self, create):
        try:
            self.logger.debug("Using cache dir: %s", self.basedir)
            return CacheDir.CacheDir(self.basedir, 1, 2,
                                     create=(self.server.allowNew and create),
                                     user=self.server.user,
                                     group=self.server.group,
                                     skipFile=self.server.skip)
        except CacheDir.CacheDirDoesNotExist as e:
            if not self.server.allowNew:
                raise InitFailedException("Server does not allow new clients")
            else:
                raise InitFailedException("Must request new client (--create))")

    def getDB(self, client, create):
        script = None
        ret = "EXISTING"
        journal = None

        (dbdir, dbfile) = self.genPaths()

        if create and os.path.exists(dbfile):
            raise InitFailedException("Cannot create client %s.  Already exists" % (client))

        self.cache = self.getCacheDir(create)

        connid = {'connid': self.idstr }

        if not os.path.exists(dbfile):
            if not os.path.exists(dbdir):
                os.makedirs(dbdir)
            self.logger.debug("Initializing database for %s with file %s", client, schemaFile)
            script = schemaFile
            ret = "NEW"

        if self.server.journal:
            journal = os.path.join(dbdir, self.server.journal)

        self.db = TardisDB.TardisDB(dbfile,
                                    initialize=script,
                                    backup=(self.server.dbbackups > 0),
                                    connid=connid,
                                    user=self.server.user,
                                    group=self.server.group,
                                    numbackups=self.server.dbbackups,
                                    journal=journal,
                                    allow_upgrade = self.server.allowUpgrades)

        self.regenerator = Regenerator.Regenerator(self.cache, self.db)
        return ret

    def setConfig(self):
        self.formats        = self.server.formats
        self.priorities     = self.server.priorities
        self.keep           = self.server.keep
        self.forceFull      = self.server.forceFull

        self.savefull       = self.server.savefull
        self.maxChain       = self.server.maxChain
        self.deltaPercent   = self.server.deltaPercent
        self.autoPurge      = self.server.autoPurge
        self.saveConfig     = self.server.saveConfig

        if self.server.allowOverrides:
            try:
                formats     = self.db.getConfigValue('Formats')
                priorities  = self.db.getConfigValue('Priorities')
                keepDays    = self.db.getConfigValue('KeepDays')
                forceFull   = self.db.getConfigValue('ForceFull')

                if formats:
                    self.logger.debug("Overriding global name formats: %s", formats)
                    self.formats        = list(map(string.strip, formats.split(',')))
                if priorities:
                    self.logger.debug("Overriding global priorities: %s", priorities)
                    self.priorities     = list(map(int, priorities.split(',')))
                if keepDays:
                    self.logger.debug("Overriding global keep days: %s", keepDays)
                    self.keep           = list(map(int, keepDays.split(',')))
                if forceFull:
                    self.logger.debug("Overriding global force full: %s", forceFull)
                    self.forceFull      = list(map(int, forceFull.split(',')))

                numFormats = len(self.formats)
                if len(self.priorities) != numFormats or len(self.keep) != numFormats or len(self.forceFull) != numFormats:
                    self.logger.warning("Client %s has different sizes for the lists of formats: Formats: %d Priorities: %d KeepDays: %d ForceFull: %d",
                                        self.client, len(self.formats), len(self.priorities), len(self.keep), len(self.forceFull))

                savefull        = self.db.getConfigValue('SaveFull')
                maxChain        = self.db.getConfigValue('MaxDeltaChain')
                deltaPercent    = self.db.getConfigValue('MaxChangePercent')
                autoPurge       = self.db.getConfigValue('AutoPurge')
                saveConfig      = self.db.getConfigValue('SaveConfig')

                if savefull is not None:
                    self.logger.debug("Overriding global save full: %s", savefull)
                    self.savefull = bool(savefull)
                if maxChain is not None:
                    self.logger.debug("Overriding global max chain length: %s", maxChain)
                    self.maxChain = int(maxChain)
                if deltaPercent is not None:
                    self.logger.debug("Overriding global max change percentage: %s", deltaPercent)
                    self.deltaPercent = float(deltaPercent) / 100.0
                if autoPurge is not None:
                    self.logger.debug("Overriding global autopurge value: %s", bool(autoPurge))
                    self.autoPurge = bool(autoPurge)
                if saveConfig is not None:
                    self.logger.debug("Overriding global saveconfig value: %s", bool(autoPurge))
                    self.saveconfig = bool(saveconfig)
            except Exception as e:
                self.logger.error("Client %s: Unable to override global configuration: %s", self.client, str(e))

    def startSession(self, name, force):
        self.name = name

        # Check if the previous backup session completed.
        prev = self.db.lastBackupSet(completed=False)
        if prev['endtime'] is None or self.server.checkSession(prev['session']):
            if force:
                self.logger.warning("Staring session %s while previous backup still warning: %s", name, prev['name'])
            else:
                if self.server.checkSession(prev['session']):
                    raise InitFailedException("Previous backup session still running: {}.  Run with --force to force starting the new backup".format(prev['name']))
                else:
                    self.logger.warning('Previous session for client %s (%s) did not complete.', self.client, prev['session'])

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

    def calcAutoInfo(self, clienttime):
        """
        Calculate a name if autoname is passed in.
        """
        starttime = datetime.fromtimestamp(clienttime)
        # Walk the automatic naming formats until we find one that's free
        for (fmt, prio, keep, full) in zip(self.formats, self.priorities, self.keep, self.forceFull):
            name = starttime.strftime(fmt)
            if self.db.checkBackupSetName(name):
                return (name, prio, keep, full)

        # Oops, nothing worked.  Create a temporary name
        name = starttime.strftime("Backup_%Y-%m-%d_%H:%M:%S")
        return (name, 0, 0, False)

    def mkMessenger(self, sock, encoding, compress):
        """
        Create the messenger object to handle communications with the client
        """
        if encoding == "JSON":
            self.messenger = Messages.JsonMessages(sock, compress=compress)
        elif encoding == 'MSGP':
            self.messenger = Messages.MsgPackMessages(sock, compress=compress)
        elif encoding == "BSON":
            self.messenger = Messages.BsonMessages(sock, compress=compress)
        else:
            message = {"status": "FAIL", "error": "Unknown encoding: {}".format(encoding)}
            sock.sendall(bytes(json.dumps(message), 'utf-8'))
            raise InitFailedException("Unknown encoding: ", encoding)

    def doGetKeys(self):
        try:
            message = {"status": "NEEDKEYS"}
            self.sendMessage(message)
            resp = self.recvMessage()
            self.checkMessage(resp, "SETKEYS")

            filenameKey = resp['filenameKey']
            contentKey  = resp['contentKey']
            srpSalt     = resp['srpSalt']
            srpVkey     = resp['srpVkey']
            # ret = self.db.setKeys(srpSalt, srpVkey, filenameKey, contentKey)
            return(srpSalt, srpVkey, filenameKey, contentKey)

        except KeyError as e:
            raise InitFailedException(e.message)

    def doSrpAuthentication(self):
        """
        Perform the SPR authentication steps  Start with the name and value A passed in from the
        connection call.
        """
        self.logger.debug("Beginning Authentication")
        try:
            message = {"message": "AUTH", "status": "AUTH", "client": self.db.clientId}
            self.sendMessage(message)
            autha = self.recvMessage()
            self.checkMessage(autha, "AUTH1")
            name = base64.b64decode(autha['srpUname'])
            srpValueA = base64.b64decode(autha['srpValueA'])

            srpValueS, srpValueB = self.db.authenticate1(name, srpValueA)
            if srpValueS is None or srpValueB is None:
                raise TardisDB.AuthenticationFailed

            self.logger.debug("Sending Challenge values")   
            message = {
                'message': 'AUTH1',
                'status': 'OK',
                'srpValueS': base64.b64encode(srpValueS),
                'srpValueB': base64.b64encode(srpValueB)
            }
            self.sendMessage(message)

            resp = self.recvMessage()
            self.logger.debug("Received challenge response")
            self.checkMessage(resp, "AUTH2")
            srpValueM = base64.b64decode(resp['srpValueM'])
            srpValueHAMK = self.db.authenticate2(srpValueM)
            message = {
                'message': 'AUTH2',
                'status': 'OK',
                'srpValueHAMK': base64.b64encode(srpValueHAMK)
            }
            self.logger.debug("Authenticated")
            return message
        except TardisDB.AuthenticationFailed as e:
            message = {
                'status': 'AUTHFAIL',
                'message': str(e)
            }
            self.sendMessage(message)
            raise e

    def handle(self):
        started   = False
        completed = False
        starttime = datetime.now()
        client = ""

        if self.server.profiler:
            self.logger.info("Starting Profiler")
            self.server.profiler.enable()

        try:
            sock = self.request
            sock.settimeout(args.timeout)

            if self.server.ssl:
                sock.sendall(bytes(Connection.sslHeaderString, 'utf-8'))
                sock = ssl.wrap_socket(sock, server_side=True, certfile=self.server.certfile, keyfile=self.server.keyfile)
            else:
                sock.sendall(bytes(Connection.headerString, 'utf-8'))

            # Receive the initial messages.  Defines the communication parameters.
            # Should be : { "encoding": "MSGP", "compress": "snappy" }

            message = sock.recv(1024)
            self.logger.debug(message)
            message = str(message, 'utf-8').strip()

            fields = json.loads(message)
            resp = {'status': 'OK'}
            sock.sendall(bytes(json.dumps(resp), 'utf-8'))

            # Create the messenger object.  From this point on, ALL communications should
            # go through messenger, not director to the socket
            self.mkMessenger(sock, fields['encoding'], fields['compress'])

            try:
                fields = self.recvMessage()
                messType    = fields['message']
                if not messType == 'BACKUP':
                    raise InitFailedException("Unknown message type: {}".format(messType))

                client      = fields['host']            # TODO: Change at client as well.
                clienttime  = fields['time']
                version     = fields['version']

                autoname    = fields.get('autoname', True)
                name        = fields.get('name', None)
                full        = fields.get('full', False)
                priority    = fields.get('priority', 0)
                force       = fields.get('force', False)
                create      = fields.get('create', False)

                self.logger.info("Creating backup for %s: %s (Autoname: %s) %s %s", client, name, str(autoname), version, clienttime)
            except ValueError as e:
                raise InitFailedException("Cannot parse JSON field: {}".format(message))
            except KeyError as e:
                raise InitFailedException(str(e))

            self.client = client
            self.server.addSession(self.sessionid, client)

            serverName = None
            serverForceFull = False
            authResp = {}
            keys = None

            try:
                (_, dbfile) = self.genPaths()
                if create and os.path.exists(dbfile):
                    raise Exception("Client %s already exists" % client)
                elif not create and not os.path.exists(dbfile):
                    raise Exception("Unknown client: %s" % client)

                if self.server.requirePW and create and self.server.allowNew:
                    keys = self.doGetKeys()

                newBackup = self.getDB(client, create)

                if self.server.requirePW and not self.db.needsAuthentication():
                    raise InitFailedException("Passwords required on this server.  Please add a password (sonic setpass) and encrypt the DB if necessary")

                if keys:
                    self.logger.debug("Setting keys into new client DB")
                    (srpSalt, srpVkey, filenameKey, contentKey) = keys
                    ret = self.db.setKeys(srpSalt, srpVkey, filenameKey, contentKey)
                    keys = None

                self.logger.debug("Ready for authentication")
                if self.db.needsAuthentication():
                    authResp = self.doSrpAuthentication()

                disabled = self.db.getConfigValue('Disabled')
                if disabled is not None and int(disabled) != 0:
                    raise InitFailedException("Client %s is currently disabled." % client)

                self.setConfig()
                self.startSession(name, force)

                # Create a name
                if autoname:
                    (serverName, serverPriority, serverKeepDays, serverForceFull) = self.calcAutoInfo(clienttime)
                    self.logger.debug("Setting name, priority, keepdays to %s", (serverName, serverPriority, serverKeepDays))
                    if serverName:
                        self.serverKeepTime = serverKeepDays * 3600 * 24
                        self.serverPriority = serverPriority
                    else:
                        self.serverKeepTime = None
                        self.serverPriority = None
                else:
                    self.serverKeepTime = None
                    self.serverPriority = None

                # Either the server or the client can specify a full backup.
                self.full = full or serverForceFull

                if priority is None:
                    priority = 0

                # Create the actual backup set
                self.db.newBackupSet(name, self.sessionid, priority, clienttime, version, self.address, self.full, self.server.serverSessionID)
            except Exception as e:
                message = {"status": "FAIL", "error": str(e)}
                self.sendMessage(message)
                if self.server.exceptions:
                    self.logger.exception(e)
                raise InitFailedException(str(e))

            response = {
                "message": "INIT",
                "status": "OK",
                "sessionid": self.sessionid,
                "prevDate": str(self.db.prevBackupDate),
                "new": newBackup,
                "name": serverName if serverName else name,
                "clientid": str(self.db.clientId)
                }

            if authResp:
                response.update(authResp)
                filenameKey = self.db.getConfigValue('FilenameKey')
                contentKey  = self.db.getConfigValue('ContentKey')

                if (filenameKey is None) ^ (contentKey is None):
                    self.logger.warning("Name Key and Data Key are both not in the same state. FilenameKey: %s  ContentKey: %s", filenameKey, contentKey)

                if filenameKey:
                    response['filenameKey'] = filenameKey
                if contentKey:
                    response['contentKey'] = contentKey

            self.sendMessage(response)

            started = True

            #sock.sendall("OK {} {} {}".format(str(self.sessionid), str(self.db.prevBackupDate), serverName if serverName else name))
            done = False

            while not done:
                flush = False
                message = self.recvMessage()
                if message["message"] == "BYE":
                    done = True
                else:
                    (response, flush) = self.processMessage(message)
                    if response:
                        self.sendMessage(response)
                if flush:
                    self.db.commit()

            self.db.completeBackup()

            if autoname and serverName is not None:
                self.logger.debug("Changing backupset name from %s to %s.  Priority is %s", name, serverName, serverPriority)
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
                self.db.setClientEndTime()
                # Autopurge if it's set.
                if self.autoPurge and not self.purged and completed:
                    self.processPurge()
                self.endSession()
                self.db.setStats(self.statNewFiles, self.statUpdFiles, self.statBytesReceived)


            if self.server.profiler:
                self.logger.info("Stopping Profiler")
                self.server.profiler.disable()
                s = io.StringIO()
                sortby = 'cumulative'
                ps = pstats.Stats(self.server.profiler, stream=s).sort_stats(sortby)
                ps.print_stats()
                print(s.getvalue())

            if started:
                (count, size, _) = Util.removeOrphans(self.db, self.cache)
                endtime = datetime.now()

                self.logger.info("Connection completed successfully: %s  Runtime: %s", str(completed), str(endtime - starttime))
                self.logger.info("New or replaced files:    %d", self.statNewFiles)
                self.logger.info("Updated files:            %d", self.statUpdFiles)
                self.logger.info("Total file data received: %s (%d)", Util.fmtSize(self.statBytesReceived), self.statBytesReceived)
                self.logger.info("Command breakdown:        %s", self.statCommands)
                self.logger.info("Purged Sets and File:     %d %d", self.statPurgedSets, self.statPurgedFiles)
                self.logger.info("Removed Orphans           %d (%s)", count, Util.fmtSize(size))

                self.logger.debug("Removing orphans")

                self.db.commit()
                self.db.compact()

            if self.db:
                self.db.close(started)

        self.logger.info("Session from %s {%s} Ending: %s: %s", client, self.sessionid, str(completed), str(datetime.now() - starttime))

class TardisServer(object):
    # HACK.  Operate on an object, but not in the class.
    # Want to do this in multiple classes.
    def __init__(self):
        self.basedir        = args.database
        if args.dbdir:
            self.dbdir      = args.dbdir
        else:
            self.dbdir      = self.basedir
        self.savefull       = config.getboolean(configSection, 'SaveFull')
        self.maxChain       = config.getint(configSection, 'MaxDeltaChain')
        self.deltaPercent   = float(config.getint(configSection, 'MaxChangePercent')) / 100.0        # Convert to a ratio
        self.cksContent     = config.getint(configSection, 'CksContent')

        self.dbname         = args.dbname
        self.allowNew       = args.newhosts
        self.schemaFile     = args.schema
        self.journal        = args.journal

        self.linkBasis      = config.getboolean(configSection, 'LinkBasis')

        self.timeout        = args.timeout

        self.requirePW      = config.getboolean(configSection, 'RequirePassword')

        self.allowOverrides = config.getboolean(configSection, 'AllowClientOverrides')

        self.allowUpgrades  = config.getboolean(configSection, 'AllowSchemaUpgrades')

        self.formats        = list(map(str.strip, config.get(configSection, 'Formats').split(',')))
        self.priorities     = list(map(int, config.get(configSection, 'Priorities').split(',')))
        self.keep           = list(map(int, config.get(configSection, 'KeepDays').split(',')))
        self.forceFull      = list(map(int, config.get(configSection, 'ForceFull').split(',')))

        numFormats = len(self.formats)
        if len(self.priorities) != numFormats or len(self.keep) != numFormats or len(self.forceFull) != numFormats:
            logger.warning("Different sizes for the lists of formats: Formats: %d Priorities: %d KeepDays: %d ForceFull: %d",
                           len(self.formats), len(self.priorities), len(self.keep), len(self.forceFull))

        self.dbbackups      = config.getint(configSection, 'DBBackups')

        self.exceptions     = args.exceptions

        self.umask          = Util.parseInt(config.get(configSection, 'Umask'))

        self.autoPurge      = config.getboolean(configSection, 'AutoPurge')
        self.saveConfig     = config.getboolean(configSection, 'SaveConfig')

        self.skip           = config.get(configSection, 'SkipFileName')

        self.user = None
        self.group = None

        self.sessions = {}

        # If the User or Group is set, attempt to determine the users
        # Note, these will throw exeptions if the User or Group is unknown.  Will get
        # passed up.
        if args.daemon:
            if args.user:
                self.user = pwd.getpwnam(args.user).pw_uid
            if args.group:
                self.group = grp.getgrnam(args.group).gr_gid

        # Get SSL set up, if it's been requested.
        self.ssl            = args.ssl
        self.certfile       = args.certfile
        self.keyfile        = args.keyfile

        # Create a session ID
        self.serverSessionID = str(uuid.uuid1())

        if args.profile:
            self.profiler = cProfile.Profile()
        else:
            self.profiler = None

    def addSession(self, sessionId, client):
        self.sessions[sessionId] = client

    def rmSession(self, sessionId):
        del self.sessions[sessionId]

    def checkSession(self, sessionId):
        return sessionId in self.sessions

#class TardisSocketServer(SocketServer.TCPServer):
class TardisSocketServer(socketserver.ThreadingMixIn, socketserver.TCPServer, TardisServer):
    def __init__(self):

        socketserver.TCPServer.__init__(self, ("", args.port), TardisServerHandler)
        TardisServer.__init__(self)
        logger.info("TCP Server %s Running", Tardis.__versionstring__)

class TardisSingleThreadedSocketServer(socketserver.TCPServer, TardisServer):
    def __init__(self):
        socketserver.TCPServer.__init__(self, ("", args.port), TardisServerHandler)
        TardisServer.__init__(self)
        logger.info("Single Threaded TCP Server %s Running", Tardis.__versionstring__)

class TardisDomainSocketServer(socketserver.UnixStreamServer, TardisServer):
    def __init__(self):
        socketserver.UnixStreamServer.__init__(self,  args.local, TardisServerHandler)
        TardisServer.__init__(self)
        logger.info("Unix Domain Socket %s Server Running", Tardis.__versionstring__)



def setupLogging():
    levels = [logging.WARNING, logging.INFO, logging.DEBUG, logging.TRACE]

    logging.addLevelName(logging.TRACE, 'Message')
    logging.addLevelName(logging.MSGS,  'MSG')

    if args.logcfg:
        logging.config.fileConfig(args.logcfg)
        logger = logging.getLogger('')
    else:
        logger = logging.getLogger('')
        if args.logfile or args.daemon:
            logFormat = logging.Formatter("%(asctime)s %(levelname)s : %(message)s")
        else:
            logFormat = colorlog.TTYColoredFormatter("%(asctime)s %(log_color)s%(levelname)s%(reset)s : %(message)s", stream=sys.stdout)

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

        handler.setFormatter(logFormat)
        logger.addHandler(handler)

        loglevel = levels[verbosity] if verbosity < len(levels) else levels[-1]
        logger.setLevel(loglevel)

    return logger

def run_server():
    global server

    try:
        if args.reuseaddr:
            # Allow reuse of the address before timeout if requested.
            socketserver.TCPServer.allow_reuse_address = True

        if args.local:
            logger.info("Starting Server. Socket: %s", args.local)
            server = TardisDomainSocketServer()
        elif args.threaded:
            logger.info("Starting Server on Port: %d", config.getint(configSection, 'Port'))
            server = TardisSocketServer()
        else:
            logger.info("Starting Single Threaded Server on Port: %d", config.getint(configSection, 'Port'))
            server = TardisSingleThreadedSocketServer()

        logger.info("Server Session: %s", server.serverSessionID)

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

    t = configSection
    config = configparser.RawConfigParser(configDefaults, default_section='Tardis')
    config.add_section(t)                   # Make it safe for reading other values from.
    if args.config:
        config.read(args.config)

    parser.add_argument('--port',               dest='port',            default=config.getint(t, 'Port'), type=int, help='Listen on port (Default: %(default)s)')
    parser.add_argument('--database',           dest='database',        default=config.get(t, 'BaseDir'), help='Dabatase directory (Default: %(default)s)')
    parser.add_argument('--dbdir',              dest='dbdir',           default=config.get(t, 'DBDir'),  help='Dabatase directory (Default: %(default)s)')
    parser.add_argument('--dbname',             dest='dbname',          default=config.get(t, 'DBName'), help='Use the database name (Default: %(default)s)')
    parser.add_argument('--schema',             dest='schema',          default=config.get(t, 'Schema'), help='Path to the schema to use (Default: %(default)s)')
    parser.add_argument('--logfile', '-l',      dest='logfile',         default=config.get(t, 'LogFile'), help='Log to file (Default: %(default)s)')
    parser.add_argument('--logcfg',             dest='logcfg',          default=config.get(t, 'LogCfg'), help='Logging configuration file')
    parser.add_argument('--verbose', '-v',      dest='verbose',         action='count', default=config.getint(t, 'Verbose'), help='Increase the verbosity (may be repeated)')
    parser.add_argument('--exceptions',         dest='exceptions',      action=Util.StoreBoolean, default=config.getboolean(t, 'LogExceptions'), help='Log full exception details')
    parser.add_argument('--allow-new-hosts',    dest='newhosts',        action=Util.StoreBoolean, default=config.getboolean(t, 'AllowNewHosts'),
                        help='Allow new clients to attach and create new backup sets')
    parser.add_argument('--profile',            dest='profile',         default=config.getboolean(t, 'Profile'), help='Generate a profile')

    parser.add_argument('--single',             dest='single',          action=Util.StoreBoolean, default=config.getboolean(t, 'Single'),
                        help='Run a single transaction and quit')
    parser.add_argument('--local',              dest='local',           default=config.get(t, 'Local'),
                        help='Run as a Unix Domain Socket Server on the specified filename')
    parser.add_argument('--threads',            dest='threaded',        action=Util.StoreBoolean, default=True, help='Run a threaded server.  Default: %(default)s')

    parser.add_argument('--timeout',            dest='timeout',         default=config.getint(t, 'Timeout'), type=float, help='Timeout, in seconds.  0 for no timeout (Default: %(default)s)')
    parser.add_argument('--journal', '-j',      dest='journal',         default=config.get(t, 'JournalFile'), help='Journal file actions to this file (Default: %(default)s)')

    parser.add_argument('--reuseaddr',          dest='reuseaddr',       action=Util.StoreBoolean, default=config.getboolean(t, 'ReuseAddr'),
                        help='Reuse the socket address immediately')

    parser.add_argument('--daemon',             dest='daemon',          action=Util.StoreBoolean, default=config.getboolean(t, 'Daemon'),
                        help='Run as a daemon')
    parser.add_argument('--user',               dest='user',            default=config.get(t, 'User'), help='Run daemon as user.  Valid only if --daemon is set')
    parser.add_argument('--group',              dest='group',           default=config.get(t, 'Group'), help='Run daemon as group.  Valid only if --daemon is set')
    parser.add_argument('--pidfile',            dest='pidfile',         default=config.get(t, 'PidFile'), help='Use this pidfile to indicate running daemon')

    parser.add_argument('--ssl',                dest='ssl',             action=Util.StoreBoolean, default=config.getboolean(t, 'SSL'), help='Use SSL connections')
    parser.add_argument('--certfile',           dest='certfile',        default=config.get(t, 'CertFile'), help='Path to certificate file for SSL connections')
    parser.add_argument('--keyfile',            dest='keyfile',         default=config.get(t, 'KeyFile'), help='Path to key file for SSL connections')

    parser.add_argument('--version',            action='version', version='%(prog)s ' + Tardis.__versionstring__,    help='Show the version')
    parser.add_argument('--help', '-h',         action='help')

    Util.addGenCompletions(parser)

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
        print("Unable to initialize logging: {}".format(str(e)), file=sys.stderr)
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
            logger.warning("Killed by Keyboard")
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
