# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2024, Eric Koldinger, All Rights Reserved.
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

import base64
import io
import json
import logging
import logging.config
import os
import pprint
import shutil
import tempfile
import uuid
from datetime import datetime
from enum import IntEnum

from . import CacheDir
from . import CompressedBuffer
from . import ConnIdLogAdapter
from . import Defaults
from . import librsync
from . import Messages
from . import Regenerator
from . import TardisCrypto
from . import TardisDB
from . import Util
from . import Protocol
from . import log

#from icecream import ic
#ic.configureOutput(includeContext=True)

class FileResponse(IntEnum):
    DONE    = 0
    CONTENT = 1
    CKSUM   = 2
    DELTA   = 3
    REFRESH = 4                     # Perform a full content update
    LINKED  = 5                     # Check if it's already linked

config = None
args   = None

schemaName      = Defaults.getDefault('TARDIS_SCHEMA')

if os.path.isabs(schemaName):
    schemaFile = schemaName
else:
    parentDir    = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    schemaFile   = os.path.join(parentDir, schemaName)
    # Hack.  Make it look shorter.
    schemaFile = min([schemaFile, os.path.relpath(schemaFile)], key=len)
    #if len(schemaFile) > len(os.path.relpath(schemaFile)):
        #schemaFile = os.path.relpath(schemaFile)

pp = pprint.PrettyPrinter(indent=2, width=256, compact=True)

_sessions = {}
def addSession(sessionId, client):
    _sessions[sessionId] = client

def rmSession(sessionId):
    try:
        del _sessions[sessionId]
    except KeyError:
        pass

def checkSession(sessionId):
    return sessionId in _sessions

class InitFailedException(Exception):
    pass

class ProtocolError(Exception):
    pass

class ProcessingError(Exception):
    pass

class BackendConfig:
    """
    Configuration class.   Used by the Client class when an integrated backend is used (ie, 
    local mode)
    """
    umask           = 0
    cksContent      = 0
    serverSessionID = None
    formats         = []
    priorities      = []
    keep            = []
    forceFull       = False
    journal         = None

    savefull        = False
    maxChain        = 0
    deltaPercent    = 0
    autoPurge       = False
    saveConfig      = False
    dbbackups       = 0

    user            = None
    group           = None

    dbname          = ""
    dbdir           = ""
    basedir         = ""
    allowNew        = True
    allowUpgrades   = True

    allowOverrides  = True

    requirePW       = False

    exceptions      = False

    linkBasis       = False

    skip            = Defaults.getDefault('TARDIS_SKIP')


class Backend:
    def __init__(self, messenger: Messages.Messages, conf, logSession=True, sessionid=None):
        self.numfiles       = 0
        self.logger: logging.Logger     = None
        self.sessionid      = None
        self.cache: CacheDir.CacheDir   = None
        self.tempdir        = None
        self.db: TardisDB.TardisDB      = None
        self.purged         = False
        self.full           = False
        self.done           = False
        self.statNewFiles   = 0
        self.statUpdFiles   = 0
        self.statDirs       = 0
        self.statBytesReceived  = 0
        self.statPurgedFiles    = 0
        self.statPurgedSets = 0
        self.statCommands   = {}
        self.address        = ''
        self.regenerator    = None
        self.basedir        = None
        self.autoPurge      = False
        self.saveConfig     = False
        self.deltaPercent   = 80
        self.forceFull      = False
        self.saveFull       = False
        self.lastCompleted  = None
        self.maxChain       = 0

        self.sessionid = sessionid if sessionid else str(uuid.uuid1())
        self.idstr  = self.sessionid[0:13]   # Leading portion (ie, timestamp) of the UUID.  Sufficient for logging.
        if logSession:
            self.logger = ConnIdLogAdapter.ConnIdLogAdapter(logging.getLogger('Backend'), {'connid': self.idstr })
        else:
            self.logger = logging.getLogger('Backend')

        self.logger.debug("Created backend: %s", self.sessionid)
        self.messenger = messenger
        self.config = conf
        self.printMessages = self.logger.isEnabledFor(log.MSGS)
        self.tempPrefix = self.sessionid + "-"
        # Not quite sure why I do this here.  But just in case.
        os.umask(self.config.umask)

        self.exceptionLogger = Util.ExceptionLogger(self.logger, self.config.exceptions, True)


    def checkMessage(self, message, expected):
        """ Check that a message is of the expected type.  Throw an exception if not """
        if not message['message'] == expected:
            self.logger.critical(f"Expected {expected} message, received {message['message']}")
            raise ProtocolError(f"Expected {expected} message, received {message['message']}")

    def setXattrAcl(self, inode, device, xattr, acl):
        self.logger.debug("Setting Xattr and ACL info: %d %s %s", inode, xattr, acl)
        if xattr:
            self.db.setXattrs(inode, device, xattr)
        if acl:
            self.db.setAcl(inode, device, acl)

    def sendMessage(self, message):
        #if not 'message' in message:
        #    self.logger.error("No `message` block in message: %s", message)
        if self.printMessages:
            self.logger.log(log.MSGS, "Sending:\n" + pp.pformat(message))
        self.messenger.sendMessage(message)

    def recvMessage(self) -> dict[str, str]|bytearray:
        message = self.messenger.recvMessage()
        if self.printMessages:
            self.logger.log(log.MSGS, "Received:\n" + pp.pformat(message))
        return message

    sizes = set()
    sizesLoaded = False

    def checkForSize(self, size):
        if not self.sizesLoaded:
            self.logger.debug("Loading sizes")
            for i in self.db.getFileSizes(self.config.cksContent):
                self.sizes.add(i[0])
            self.logger.debug("Size loading complete: %d", len(self.sizes))
            self.sizesLoaded = True

        if (size > self.config.cksContent) and (size in self.sizes):
            return FileResponse.CKSUM
        return FileResponse.CONTENT

    def checkFile(self, parent, f, dirhash):
        """
        Process an individual file.  Check to see if it's different from what's there already
        """
        basis = None
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

        if f["dir"] == 1:
            #self.logger.debug("Is a directory: %s", name)
            if old:
                if (old["inode"] == inode) and (old["device"] == device) and (old["mtime"] == f["mtime"]):
                    #self.db.extendFileInode(parent, (inode, device))
                    self.db.extendFileRowID(old['rowid'])
                else:
                    self.db.insertFile(f, parent)
                    self.setXattrAcl(inode, device, xattr, acl)
            else:
                self.db.insertFile(f, parent)
                self.setXattrAcl(inode, device, xattr, acl)
            retVal = FileResponse.DONE
        else:       # Not a directory, it's a file
            # Check to see if there's an updated version.
            if not self.lastCompleted:
                # not in this directory, but lets look further in any incomplete sets if there are any
                #self.logger.debug("Looking up file in partial backup(s): %s (%s)", name, inode)
                tmp = self.db.getFileFromPartialBackup(f)
                if tmp:
                    old = tmp
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
                    # Just request full content if the old version was a link or dir
                    if old["checksum"] is not None and not (old['dir'] or old['link']):
                        #self.db.setChecksum(inode, device, old['checksum'])
                        if (old['mode'] == f['mode']) and (old['ctime'] == f['ctime']) and (old['xattrs'] == xattr) and (old['acl'] == acl):
                            # nothing has changed, just extend it
                            #self.logger.debug("Extending %s", name)
                            #self.db.extendFileInode(parent, (inode, device), old=fromPartial)
                            self.db.extendFileRowID(old['rowid'])
                        else:
                            # Some metadata has changed, so let's insert the new record, and set it's checksum
                            #self.logger.debug("Inserting new version %s", name)
                            self.db.insertFile(f, parent)
                            self.db.setChecksum(inode, device, old['checksum'])
                            self.setXattrAcl(inode, device, xattr, acl)
                        if self.full and old['chainlength'] != 0:
                            retVal = FileResponse.REFRESH
                        else:
                            retVal = FileResponse.DONE       # we're done either way
                    else:
                        # Otherwise we need a whole new file
                        #self.logger.debug("No checksum: Get new file %s", name)
                        self.db.insertFile(f, parent)
                        self.setXattrAcl(inode, device, xattr, acl)
                        retVal = FileResponse.CONTENT
                #elif (osize == fsize) and ("checksum" in old.keys()) and not (old["checksum"] is None):
                elif (osize == fsize) and (old["checksum"] is not None):
                    #self.logger.debug("Secondary match, requesting checksum: %s", name)
                    # Size hasn't changed, but something else has.  Ask for a checksum
                    self.db.insertFile(f, parent)
                    self.setXattrAcl(inode, device, xattr, acl)
                    retVal = FileResponse.CKSUM
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
                    retVal = FileResponse.REFRESH
                else:
                    # Otherwise, let's just get the delta
                    #self.logger.debug("Fourth case.  Should be a delta: %s", name)
                    self.db.insertFile(f, parent)
                    self.setXattrAcl(inode, device, xattr, acl)
                    if self.full:
                        # Full backup, request the full version anyhow.
                        retVal = FileResponse.CONTENT
                    else:
                        retVal = FileResponse.DELTA
                        basis = old['checksum']
            else:           # if old (i.e., if not old)
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
                        retVal = FileResponse.LINKED             # special value, allowing the caller to determine that this was handled as a link
                    else:
                        #self.logger.debug('No link data found for inode %d: %s.   Requesting new content', inode, f['name'])
                        retVal = self.checkForSize(f['size'])
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
                                retVal = FileResponse.DONE
                            else:
                                retVal = self.checkForSize(f['size'])
                        else:
                            # otherwise
                            retVal = FileResponse.CKSUM
                    else:
                        # TODO: Lookup based on inode.
                        #self.logger.debug("No old file.")
                        retVal = self.checkForSize(f['size'])

        return retVal, basis

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
            res, basis = self.checkFile(parentInode, f, dirhash)
            # Shortcut for this:
            #if res == 0: done.append(inode)
            #elif res == 1: content.append(inode)
            #elif res == 2: cksum.append(inode)
            #elif res == 3: delta.append(inode)
            if res == FileResponse.LINKED:
                # Determine if this fileid is already in one of the queues
                if not any(map(lambda x: fileId in x, queues)):
                    queues[FileResponse.DONE].add(fileId)
            elif res == FileResponse.DELTA:
                queues[FileResponse.DELTA].add((fileId, basis))
            else:
                queues[res].add(fileId)

            if 'xattr' in f:
                xattr = f['xattr']
                # Check to see if we have this checksum
                info = self.db.getChecksumInfo(xattr)
                if (not info) or (info['size'] == -1):
                    attrs.add(xattr)
        # And commit them to the DB
        self.db.commit()

        response = {
            "message"   : Protocol.Responses.ACKDIR,
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
            cksid = self.db.insertChecksum(checksum, encrypted=False, size=message['size'], isFile=False)
            self.db.setStats(self.statNewFiles, self.statUpdFiles, self.statBytesReceived)
        self.db.updateDirChecksum(inode, cksid)
        response = {
            "message" : Protocol.Responses.ACKDHSH,
            "status"  : "OK"
        }
        return (response, False)

    def processManySigsRequest(self, message):
        inodes = message['inodes']
        for i in inodes:
            ((inode, dev), checksum) = i
            self.logger.debug("ProcessManySigRequests: %s %s %s", inode, dev, checksum)
            self.sendSignature(inode, dev, checksum, message.get('msgid', 0))
        response = {
            'message': Protocol.Commands.SIG,
            'status' : "DONE"
        }
        return(response, True)

    def processSigRequest(self, message):
        """ Generate and send a signature for a file """
        self.logger.debug("Processing signature request message: %s", str(message))
        ((inode, dev), checksum) = message["inode"]
        return self.sendSignature(inode, dev, checksum, message.get('msgid', 0))

    def sendSignature(self, inode, dev, chksum, msgid):
        response = None
        errmsg = None
        sig = b''

        self.logger.debug("Signature requested: %s %s %s", inode, dev, chksum)
        ### TODO: Remove this function.  Shouldn't be needed anymore.
        if chksum is None:
            info = self.db.getFileInfoByInode((inode, dev), current=False)
            if info:
                chksum = info['checksum']
            else:
                self.logger.warning("No Checksum Info available for (%d, %d)", inode, dev)

        self.logger.debug("Sending signature for (%d, %d): %s", inode, dev, str(chksum))

        if chksum:
            try:
                sigfile = chksum + ".sig"
                if self.cache.exists(sigfile):
                    sigfile = self.cache.open(sigfile, "rb")
                    sig = sigfile.read()       # TODO: Does this always read the entire file?
                    sigfile.close()
                else:
                    ### TODO: Remove this?   Only valid for unencrypted backups.
                    try:
                        rpipe = self.regenerator.recoverChecksum(chksum)
                        if rpipe:
                            s = librsync.signature(rpipe)
                            sig = s.read()

                            outfile = self.cache.open(sigfile, "wb")
                            outfile.write(sig)
                            outfile.close()

                    except (librsync.LibrsyncError, Regenerator.RegenerateException) as e:
                        self.logger.error(f"Unable to generate signature for inode: {inode}, checksum: {chksum}: {e}")
                # TODO: Break the signature out of here.
                response = {
                    "message": Protocol.Commands.SIG,
                    "respid" : msgid,
                    "inode": (inode, dev),
                    "status": "OK",
                    "encoding": self.messenger.getEncoding(),
                    "checksum": chksum,
                    "size": len(sig) }
                self.sendMessage(response)
                sigio = io.BytesIO(sig)
                Util.sendDataPlain(self.messenger, sigio, compress=None)
                return (None, False)
            except Exception as e:
                self.logger.error("Could not recover data for checksum: %s: %s", chksum, str(e))
                self.exceptionLogger.log(e)
                errmsg = str(e)

        if response is None:
            response = {
                "message": Protocol.Commands.SIG,
                "respid" : msgid,
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

        savefull = self.config.savefull and not encrypted
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
                    if not basisFile.seekable():
                        # TODO: Is it possible to get here?  Is this just dead code?
                        temp = basisFile
                        basisFile = tempfile.TemporaryFile(dir=self.tempdir, prefix=self.tempPrefix)
                        shutil.copyfileobj(temp, basisFile)
                    patched = librsync.patch(basisFile, delta)
                    shutil.copyfileobj(patched, self.cache.open(checksum, "wb"))
                    self.db.insertChecksum(checksum, encrypted, size=size, disksize=bytesReceived)
                    self.db.setStats(self.statNewFiles, self.statUpdFiles, self.statBytesReceived)
                else:
                    if self.config.linkBasis:
                        self.cache.link(basis, checksum + ".basis")
                    self.db.insertChecksum(checksum, encrypted, size=size, deltasize=deltasize, basis=basis, compressed=compressed, disksize=bytesReceived)
                    self.db.setStats(self.statNewFiles, self.statUpdFiles, self.statBytesReceived)

                # record the metadata for this file
                Util.recordMetaData(self.cache, checksum, size, compressed, encrypted, bytesReceived, basis=basis, logger=self.logger)

                # Track that we've added a file of this size.
                self.sizes.add(size)

                self.statUpdFiles += 1

                self.logger.debug("Setting checksum for inode %s to %s", inode, checksum)
                self.db.setChecksum(inode, dev, checksum)
            except Exception as e:
                self.logger.error("Could not insert checksum %s: %s", checksum, str(e))
            output.close()
            # TODO: This has gotta be wrong.
        else:
            self.db.setChecksum(inode, dev, checksum)

        flush = size > 1000000
        message = {
            "message": Protocol.Responses.ACKDEL,
            "status" : "OK"
        }
        return (message, flush)

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
        (_, _, _, checksum, _) = Util.receiveData(self.messenger, output)

        if output is not None:
            output.close()

        response = { 'message': Protocol.Responses.ACKSIG, 'status': 'OK' }
        return (response, False)

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
            try:
                # Check to see if the checksum already exists
                info = self.db.getChecksumInfo(cksum)
                if info and info['isfile'] and info['size'] >= 0:
                    # if it does, set the new checksum
                    self.db.setChecksum(inode, dev, cksum)
                    done.append(f['inode'])
                else:
                    # else, check the old version
                    old = self.db.getFileInfoByInode((inode, dev))
                    # if it exists, and the chainlength is low, add a chain
                    if old and (old['chainlength'] < self.maxChain):
                        delta.append((f['inode'], old['checksum']))
                    else:
                        # else get the whol thing.
                        content.append(f['inode'])
            except Exception as e:
                self.logger.error("Could not check checksum for %s: %s", cksum, str(e))
                self.exceptionLogger.log(e)
                content.append(f['inode'])
        message = {
            "message": Protocol.Responses.ACKSUM,
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
            try:
                info = self.db.getChecksumInfo(cksum)
                if info and info['size'] != -1:
                    done.append(cksum)
                else:
                    # Insert a placeholder with a negative size
                    # But only if we don't already have one, left over from a previous failing build.
                    if not info:
                        self.db.insertChecksum(cksum, encrypted, -1)
                    content.append(cksum)
            except Exception as e:
                self.logger.error("Could process metadata for %s: %s", cksum, str(e))
                self.exceptionLogger.log(e)
                content.append(cksum)
        message = {
            'message': Protocol.Responses.ACKMETA,
            'content': content,
            'done': done
        }
        return (message, False)

    def processMetaData(self, message):
        """ Process a metadata content message, including all the data content chunks """
        self.logger.debug("Processing metadata message: %s", message)

        data = message["data"]
        for chunk in data:
            checksum = chunk["checksum"]
            size = chunk["size"]
            encrypted = chunk.get("encrypted", False)
            compressed = chunk.get("compressed", False)

            if self.cache.exists(checksum):
                self.logger.debug("Checksum file %s already exists", checksum)
            else:
                d = chunk["data"]
                with self.cache.open(checksum, "wb") as output:
                    output.write(bytes(d))
                self.db.updateChecksumFile(
                    checksum, encrypted, size, compressed=compressed, disksize=len(d)
                )
                self.statNewFiles += 1
                self.statBytesReceived += len(d)

        return ({"message": Protocol.Responses.ACKMETADATA, "status": "OK"}, False)

    def processPurge(self, message=None):
        self.logger.debug("Processing purge message: %s", str(message))
        message = message or {}
        prevTime = None
        if 'time' in message:
            if message['relative']:
                prevTime = float(self.db.prevBackupDate) - float(message['time'])
            else:
                prevTime = float(message['time'])
        elif self.configKeepTime:
            prevTime = float(self.db.prevBackupDate) - float(self.configKeepTime)

        if 'priority' in message:
            priority = message['priority']
        else:
            priority = self.configPriority

        # Purge the files
        if prevTime:
            (files, sets) = self.db.purgeSets(priority, prevTime)
            self.statPurgedSets += sets
            self.statPurgedFiles += files
            self.logger.info("Purged %d files in %d backup sets", files, sets)
            if files:
                self.purged = True
            return ({"message": Protocol.Responses.ACKPRG, "status": "OK"}, True)
        return ({"message": Protocol.Responses.ACKPRG, "status": "FAIL"}, True)

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
        self.logger.debug("Clone done")
        return ({"message" : Protocol.Responses.ACKCLN, "done" : done, 'content' : content }, True)

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
                        self.db.insertChecksum(checksum, encrypted, size, compressed=compressed, disksize=bytesReceived)
                        self.db.setStats(self.statNewFiles, self.statUpdFiles, self.statBytesReceived)
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
                    self.db.insertChecksum(checksum, encrypted, size, compressed=compressed, disksize=bytesReceived)
                    self.db.setStats(self.statNewFiles, self.statUpdFiles, self.statBytesReceived)
            else:
                self.db.insertChecksum(checksum, encrypted, size, compressed=compressed, disksize=bytesReceived)
                self.db.setStats(self.statNewFiles, self.statUpdFiles, self.statBytesReceived)

            (inode, dev) = message['inode']

            self.logger.debug("Setting checksum for inode %d to %s", inode, checksum)
            self.db.setChecksum(inode, dev, checksum)
            self.statNewFiles += 1
            # Record the metadata.  Do it here after we've inserted the file because on a full backup we could overwrite
            # a version which had a basis without updating the base file.
            Util.recordMetaData(self.cache, checksum, size, compressed, encrypted, bytesReceived, logger=self.logger)


        except Exception as e:
            self.logger.error("Could insert checksum %s info: %s", checksum, str(e))
            self.exceptionLogger.log(e)

        self.statBytesReceived += bytesReceived

        response = { 'message': Protocol.Responses.ACKCON, 'status': 'OK' }
        return (response, False)

    def processBatch(self, message):
        batch = message['batch']
        responses = []
        for mess in batch:
            (response, _) = self.processMessage(mess, transaction=False)
            if response:
                responses.append(response)

        response = {
            'message': Protocol.Responses.ACKBTCH,
            'responses': responses
        }
        self.db.setStats(self.statNewFiles, self.statUpdFiles, self.statBytesReceived)
        self.db.commit()
        return (response, True)

    def processSetKeys(self, message):
        filenameKey     = message['filenameKey']
        contentKey      = message['contentKey']
        srpSalt         = message['srpSalt']
        srpVkey         = message['srpVkey']
        cryptoScheme    = message['cryptoScheme']

        ret = self.db.setKeys(srpSalt, srpVkey, filenameKey, contentKey)
        self.db.setConfigValue('CryptoScheme', cryptoScheme)
        response = {
            'message': Protocol.Responses.ACKSETKEYS,
            'response': 'OK' if ret else 'FAIL'
        }
        return (response, True)

    def processClientConfig(self, message):
        if self.saveConfig:
            clientConfig = message['args']
            self.logger.debug("Received client config: %s", clientConfig)
            self.db.setClientConfig(clientConfig)
        response = {
            'message': Protocol.Responses.ACKCLICONFIG,
            'saved': self.saveConfig
        }
        return (response, False)

    def processDone(self, _):
        self.done = True
        response = {
            'message': Protocol.Responses.ACKDONE
        }
        return (response, True)

    def processCommandLine(self, message):
        cksum = message['hash']
        self.logger.debug("Received command line")
        ckInfo = self.db.getChecksumInfo(cksum)
        if ckInfo is None:
            self.logger.debug("Inserting command line file")
            f = self.cache.open(cksum, 'wb')
            if isinstance(message['line'], bytes):
                f.write(message['line'])
            else:
                f.write(bytes(message['line'], 'utf8'))
            cksid = self.db.insertChecksum(cksum, message['encrypted'], size=message['size'], disksize=f.tell())
            self.db.setStats(self.statNewFiles, self.statUpdFiles, self.statBytesReceived)
            f.close()
        else:
            cksid = ckInfo['checksumid']
        self.logger.debug("Command Line stored as checksum: %s => %d", cksum, cksid)
        self.db.setCommandLine(cksid)

        response = {
            'message': Protocol.Responses.ACKCMDLN
        }
        return (response, False)

    def processMessage(self, message, transaction=True):
        """ Dispatch a message to the correct handlers """
        try:
            messageType = message['message']
            # Stats
            self.statCommands[messageType] = self.statCommands.get(messageType, 0) + 1

            #if transaction:
            #    self.db.beginTransaction()

            match messageType:
                case Protocol.Commands.DIR:
                    (response, flush) = self.processDir(message)
                case Protocol.Commands.DHSH:
                    (response, flush) = self.processDirHash(message)
                case Protocol.Commands.SGR:
                    (response, flush) = self.processSigRequest(message)
                case Protocol.Commands.SGS:
                    (response, flush) = self.processManySigsRequest(message)
                case Protocol.Commands.SIG:
                    (response, flush) = self.processSignature(message)
                case Protocol.Commands.DEL:
                    (response, flush) = self.processDelta(message)
                case Protocol.Commands.CON:
                    (response, flush) = self.processContent(message)
                case Protocol.Commands.CKS:
                    (response, flush) = self.processChecksum(message)
                case Protocol.Commands.CLN:
                    (response, flush) = self.processClone(message)
                case Protocol.Commands.BATCH:
                    (response, flush) = self.processBatch(message)
                case Protocol.Commands.PRG:
                    (response, flush) = self.processPurge(message)
                case Protocol.Commands.CLICONFIG:
                    (response, flush) = self.processClientConfig(message)
                case Protocol.Commands.COMMANDLINE:
                    (response, flush) = self.processCommandLine(message)
                case Protocol.Commands.META:
                    (response, flush) = self.processMeta(message)
                case Protocol.Commands.METADATA:
                    (response, flush) = self.processMetaData(message)
                case Protocol.Commands.SETKEYS:
                    (response, flush) = self.processSetKeys(message)
                case Protocol.Commands.DONE:
                    (response, flush) = self.processDone(message)
                case _:
                    raise ProtocolError("Unknown message type", messageType)

            if response and 'msgid' in message:
                response['respid'] = message['msgid']
            if transaction:
                self.db.setStats(self.statNewFiles, self.statUpdFiles, self.statBytesReceived)
                self.db.commit()

            return (response, flush)
        except ProtocolError as e:
            raise ProtocolError(str(e)) from e
        except Exception as e:
            self.logger.error("Caught exception processing message: %s", json.dumps(message))
            self.exceptionLogger.log(e)
            raise ProcessingError(str(e)) from e

    def genPaths(self):
        self.logger.debug("Generating paths: %s", self.config.basedir)
        self.basedir    = os.path.join(self.config.basedir, self.client)
        dbdir           = os.path.join(self.config.dbdir, self.client)
        dbname          = self.config.dbname.format({'client': self.client})
        dbfile          = os.path.join(dbdir, dbname)
        return (dbdir, dbfile)

    def getCacheDir(self, create):
        try:
            self.logger.debug("Using cache dir: %s", self.basedir)
            return CacheDir.CacheDir(self.basedir, 1, 2,
                                     create=(self.config.allowNew and create),
                                     user=self.config.user,
                                     group=self.config.group,
                                     skipFile=self.config.skip)
        except CacheDir.CacheDirDoesNotExist as exc:
            if not self.config.allowNew:
                raise InitFailedException("Server does not allow new clients") from exc
            raise InitFailedException("Must request new client (--create))") from exc

    def getDB(self, client, create):
        script = None
        ret = "EXISTING"
        journal = None

        (dbdir, dbfile) = self.genPaths()

        if create and os.path.exists(dbfile):
            raise InitFailedException(f"Cannot create client {client}.  Already exists")

        self.cache = self.getCacheDir(create)

        connid = {'connid': self.idstr }

        if not os.path.exists(dbfile):
            if not os.path.exists(dbdir):
                os.makedirs(dbdir)
            self.logger.debug("Initializing database for %s with file %s", client, schemaFile)
            script = schemaFile
            ret = "NEW"

        if self.config.journal:
            journal = os.path.join(dbdir, self.config.journal)

        self.db = TardisDB.TardisDB(dbfile,
                                    initialize=script,
                                    backup=(self.config.dbbackups > 0),
                                    connid=connid,
                                    user=self.config.user,
                                    group=self.config.group,
                                    numbackups=self.config.dbbackups,
                                    journal=journal,
                                    allow_upgrade = self.config.allowUpgrades)

        self.regenerator = Regenerator.Regenerator(self.cache, self.db, TardisCrypto.Crypto_Null())
        return ret

    def setConfig(self):
        self.formats        = self.config.formats
        self.priorities     = self.config.priorities
        self.keep           = self.config.keep
        self.forceFull      = self.config.forceFull

        self.savefull       = self.config.savefull
        self.maxChain       = self.config.maxChain
        self.deltaPercent   = self.config.deltaPercent
        self.autoPurge      = self.config.autoPurge
        self.saveConfig     = self.config.saveConfig

        if self.config.allowOverrides:
            try:
                formats     = self.db.getConfigValue('Formats')
                priorities  = self.db.getConfigValue('Priorities')
                keepDays    = self.db.getConfigValue('KeepDays')
                forceFull   = self.db.getConfigValue('ForceFull')

                if formats:
                    self.logger.debug("Overriding global name formats: %s", formats)
                    self.formats        = list(map(str.strip, formats.split(',')))
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
                    self.saveconfig = bool(saveConfig)
            except Exception as e:
                self.logger.error("Client %s: Unable to override global configuration: %s", self.client, str(e))

    def startSession(self, name, force):
        self.name = name

        # Check if the previous backup session completed.
        prev = self.db.lastBackupSet(completed=False)
        if prev['endtime'] is None or checkSession(prev['session']):
            if force:
                self.logger.warning("Staring session %s while previous backup still warning: %s", name, prev['name'])
            else:
                if checkSession(prev['session']):
                    raise InitFailedException(f"Previous backup session still running: {prev['name']}.  Run with --force to force starting the new backup")
                self.logger.warning('Previous session for client %s (%s) did not complete.', self.client, prev['session'])

        addSession(self.sessionid, self.client)

        # Mark if the last session was completed
        self.lastCompleted = prev['completed']
        self.tempdir = os.path.join(self.basedir, "tmp")
        if not os.path.exists(self.tempdir):
            os.makedirs(self.tempdir)

    def endSession(self):
        try:
            pass
            #if (self.tempdir):
                # Clean out the temp dir
                #shutil.rmtree(self.tempdir)
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

    def doGetKeys(self):
        try:
            message = {"status": Protocol.Responses.NEEDKEYS }
            self.sendMessage(message)
            resp = self.recvMessage()
            self.checkMessage(resp, "SETKEYS")

            filenameKey = resp['filenameKey']
            contentKey  = resp['contentKey']
            srpSalt     = resp['srpSalt']
            srpVkey     = resp['srpVkey']
            cryptoScheme = resp['cryptoScheme']
            # ret = self.db.setKeys(srpSalt, srpVkey, filenameKey, contentKey)
            return(srpSalt, srpVkey, filenameKey, contentKey, cryptoScheme)
        except KeyError as e:
            raise InitFailedException(str(e)) from e

    def doSrpAuthentication(self):
        """
        Perform the SPR authentication steps  Start with the name and value A passed in from the
        connection call.
        """
        self.logger.debug("Beginning Authentication")
        try:
            cryptoScheme = self.db._getConfigValue('CryptoScheme', '1')
            message = {"message": Protocol.Responses.AUTH, "status": "AUTH", 'cryptoScheme': cryptoScheme, "client": self.db.clientId}
            self.sendMessage(message)
            auth1 = self.recvMessage()
            self.checkMessage(auth1, Protocol.Commands.AUTH1)
            name = base64.b64decode(auth1['srpUname'])
            srpValueA = base64.b64decode(auth1['srpValueA'])

            srpValueS, srpValueB = self.db.authenticate1(name, srpValueA)
            if srpValueS is None or srpValueB is None:
                raise TardisDB.AuthenticationFailed

            self.logger.debug("Sending Challenge values")
            message = {
                'message'   : Protocol.Commands.AUTH1,
                'status'    : 'OK',
                'srpValueS' : base64.b64encode(srpValueS),
                'srpValueB' : base64.b64encode(srpValueB),
                'respid'    : auth1.get('msgid', 0)
            }
            self.sendMessage(message)

            auth2 = self.recvMessage()
            self.logger.debug("Received challenge response")
            self.checkMessage(auth2, Protocol.Commands.AUTH2)
            srpValueM = base64.b64decode(auth2['srpValueM'])
            srpValueHAMK = self.db.authenticate2(srpValueM)
            message = {
                'message'       : Protocol.Commands.AUTH2,
                'status'        : 'OK',
                'srpValueHAMK'  : base64.b64encode(srpValueHAMK),
                'respid'        : auth2.get('msgid', 0)
            }
            self.logger.debug("Authenticated")
        except TardisDB.AuthenticationFailed as e:
            message = {
                'status'    : 'AUTHFAIL',
                'error'     : str(e)
            }
            self.sendMessage(message)
            raise
        return message

    def initializeBackup(self):
        try:
            message:dict = self.recvMessage()
            messType    = message['message']
            if messType != Protocol.Commands.BACKUP:
                raise InitFailedException(f"Unknown message type: {messType}")

            client      = message['host']            # TODO: Change at client as well.
            clienttime  = message['time']
            version     = message['version']

            autoname    = message.get('autoname', True)
            name        = message.get('name', None)
            full        = message.get('full', False)
            priority    = message.get('priority', 0)
            force       = message.get('force', False)
            create      = message.get('create', False)
            encrypted   = message.get('encrypted', False)

            self.logger.info("Creating backup for %s: %s (Autoname: %s) %s %s", client, name, str(autoname), version, clienttime)
        except ValueError:
            raise InitFailedException("Parsing error on backup message")
        except KeyError as e:
            raise InitFailedException(str(e))

        self.client = client

        (_, dbfile) = self.genPaths()
        self.logger.debug("Database File: %s", dbfile)

        if create and not self.config.allowNew:
            raise InitFailedException("New databases not allowed")
        if create and self.config.requirePW and not encrypted:
            raise InitFailedException("Server requires backups to be encrypted, ie, have a password")
        if create and os.path.exists(dbfile):
            raise InitFailedException(f"Client {client} already exists")
        if not create and not os.path.exists(dbfile):
            raise InitFailedException(f"Unknown client: {client}")

        keys = None
        if (self.config.requirePW or encrypted) and create:
            keys = self.doGetKeys()

        newBackup = self.getDB(client, create)

        serverForceFull = False
        authResp = None
        if create:
            if keys:
                srpSalt, srpVkey, filenameKey, contentKey, cryptoScheme = keys
                self.logger.debug("Setting keys into new client DB")
                self.logger.debug("Setting CryptoScheme %d", cryptoScheme)
                self.db.setKeys(srpSalt, srpVkey, filenameKey, contentKey)
                self.db.setConfigValue('CryptoScheme', cryptoScheme)
                keys = None
            else:
                self.db.setConfigValue('CryptoScheme', TardisCrypto.NO_CRYPTO_SCHEME)

        if self.config.requirePW and not self.db.needsAuthentication():
            raise InitFailedException("Passwords required on this server.  Please add a password (sonic setpass) and encrypt the DB if necessary")

        self.logger.debug("Ready for authentication")
        if self.db.needsAuthentication():
            authResp = self.doSrpAuthentication()

        disabled = self.db.getConfigValue('Disabled')
        if disabled is not None and int(disabled) != 0:
            raise InitFailedException(f"Client {client} is currently disabled.")

        self.setConfig()
        self.startSession(name, force)

        # Create a name
        if autoname:
            (serverName, serverPriority, serverKeepDays, serverForceFull) = self.calcAutoInfo(clienttime)
            self.logger.debug("Setting name, priority, keepdays to %s", (serverName, serverPriority, serverKeepDays))
            if serverName:
                self.configKeepTime = serverKeepDays * 3600 * 24
                self.configPriority = serverPriority
            else:
                self.configKeepTime = None
                self.configPriority = None
        else:
            serverName = None
            self.configKeepTime = None
            self.configPriority = None

        if autoname and serverName:
            self.name = serverName

        # Either the server or the client can specify a full backup.
        self.full = full or serverForceFull

        if priority is None:
            priority = 0

        # Create the actual backup set
        self.db.newBackupSet(name, self.sessionid, priority, clienttime, version, self.address, self.full, self.config.serverSessionID)

        response = {
            "message": Protocol.Responses.ACKBACKUP,
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

    def processBackupMessages(self):
        while True:
            flush = False
            message = self.recvMessage()
            if message is None:
                raise Exception("No message received")

            if message["message"] == "BYE":
                if 'error' in message:
                    raise Exception("Client Error: " + message['error'])
                break

            (response, flush) = self.processMessage(message)
            if response:
                self.sendMessage(response)
            if flush:
                self.db.commit()

    def runBackup(self):
        started   = False
        completed = False

        try:
            try:
                self.initializeBackup()
            except Exception as e:
                self.logger.error("Caught exception : %s", str(e))
                message = {"status": "FAIL", "error": str(e)}
                self.exceptionLogger.log(e)
                self.sendMessage(message)
                raise InitFailedException(str(e)) from e

            started = True

            #sock.sendall("OK {} {} {}".format(str(self.sessionid), str(self.db.prevBackupDate), serverName if serverName else name))
            self.processBackupMessages()

            # Shutdown the backup
            self.logger.debug("Completing Backup %s", self.idstr)
            if self.done:
                self.db.completeBackup()

                if self.name:
                    self.logger.debug("Changing backupset name to %s.  Priority is %s", self.name, self.configPriority)
                    self.db.setBackupSetName(self.name, self.configPriority)

            completed = True
        except Exception as e:
            self.logger.warning("Caught Exception during run: %s", str(e))
            self.exceptionLogger.log(e)
            if self.db:
                self.db.setFailure(e)

        finally:
            endtime = datetime.now()
            count = 0
            size = 0
            #sock.close()
            #self.messenger.closeSocket()

            rmSession(self.sessionid)

            if started:
                self.db.setClientEndTime()

                # Autopurge if it's set.
                if self.autoPurge and not self.purged and completed:
                    self.processPurge()
                self.endSession()
                self.db.setStats(self.statNewFiles, self.statUpdFiles, self.statBytesReceived)
                self.logger.debug("Removing orphans")
                (count, size, _) = Util.removeOrphans(self.db, self.cache)

            if self.db:
                self.db.commit()
                self.db.compact()
                self.db.close(started)

        return started, completed, endtime, count, size
