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

import os
import types
import sys
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
from rdiff_backup import librsync

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

sessions = {}

DONE    = 0
CONTENT = 1
CKSUM   = 2
DELTA   = 3

config = None
databaseName = 'tardis.db'
schemaName   = 'schema/tardis.sql'
schemaFile   = None
parentDir    = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
configName   = '/etc/tardis/tardisd.cfg'
messages = [ "DIR", "SGR", "SIG", "DEL", "CON", "CKS", "CLN", "CPY", "BATCH", "TMPDIR", "PRG" ]

server = None
logger = None

pp = pprint.PrettyPrinter(indent=2, width=200)

logging.TRACE = logging.DEBUG - 1

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

    def setup(self):
        self.sessionid = uuid.uuid1()
        logger = logging.getLogger('Tardis')
        self.logger = ConnIdLogAdapter.ConnIdLogAdapter(logger, {'connid': self.client_address[0]})

    def checkFile(self, parent, f, dirhash):
        """ Process an individual file.  Check to see if it's different from what's there already """
        name = f["name"]
        inode = f["inode"]

        self.logger.debug("Processing Inode: %8d -- File: %s", inode, name)
        
        if name in dirhash:
            old = dirhash[name]
        else:
            old = None

        if f["dir"] == 1:
            if old:
                if (old["inode"] == inode) and (old["mtime"] == f["mtime"]):
                    self.db.extendFile(parent, f['name'])
                else:
                    self.db.insertFile(f, parent)
            else:
                self.db.insertFile(f, parent)
            retVal = DONE
        else:
            # Get the last backup information
            #old = self.db.getFileInfoByName(f["name"], parent)
            name = f["name"].encode('utf-8')
            inode = f["inode"]
            if name in dirhash:
                old = dirhash[name]
                self.logger.debug('Matching against old version for file %s (%d)', f["name"], inode)
                #self.logger.debug("Comparing file structs: {} New: {} {} {} : Old: {} {} {}"
                                  #.format(f["name"], f["inode"], f["size"], f["mtime"], old["inode"], old["size"], old["mtime"]))
                #if (old["inode"] == inode) and (old["size"] == f["size"]) and (old["mtime"] == f["mtime"]):
                if (old["inode"] == inode) and (old["size"] == f["size"]) and (old["mtime"] == f["mtime"]) and (old['mode'] == f['mode']):
                    if ("checksum") in old and not (old["checksum"] is None):
                        #self.db.setChecksum(inode, old['checksum'])
                        self.db.extendFile(parent, f['name'])
                        retVal = DONE
                    else:
                        self.db.insertFile(f, parent)
                        retVal = CONTENT
                elif (old["size"] == f["size"]) and ("checksum") in old and not (old["checksum"] is None):
                        self.db.insertFile(f, parent)
                        retVal = CKSUM
                elif f["size"] < 4096 or old["size"] is None:
                    # Just ask for content if the size is under 4K, or the old filesize is marked as 0.
                    self.db.insertFile(f, parent)
                    retVal = CONTENT
                else:
                    self.db.insertFile(f, parent)
                    retVal = DELTA
            else:
                self.db.insertFile(f, parent)
                if f["nlinks"] > 1:
                    # We're a file, and we have hard links.  Check to see if I've already been handled
                    self.logger.debug('Looking for file with same inode %d in backupset', inode)
                    checksum = self.db.getChecksumByInode(inode, True)
                    if checksum:
                        self.db.setChecksum(inode, checksum)
                        retVal = DONE
                    else:
                        retVal = CONTENT
                else:
                    #Check to see if it already exists
                    self.logger.debug(u'Looking for similar file: %s (%s)', name, inode)
                    old = self.db.getFileInfoBySimilar(f)
                    if old is None:
                        old = self.db.getFileFromPartialBackup(f)

                    if old:
                        if old["name"] == f["name"] and old["parent"] == parent:
                            # If the name and parent ID are the same, assume it's the same
                            if ("checksum") in old and not (old["checksum"] is None):
                                self.db.setChecksum(inode, old['checksum'])
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
        # Keep the order
        queues = [done, content, cksum, delta]

        parentInode = data['inode']
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
                dirInode = oldDir['inode']
            else:
                # Otherwise
                dirInode = parentInode
            directory = self.db.readDirectory(dirInode)
            for i in directory:
                dirhash[i["name"]] = i
            self.lastDirHash = dirhash
            self.lastDirNode = parentInode

        for f in files:
            inode = f['inode']
            fileId = (f['dev'], f['inode'])
            self.logger.debug(u'Processing file: %s %d %s', f["name"], inode, fileId)
            res = self.checkFile(parentInode, f, dirhash)
            # Shortcut for this:
            #if res == 0: done.append(inode)
            #elif res == 1: content.append(inode)
            #elif res == 2: cksum.append(inode)
            #elif res == 3: delta.append(inode)
            queues[res].add(fileId)

        response = {
            "message"   : "ACKDIR",
            "status"    : "OK",
            "path"      : data["path"],
            "inode"     : data["inode"],
            "done"      : list(done),
            "cksum"     : list(cksum),
            "content"   : list(content),
            "delta"     : list(delta)
        }

        return (response, True)

    def processSigRequest(self, message):
        """ Generate and send a signature for a file """
        #self.logger.debug("Processing signature request message: %s"format(str(message)))
        (dev, inode) = message["inode"]
        response = None

        ### TODO: Remove this function.  Clean up.
        info = self.db.getNewFileInfoByInode(inode)
        chksum = self.db.getChecksumByName(info["name"], info["parent"])      ### Assumption: Current parent is same as old

        if chksum:
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
                        s = librsync.SigFile(rpipe)
                        sig = s.read()

                        outfile = self.cache.open(sigfile, "wb")
                        outfile.write(sig)
                        outfile.close()
                        # TODO: Break the signature out of here.
                        response = {
                            "message": "SIG",
                            "inode": inode,
                            "status": "OK",
                            "encoding": self.messenger.getEncoding(),
                            "checksum": chksum,
                            "size": len(sig),
                            "signature": self.messenger.encode(sig) }
                    except (librsync.librsyncError, Regenerate.RegenerateException) as e:
                        self.logger.error("Unable to generate signature for inode: {}, checksum: {}: {}".format(inode, chksum, e))

        if response is None:
            response = {
                "message": "SIG",
                "inode": inode,
                "status": "FAIL"
            }
        return (response, False)

    def processDelta(self, message):
        """ Receive a delta message. """
        self.logger.debug("Processing delta message: %s", message)
        output  = None
        temp    = None
        checksum = message["checksum"]
        basis    = message["basis"]
        size     = message["size"]          # size of the original file, not the content
        (dev, inode)    = message["inode"]
        iv = self.messenger.decode(message['iv']) if 'iv' in message else None
        deltasize = message['deltasize'] if 'deltasize' in message else None

        savefull = self.server.savefull and iv is not None
        if self.cache.exists(checksum):
            self.logger.debug("Checksum file %s already exists", checksum)
            # Abort read
        else:
            if not savefull:
                chainLength = self.db.getChainLength(basis)
                if chainLength >= self.server.maxChain:
                    self.logger.debug("Chain length %d.  Converting %s (%s) to full save", chainLength, basis, inode)
                    savefull = True
            if savefull:
                # Save the full output, rather than just a delta.  Save the delta to a file
                #output = tempfile.NamedTemporaryFile(dir=self.tempdir, delete=True)
                output = tempfile.SpooledTemporaryFile(dir=self.tempdir)
            else:
                output = self.cache.open(checksum, "wb")

        bytesReceived = 0

        while True:
            chunk = self.messenger.recvMessage()
            if chunk['chunk'] == 'done': break
            bytes = self.messenger.decode(chunk["data"])
            if output: output.write(bytes)
            bytesReceived += len(bytes)

        if deltasize is None:
            deltasize = bytesReceived

        if output:
            if savefull:
                output.seek(0)
                # Process the delta file into the new file.
                #subprocess.call(["rdiff", "patch", self.cache.path(basis), output.name], stdout=self.cache.open(checksum, "wb"))
                basisFile = self.regenerator.recoverChecksum(basis)
                if type(basisFile) != types.FileType:
                    temp = basisFile
                    basisFile = tempfile.TemporaryFile(dir=self.tempdir)
                    shutil.copyfileobj(temp, basisFile)
                patched = librsync.PatchedFile(basisFile, output)
                shutil.copyfileobj(patched, self.cache.open(checksum, "wb"))
                self.db.insertChecksumFile(checksum, iv, size=size)
            else:
                self.db.insertChecksumFile(checksum, iv, size=size, deltasize=deltasize, basis=basis)
            output.close()
            # TODO: This has gotta be wrong.

        self.statUpdFiles += 1
        self.statBytesReceived += bytesReceived

        self.logger.debug("Setting checksum for inode %s to %s", inode, checksum)
        self.db.setChecksum(inode, checksum)
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
        bytesReceived = 0
        while True:
            chunk = self.messenger.recvMessage()
            if chunk['chunk'] == 'done':
                size = chunk["size"]
                break

            bytes = self.messenger.decode(chunk["data"])
            if output is not None:
                output.write(bytes)
            bytesReceived += len(bytes)

        if output is not None:
            output.close()

        #self.db.setChecksum(inode, checksum)
        return (None, False)

    def processChecksum(self, message):
        """ Process a list of checksums """
        self.logger.debug("Processing checksum message: %s", message)
        done = []
        content = []
        for f in message["files"]:
            (dev, inode) = f["inode"]
            cksum = f["checksum"]
            if self.cache.exists(cksum):
                self.db.setChecksum(inode, cksum)
                done.append(f['inode'])
            else:
                # FIXME: TODO: If no checksum, should we request a delta???
                content.append(f['inode'])
        message = {
            "message": "ACKSUM",
            "status" : "OK",
            "done"   : done,
            "content": content
            }
        return (message, False)

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
            temp = tempfile.NamedTemporaryFile(dir=self.tempdir, delete=False)
            self.logger.debug("Sending output to temporary file %s", temp.name)
            output = temp.file

        if 'iv' in message:
            iv = self.messenger.decode(message['iv'])
        else:
            iv = None

        bytesReceived = 0

        while True:
            chunk = self.messenger.recvMessage()
            if chunk['chunk'] == 'done':
                size = chunk["size"]
                checksum = chunk['checksum']
                break

            bytes = self.messenger.decode(chunk["data"])
            output.write(bytes)
            bytesReceived += len(bytes)
        output.close()

        if temp:
            if self.cache.exists(checksum):
                self.logger.debug("Checksum file %s already exists.  Deleting temporary version", checksum)
                os.remove(temp.name)
            else:
                self.cache.mkdir(checksum)
                self.logger.debug("Renaming %s to %s",temp.name, self.cache.path(checksum))
                os.rename(temp.name, self.cache.path(checksum))
                self.db.insertChecksumFile(checksum, iv, size)
        else:
            self.db.insertChecksumFile(checksum, iv, size, basis=basis)

        (dev, inode) = message['inode']

        self.logger.debug("Setting checksum for inode %d to %s", inode, checksum)
        self.db.setChecksum(inode, checksum)

        self.statNewFiles += 1
        self.statBytesReceived += bytesReceived

        #return {"message" : "OK", "inode": message["inode"]}
        flush = False
        if bytesReceived > 1000000:
            flush = True;
        return (None, flush)

    def processCopy(self, message):
        (dev, inode) = message['inode']
        copyfile = message['file']
        checksum = message['checksum']
        size     = message['size']
        if 'iv' in message:
            iv = self.messenger.decode(message['iv'])
        else:
            iv = None

        if self.cache.exists(checksum):
            self.logger.debug("Checksum file %s already exists.  Deleting temporary version", checksum)
            os.remove(copyfile)
        else:
            self.cache.mkdir(checksum)
            self.logger.debug("Renaming %s to %s", copyfile, self.cache.path(checksum))
            os.rename(copyfile, self.cache.path(checksum))
            self.db.insertChecksumFile(checksum, iv, size)
        self.logger.debug("Setting checksum for inode %d to %s", message['inode'], checksum)
        self.db.setChecksum(inode, checksum)
        flush = False
        if size > 1000000:
            flush = True;
        return (None, flush)

    def processPurge(self, message):
        self.logger.debug("Processing purge message: {}".format(str(message)))
        if message['relative']:
            prevTime = float(self.db.prevBackupDate) - float(message['time'])
        else:
            prevTime = float(message['time'])

        # Purge the files
        (files, sets) = self.db.purgeFiles(message['priority'], prevTime)
        self.logger.info("Purged %d files in %d backup sets", files, sets)
        if files:
            self.purged = True
        return ({"message" : "PURGEOK"}, True)

    def checksumDir(self, dirNode):
        """ Generate a checksum of the file names in a directory"""
        # Create a list of files, extracted from the directory
        # ONLY include those that are directories, or that have a checksum ID
        # eliminates any files which don't have a valid backup.
        # Sort them to be in the same order as the sender
        filenames = sorted([x['name'] for x in self.db.readDirectory(dirNode) if (x['size'] is not None or x['dir'] == 1)]) 
        length = len(filenames)

        m = hashlib.md5()
        for f in filenames:
            m.update(f)
        return (length, m.hexdigest())

    def processClone(self, message):
        """ Clone an entire directory """
        done = []
        content = []
        for d in message['clones']:
            inode = d['inode']
            (numfiles, checksum) = self.checksumDir(inode)
            if numfiles != d['numfiles'] or checksum != d['cksum']:
                self.logger.debug("No match on clone.  Inode: %d Rows: %d %d Checksums: %s %s", inode, numfiles, d['numfiles'], checksum, d['cksum'])
                content.append(d['inode'])
            else:
                rows = self.db.cloneDir(d['inode'])
                done.append(d['inode'])
        return ({"message" : "ACKCLN", "done" : done, 'content' : content }, True)

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

    def processTmpDir(self, message):
        if self.server.allowCopies:
            response = {'message': 'ACKTDIR', "status": "OK", "target": self.tempdir }
        else:
            response = {'message': 'ACKTDIR', "status": "FAIL" }
        return (response, False)

    def processMessage(self, message):
        """ Dispatch a message to the correct handlers """
        messageType = message['message']
        #if not messageType in self.statCommands:
        #    self.statCommands[messageType] = 1
        #else:
        #    self.statCommands[messageType] += 1
        self.statCommands[messageType] = self.statCommands.get(messageType, 0) + 1

        if messageType == "DIR":
            return self.processDir(message)
        elif messageType == "SGR":
            return self.processSigRequest(message)
        elif messageType == "SIG":
            return self.processSignature(message)
        elif messageType == "DEL":
            return self.processDelta(message)
        elif messageType == "CON":
            return self.processContent(message)
        elif messageType == "CKS":
            return self.processChecksum(message)
        elif messageType == "CLN":
            return self.processClone(message)
        elif messageType == "CPY":
            return self.processCopy(message)
        elif messageType == "BATCH":
            return self.processBatch(message)
        elif messageType == "TMPDIR":
            return self.processTmpDir(message)
        elif messageType == "PRG":
            return self.processPurge(message)
        else:
            raise Exception("Unknown message type", messageType)

    def getDB(self, host):
        script = None
        self.basedir = os.path.join(self.server.basedir, host)
        self.cache = CacheDir.CacheDir(self.basedir, 2, 2)
        self.dbname = os.path.join(self.basedir, databaseName)
        if not os.path.exists(self.dbname):
            self.logger.debug("Initializing database for %s with file %s", host, schemaFile)
            script = schemaFile
        self.db = TardisDB.TardisDB(self.dbname, initialize=script, extra={'connid': self.client_address[0]})

        self.regenerator = Regenerate.Regenerator(self.cache, self.db)

    def startSession(self, name):
        #self.sessionid = uuid.uuid1()
        self.name = name
        sid = str(self.sessionid)
        sessions[sid] = self

        self.tempdir = os.path.join(self.basedir, "tmp_" + sid)
        os.makedirs(self.tempdir)

    def endSession(self):
        if self.sessionid:
            try:
                del sessions[str(self.sessionid)]
            except KeyError:
                pass
        try:
            if (self.tempdir):
                # Clean out the temp dir
                shutil.rmtree(self.tempdir)
        except OSError as error:
            self.logger.warning("Unable to delete temporary directory: %s: %s", self.tempdir, error.strerror)

    def removeOrphans(self):
        # Now remove any leftover orphans
        if self.db:
            # Get a list of orphan'd files
            orphans = self.db.listOrphanChecksums()
            self.logger.debug("Attempting to remove orphans")
            size = 0
            count = 0
            for c in orphans:
                # And remove them each....
                try:
                    s = os.stat(self.cache.path(c))
                    if s:
                        count += 1
                        size += s.st_size
                    self.cache.remove(c)
                except OSError:
                    self.logger.warning("No checksum file for checksum %s", c)
                except:
                    e = sys.exc_info()[0]
                    self.logger.exception(e)
                self.db.deleteChecksum(c)
            if count:
                self.logger.info("Removed %d orphans, %s", count, Util.fmtSize(size))
                self.purged = True


    def handle(self):
        printMessages = self.logger.isEnabledFor(logging.TRACE)

        if self.server.profiler:
            self.logger.info("Starting Profiler")
            self.server.profiler.enable()

        try:
            self.request.sendall("TARDIS 1.0")
            message = self.request.recv(256).strip()
            self.logger.info(message)
            fields = message.split()
            if (len(fields) != 6 or fields[0] != 'BACKUP'):
                self.request.sendall("FAIL")
                raise Exception("Unrecognized command", message)
            (command, host, name, encoding, priority, clienttime) = fields

            self.getDB(host)
            self.startSession(name)
            self.db.newBackupSet(name, str(self.sessionid), priority, clienttime)

            self.request.sendall("OK {} {}".format(str(self.sessionid), str(self.db.prevBackupDate)))

            if encoding == "JSON":
                self.messenger = Messages.JsonMessages(self.request)
            elif encoding == "BSON":
                self.messenger = Messages.BsonMessages(self.request)
            else:
                raise Exception("Unknown encoding", encoding)

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
        except:
            e = sys.exc_info()[0]
            self.logger.error("Caught exception: %s", e)
            self.logger.exception(e)
        finally:
            self.request.close()
            self.endSession()
            if self.server.profiler:
                self.logger.info("Stopping Profiler")
                self.server.profiler.disable()
                s = StringIO.StringIO()
                sortby = 'cumulative'
                ps = pstats.Stats(self.server.profiler, stream=s).sort_stats(sortby)
                ps.print_stats()
                print s.getvalue()
            self.logger.info("Connection complete")
            self.logger.info("New or replaced files:    %d", self.statNewFiles)
            self.logger.info("Updated file:             %d", self.statUpdFiles)
            self.logger.info("Total file data received: %s", Util.fmtSize(self.statBytesReceived))
            self.logger.info("Command breakdown:        %s", self.statCommands)
            self.logger.debug("Removing orphans")
            self.removeOrphans()
            if self.purged:
                self.db.compact()


#class TardisSocketServer(SocketServer.TCPServer):
class TardisSocketServer(SocketServer.ForkingMixIn, SocketServer.TCPServer):
    config = None

    def __init__(self, config):
        self.config = config
        SocketServer.TCPServer.__init__(self, ("", config.getint('Tardis', 'Port')), TardisServerHandler)

        self.basedir        = config.get('Tardis', 'BaseDir')
        self.savefull       = config.getboolean('Tardis', 'SaveFull')
        self.maxChain       = config.getint('Tardis', 'MaxDeltaChain')
        self.deltaPercent   = config.getint('Tardis', 'MaxChangePercent')
        self.dbname         = config.get('Tardis', 'DBName')
        self.allowCopies    = config.getboolean('Tardis', 'AllowCopies')

        self.ssl        = config.getboolean('Tardis', 'SSL')
        if self.ssl:
            certfile   = config.get('Tardis', 'CertFile')
            keyfile    = config.get('Tardis', 'KeyFile')
            self.socket = ssl.wrap_socket(self.socket, server_side=True, certfile=certfile, keyfile=keyfile, ssl_version=ssl.PROTOCOL_TLSv1)

        if config.get('Tardis', 'Profile'):
            self.profiler = cProfile.Profile()
        else:
            self.profiler = None

def setupLogging(config):
    levels = [logging.WARNING, logging.INFO, logging.DEBUG, logging.TRACE]

    logging.addLevelName(logging.TRACE, 'Message')

    if config.get('Tardis', 'LogCfg'):
        logging.config.fileConfig(config.get('Tardis', 'LogCfg'))
        logger = logging.getLogger('')
    else:
        logger = logging.getLogger('')
        format = logging.Formatter("%(asctime)s %(levelname)s : %(message)s")

        verbosity = config.getint('Tardis', 'Verbose')

        if config.get('Tardis', 'LogFile'):
            handler = logging.handlers.WatchedFileHandler(config.get('Tardis', 'LogFile'))
        elif config.getboolean('Tardis', 'Daemon'):
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

    logger.info("Starting server");

    try:
        #server = SocketServer.TCPServer(("", config.getint('Tardis', 'Port')), TardisServerHandler)
        server = TardisSocketServer(config)

        if (config.getboolean('Tardis', 'Single')):
            server.handle_request()
        else:
            try:
                server.serve_forever()
            except:
                logger.info("Socket server completed")
        logger.info("Ending")
    except Exception:
        logger.critical("Unable to run server: {}".format(sys.exc_info()[1]))
        logger.exception(sys.exc_info()[1])

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

def main():
    # Compute the path to the default schema.  Needs to be done here for some reason
    schemaLocal   = os.path.join(parentDir, schemaName)

    parser = argparse.ArgumentParser(description='Tardis Backup Server')

    parser.add_argument('--config',         dest='config', default=configName, help="Location of the configuration file")
    parser.add_argument('--single',         dest='single', action='store_true', help='Run a single transaction and quit')
    parser.add_argument('--dbname', '-d',   dest='dbname', default=databaseName, help='Use the database name')
    parser.add_argument('--schema',         dest='schema', default=schemaLocal, help='Path to the schema to use')
    parser.add_argument('--logfile', '-l',  dest='logfile', default=None, help='Log to file')
    parser.add_argument('--version',        action='version', version='%(prog)s 0.1', help='Show the version')
    parser.add_argument('--logcfg', '-L',   dest='logcfg', default=None, help='Logging configuration file');
    parser.add_argument('--verbose', '-v',  action='count', default=0, dest='verbose', help='Increase the verbosity')
    parser.add_argument('--allow-copies',   action='store_true', dest='copies', default=False, help='Allow the client to copy files in directly')
    parser.add_argument('--profile',        dest='profile', default=None, help='Generate a profile')

    parser.add_argument('--daemon', '-D',   action='store_true', dest='daemon', default=False, help='Run as a daemon')
    parser.add_argument('--user', '-U',     dest='user',  default=None, help='Run daemon as user.  Valid only if --daemon is set')
    parser.add_argument('--group', '-G',    dest='group', default=None, help='Run daemon as group.  Valid only if --daemon is set')
    parser.add_argument('--pidfile', '-P',  dest='pidfile', default='/var/run/tardisd.pid', help='Use this pidfile to indicate running daemon')

    sslgroup = parser.add_mutually_exclusive_group()
    sslgroup.add_argument('--ssl', '-s',    dest='ssl', action='store_true', default=False, help='Use SSL connections')
    sslgroup.add_argument('--nossl',        dest='ssl', action='store_false', help='Do not use SSL connections')

    parser.add_argument('--certfile', '-c', dest='certfile', default=None, help='Path to certificate file for SSL connections')
    parser.add_argument('--keyfile', '-k',  dest='keyfile',  default=None, help='Path to key file for SSL connections')

    args = parser.parse_args()

    configDefaults = {
        'Port'          : '9999',
        'BaseDir'       : './cache',
        'SaveFull'      : str(True),
        'DBName'        : args.dbname,
        'Schema'        : args.schema,
        'LogCfg'        : args.logcfg,
        'Profile'       : args.profile,
        'LogFile'       : args.logfile,
        'AllowCopies'   : str(args.copies),
        'Single'        : str(args.single),
        'Verbose'       : str(args.verbose),
        'Daemon'        : str(args.daemon),
        'User'          : args.user,
        'Group'         : args.group,
        'SSL'           : str(args.ssl),
        'CertFile'      : args.certfile,
        'KeyFile'       : args.keyfile,
        'PidFile'       : args.pidfile
    }

    global config
    config = ConfigParser.ConfigParser(configDefaults)
    config.read(args.config)

    if config.get('Tardis', 'Profile'):
        profiler = cProfile.Profile()
    if config.get('Tardis', 'Schema'):
        global schemaFile
        schemaFile = config.get('Tardis', 'Schema')

    # Set up a handler
    signal.signal(signal.SIGTERM, signal_term_handler)
    global logger
    try:
        logger = setupLogging(config)
    except Exception as e:
        print >> sys.stderr, "Unable to initialize logging: {}".format(str(e))
        sys.exit(1)

    if config.getboolean('Tardis', 'Daemon'):
        user  = config.get('Tardis', 'User')
        group = config.get('Tardis', 'Group')
        pidfile = config.get('Tardis', 'PidFile')
        try:
            daemon = daemonize.Daemonize(app="tardisd", pid=pidfile, action=run_server, user=user, group=group)
            daemon.start()
        except Exception as e:
            print >> "Caught Exception on Daemonize call: {}".format(e)
    else:
        try:
            run_server()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print "Unable to run server: {}".format(e)
            traceback.print_exc()

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        traceback.print_exc()
