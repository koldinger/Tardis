#! /usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import uuid
import logging
import logging.config
import ConfigParser
import SocketServer
import tempfile
import hashlib
import base64
import subprocess

# For profiling
import cProfile
import StringIO
import pstats

import CacheDir
import TardisDB
import regenerate

sys.path.append("../utils")
import Messages

sessions = {}

DONE    = 0
CONTENT = 1
CKSUM   = 2
DELTA   = 3

config = None
profiler = None

def getDecoder(encoding):
    decoder = None
    if (encoding == "bin"):
        decoder = lambda x: x
        encoder = lambda x: x
    elif (encoding == "base64"):
        decoder = base64.b64encode
        decoder = base64.b64decode
    return decoder

class TardisServerHandler(SocketServer.BaseRequestHandler):
    numfiles = 0
    logger = logging.getLogger('Tardis')
    sessionid = None
    tempdir = None

    def checkFile(self, parent, f, dirhash):
        """ Process an individual file.  Check to see if it's different from what's there already """
        if f["dir"] == 1:
            retVal = DONE
        else:
            # Get the last backup information
            #old = self.db.getFileInfoByName(f["name"], parent)
            name = f["name"]
            inode = f["inode"]
            if name in dirhash:
                old = dirhash[name]
                self.logger.debug(u'Matching against old version for file {} ({})'.format(name, inode))
                #self.logger.debug("Comparing file structs: {} New: {} {} {} : Old: {} {} {}"
                                  #.format(f["name"], f["inode"], f["size"], f["mtime"], old["inode"], old["size"], old["mtime"]))
                if (old["inode"] == inode) and (old["size"] == f["size"]) and (old["mtime"] == f["mtime"]):
                    if ("checksum") in old and not (old["checksum"] is None):
                        self.db.copyChecksum(old["inode"], inode)
                        retVal = DONE
                    else:
                        #self.db.setChecksum(inode, old["checksum"])
                        retVal = CONTENT
                elif f["size"] < 4096:
                    # Just ask for content if the size is under 4K.  Easier.
                    retVal = CONTENT
                else:
                    retVal = DELTA
            else:
                if f["nlinks"] > 1:
                    # We're a file, and we have hard links.  Check to see if I've already been handled
                    self.logger.debug('Looking for file with same inode {} in backupset'.format(inode))
                    checksum = self.db.getChecksumByInode(inode, True)
                    if checksum:
                        self.db.setChecksum(inode, checksum)
                        retVal = DONE
                    else:
                        retVal = CONTENT
                else:
                    #Check to see if it already exists
                    self.logger.debug(u'Looking for similar file: {} ({})'.format(name, inode));
                    old = self.db.getFileInfoBySimilar(f)
                    if old:
                        if old["name"] == f["name"] and old["parent"] == parent:
                            # If the name and parent ID are the same, assume it's the same
                            retVal = DONE
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
        done = set()
        cksum = set()
        content = set()
        delta = set()
        queues = [done, content, cksum, delta]

        parentInode = data['inode']
        files = data['files']

        dirhash = {}

        # Get the old directory info
        if self.lastDirNode == parentInode:
            dirhash = self.lastDirHash
        else:
            directory = self.db.readDirectory(parentInode)
            for i in directory:
                dirhash[i["name"]] = i
            self.lastDirHash = dirhash
            self.lastDirNode = parentInode

        # Insert the current file info
        self.db.insertFiles(files, parentInode)

        for f in files:
            inode = f['inode']
            self.logger.debug(u'Processing file: {} {}'.format(f["name"], str(inode)))
            res = self.checkFile(parentInode, f, dirhash)
            # Shortcut for this:
            #if res == 0: done.append(inode)
            #elif res == 1: content.append(inode)
            #elif res == 2: cksum.append(inode)
            #elif res == 3: delta.append(inode)
            queues[res].add(inode)

        # self.db.commit()

        response = {
            "message": "ACKDIR",
            "status":  "OK",
            "inode": data["inode"],
            "done":  list(done),
            "cksum": list(cksum),
            "content": list(content),
            "delta": list(delta)
        }

        return response

    def processSigRequest(self, message):
        """ Generate and send a signature for a file """
        self.logger.debug("Processing signature request message: {}".format(str(message)))
        inode = message["inode"]

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
                pipe = subprocess.Popen(["rdiff", "signature"], stdin=rpipe, stdout=subprocess.PIPE)
                #pipe = subprocess.Popen(["rdiff", "signature", self.cache.path(chksum)], stdout=subprocess.PIPE)
                (sig, err) = pipe.communicate()
                # Cache the signature for later use.  Just in case.
                # TODO: Better logic on this?
                outfile = self.cache.open(sigfile, "wb")
                outfile.write(sig)
                outfile.close()

            # TODO: Set the encoder based on the protocol
            response = {
                "message": "SIG",
                "inode": inode,
                "status": "OK",
                "encoding": "base64",
                "checksum": chksum,
                "size": len(sig),
                "signature": self.messenger.encode(sig) }
            return response
        else:
            response = {
                "message": "SIG",
                "inode": inode,
                "status": "FAIL"
            }
            return response

    def processDelta(self, message):
        """ Receive a delta message. """
        self.logger.debug("Processing delta message: {}".format(str(message)))
        output = None
        temp = None
        digest = None
        checksum = message["checksum"]
        basis    = message["basis"]
        inode    = message["inode"]
        if self.cache.exists(checksum):
            self.logger.debug("Checksum file {} already exists".format(checksum))
            # Abort read
        else:
            if savefull:
                # Save the full output, rather than just a delta.  Save the delta to a file
                output = tempfile.NamedTemporaryFile(dir=self.tempdir, delete=True)
            else:
                output = self.cache.open(checksum, "wb")

        bytesReceived = 0
        size = message["size"]
        decoder = getDecoder(message["encoding"])

        while (bytesReceived < size):
            chunk = self.messenger.recvMessage()
            bytes = self.messenger.decode(chunk["data"])
            if output:
                output.write(bytes)
            bytesReceived += len(bytes)
        if output:
            output.flush()
            if savefull:
                # Process the delta file into the new file.
                subprocess.call(["rdiff", "patch", self.cache.path(basis), output.name], stdout=self.cache.open(checksum, "wb"))
                self.db.insertChecksumFile(checksum)
            else:
                self.db.insertChecksumFile(checksum, basis=basis)
            output.close()
            # TODO: This has gotta be wrong.

        self.db.setChecksum(inode, checksum)
        return {"message" : "OK"}

    def processSignature(self, message):
        """ Receive a delta message. """
        self.logger.debug("Processing signature message: {}".format(str(message)))
        output = None
        temp = None
        checksum = message["checksum"]
        basis    = message["basis"]
        inode    = message["inode"]

        decoder = getDecoder(message["encoding"])

        # If a signature is specified, receive it as well.
        sigfile = checksum + ".sig"
        if self.cache.exists(sigfile):
            self.logger.debug("Signature file {} already exists".format(sigfile))
            # Abort read
        else:
            output = self.cache.open(sigfile, "wb")
        bytesReceived = 0
        size = message["size"]
        while (bytesReceived < size):
            bytes = self.messenger.decode(chunk["data"])
            output.write(bytes)
            bytesReceived += len(bytes)
        output.close()

        self.db.setChecksum(inode, checksum)
        return {"message" : "OK"}

    def processChecksum(self, message):
        """ Process a list of checksums """
        self.logger.debug("Processing checksum message: {}".format(str(message)))
        done = []
        content = []
        for f in message["files"]:
            inode = f["inode"]
            cksum = f["checksum"]
            if self.cache.exists(cksum):
                self.db.setChecksum(inode, cksum)
                done.append(inode)
            else:
                content.append(inode)
        message = {
            "message": "ACKSUM",
            "status" : "OK",
            "done"   : done,
            "content": content
            }
        return message

    def processContent(self, message):
        """ Process a content message, including all the data content chunks """
        self.logger.debug("Processing content message: {}".format(str(message)))
        temp = None
        digest = None
        checksum = None
        if "checksum" in message:
            checksum = message["checksum"]
            if self.cache.exists(checksum):
                self.logger.debug("Checksum file {} already exists".format(checksum))
                # Abort read
            else:
                output = self.cache.open(checksum, "w")
        else:
            temp = tempfile.NamedTemporaryFile(dir=self.tempdir, delete=False)
            self.logger.debug("Sending output to temporary file {}".format(temp.name))
            output = temp.file
            digest = hashlib.md5()

        bytesReceived = 0
        size = message["size"]
        decoder = getDecoder(message["encoding"])

        while (bytesReceived < size):
            chunk = self.messenger.recvMessage()
            bytes = self.messenger.decode(chunk["data"])
            if digest:
                digest.update(bytes)
            output.write(bytes)
            bytesReceived += len(bytes)
        output.close()

        if temp:
            checksum = digest.hexdigest()
            if self.cache.exists(checksum):
                self.logger.debug("Checksum file {} already exists".format(checksum))
                os.remove(temp.name)
            else:
                self.cache.mkdir(checksum)
                self.logger.debug("Renaming {} to {}".format(temp.name, self.cache.path(checksum)))
                os.rename(temp.name, self.cache.path(checksum))
                self.db.insertChecksumFile(checksum)
        self.db.setChecksum(message["inode"], checksum)

        return {"message" : "OK" }

    def processClone(self, message):
        """ Clone an entire directory """
        done = []
        content = []
        for d in message['clones']:
            rows = self.db.cloneDir(d['inode'])
            if rows != d['numfiles']:
                content.append(d['inode'])
            else:
                done.append(d['inode'])
        return {"message" : "ACKCLN", "done" : done, 'content' : content }

    def processMessage(self, message):
        """ Dispatch a message to the correct handlers """
        messageType = message['message']

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
        else:
            raise Exception("Unknown message type", messageType)

    def getDB(self, host):
        self.basedir = os.path.join(basedir, host)
        self.cache = CacheDir.CacheDir(self.basedir, 2, 2)
        self.dbname = os.path.join(self.basedir, "tardis.db")
        self.db = TardisDB.TardisDB(self.dbname)
        self.regenerator = regenerate.Regenerator(self.cache, self.db)

    def startSession(self, name):
        self.sessionid = uuid.uuid1()
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
                os.rmdir(self.tempdir)
        except OSError as error:
            self.logger.warning("Unable to delete temporary directory: {}: {}".format(self.tempdir, error.strerror))

    def handle(self):
        if profiler:
            profiler.enable()

        try:
            self.request.sendall("TARDIS 1.0")
            message = self.request.recv(256).strip()
            self.logger.info(message)
            fields = message.split()
            if (len(fields) != 4 or fields[0] != 'BACKUP'):
                self.request.sendall("FAIL")
                raise Exception("Unrecognized command", message)
            host     = fields[1]
            name     = fields[2]
            encoding = fields[3]

            self.getDB(host)
            self.startSession(name)
            self.db.newBackupSet(name, str(self.sessionid))

            self.request.sendall("OK {} {}".format(str(self.sessionid), str(self.db.prevBackupDate)))

            if encoding == "JSON":
                self.messenger = Messages.JsonMessages(self.request)
            elif encoding == "BSON":
                self.messenger = Messages.BsonMessages(self.request)
            else:
                raise Exception("Unknown encoding", encoding)

            done = False;

            while not done:
                message = self.messenger.recvMessage()
                self.logger.debug("Received: " + str(message).encode("utf-8"))
                if message["message"] == "BYE":
                    done = True
                else:
                    response = self.processMessage(message)
                    self.logger.debug("Sending : " + str(response))
                    self.messenger.sendMessage(response)

            self.db.completeBackup()
        except:
            e = sys.exc_info()[0]
            self.logger.exception("Caught exception: {}".format(e))
        finally:
            self.request.close()
            self.endSession()
            if profiler:
                profiler.disable()
                s = StringIO.StringIO()
                sortby = 'cumulative'
                ps = pstats.Stats(profiler, stream=s).sort_stats(sortby)
                ps.print_stats()
                print s.getvalue()
            self.logger.info("Connection complete")

if __name__ == "__main__":
    defaultConfig = './tardisd.cfg'

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]

    parser = argparse.ArgumentParser(description='Tardis Backup Server')

    parser.add_argument('--config', dest='config', default=defaultConfig, help="Location of the configuration file")
    parser.add_argument('--single', dest='single', action='store_true', help='Run a single transaction and quit')
    parser.add_argument('--version', action='version', version='%(prog)s 0.1', help='Show the version')
    parser.add_argument('--logcfg', '-l', dest='logcfg', default=None, help='Logging configuration file');
    parser.add_argument('--verbose', '-v', action='count', default=0, dest='verbose', help='Increase the verbosity')
    parser.add_argument('--profile', dest='profile', default=None, help='Generate a profile')

    args = parser.parse_args()

    configDefaults = {
        'Port' : '9999',
        'BaseDir' : './cache',
        'SaveFull': True,
        'LogCfg'  : args.logcfg,
        'Profile' : args.profile
    }

    config = ConfigParser.ConfigParser(configDefaults)
    config.read(args.config)

    if config.get('Tardis', 'LogCfg'):
        print "Loading logging config"
        logging.config.fileConfig(config.get('Tardis', 'LogCfg'))
        logger = logging.getLogger('')
    else:
        logger = logging.getLogger('')
        format = logging.Formatter("%(levelname)s : %(name)s : %(message)s")
        handler = logging.StreamHandler()
        handler.setFormatter(format)
        logger.addHandler(handler)
        loglevel = levels[args.verbose] if args.verbose < len(levels) else logging.DEBUG
        logger.setLevel(loglevel)

    basedir = config.get('Tardis', 'BaseDir')
    savefull = config.get('Tardis', 'SaveFull')
    logger.debug("BaseDir: " + basedir)

    if config.get('Tardis', 'Profile'):
        profiler = cProfile.Profile()

    try:
        server = SocketServer.TCPServer(("localhost", config.getint('Tardis', 'Port')), TardisServerHandler)
        logger.info("Starting server");
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    except:
        logger.critical("Unable to run server: {}".format(sys.exc_info()[1].strerror))
