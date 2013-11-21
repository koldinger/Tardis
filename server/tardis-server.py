#! /usr/bin/python

import os
import sys
import argparse
import uuid
import json
import logging
import logging.config
import ConfigParser
import SocketServer
import tempfile
import hashlib
import base64
import subprocess

import CacheDir
import TardisDB

sys.path.append("../utils")
import Messages

sessions = {}

DONE    = 0
CONTENT = 1
CKSUM   = 2
DELTA   = 3

config = None

class TardisServerHandler(SocketServer.BaseRequestHandler):
    numfiles = 0
    logger = logging.getLogger('Tardis')
    sessionid = None

    def checkFile(self, parent, file):
        """ Process an individual file.  Check to see if it's different from what's there already """

        # Insert the current file info
        self.db.insertFile(file, parent)
        #logger.debug("NFile: {}".format(str(file)))
        #logger.debug("OFile: {}".format(str(old)))

        if file["dir"] == 1:
            retVal = DONE
        else:
            # Get the last backup information
            old = self.db.getFileInfoByName(file["name"], parent)
            if old != None:
                self.logger.debug("Comparing file structs: {} New: {} {} {} : Old: {} {} {}"
                                  .format(file["name"], file["inode"], file["size"], file["mtime"], old["inode"], old["size"], old["mtime"]))
                if (old["inode"] == file["inode"]) and (old["size"] == file["size"]) and (old["mtime"] == file["mtime"]):
                    self.db.copyChecksum(old["inode"], file["inode"])
                    retVal = DONE
                elif file["size"] < 32:
                    # Just ask for content if the size is under 4K.  Easier.
                    retVal = CONTENT
                else:
                    retVal = DELTA
            else:
                old = self.db.getFileInfoBySimilar(file)
                if old:
                    retVal = CHKSUM
                else:
                    # TODO: Lookup based on inode.
                    self.logger.debug("No old file.")
                    retVal = CONTENT
            
        return retVal

    def processDir(self, data):
        """ Process a directory message.  Lookup each file in the previous backup set, and determine if it's changed. """
        self.logger.debug("Processing directory entry: {} : {}".format(data["path"], str(data["inode"])))
        done = []
        cksum = []
        content = []
        delta = []

        parentInode = data['inode']

        for file in data['files']:
            self.logger.debug("Processing file: {} {}".format(file["name"], str(file["inode"])))
            inode = file['inode']
            res = self.checkFile(parentInode, file)
            if res == 0:
                done.append(inode)
            elif res == 1:
                content.append(inode)
            elif res == 2:
                cksum.append(inode)
            elif res == 3:
                delta.append(inode)

        # self.db.commit()

        response = {
            "message": "ACKDIR",
            "status":  "OK",
            "inode": data["inode"],
            "done":  done,
            "cksum": cksum,
            "content": content,
            "delta": delta
        }

        return response

    def processSignature(self, message):
        """ Generate and send a signature for a file """
        self.logger.debug("Processing signature request message: {}".format(str(message)))
        inode = message["inode"]

        info = self.db.getNewFileInfoByInode(inode)
        chksum = self.db.getChecksum(info["name"], info["parent"])      ### Assumption: Current parent is same as old
        if chksum:
            sigfile = chksum + ".sig"
            if self.cache.exists(sigfile):
                file = self.cache.open(sigfile, "rb")
                sig = file.read()       # TODO: Does this always read the entire file?
                file.close()
            else:
                pipe = subprocess.Popen(["rdiff", "signature", self.cache.path(chksum)], stdout=subprocess.PIPE)
                (sig, err) = pipe.communicate()
                # Cache the signature for later use.  Just in case.
                # TODO: Better logic on this?
                outfile = self.cache.open(sigfile, "wb")
                outfile.write(sig)
                outfile.close()

            response = {
                "message": "SIG",
                "inode": inode,
                "status": "OK",
                "encoding": "base64",
                "checksum": chksum,
                "size": len(sig),
                "signature": base64.encodestring(sig) }

            return response
        else:
            # TODO: Screw this up
            pass

    def processDelta(self, message):
        """ Receive a delta message. """
        self.logger.debug("Processing delta message: {}".format(str(message)))
        output = None
        temp = None
        digest = None
        checksum = message["checksum"]
        basis    = message["basis"]
        inode = message["inode"]
        if self.cache.exists(checksum):
            self.logger.debug("Checksum file {} already exists".format(checksum))
            # Abort read
        else:
            output = self.cache.open(checksum, "wb")

        bytesReceived = 0
        size = message["size"]
        encoding = message["encoding"]
        if (encoding == "binary"):
            decoder = lambda x: x
        elif (encoding == "base64"):
            decoder = base64.decodestring

        while (bytesReceived < size):
            chunk = self.messenger.recvMessage()
            bytes = decoder(chunk["data"])
            if output:
                output.write(bytes)
            bytesReceived += len(bytes)
        if output:
            output.close()
            # TODO: This has gotta be wrong.
            self.db.insertChecksumFile(checksum, basis=basis)

        self.db.setChecksum(inode, checksum)
        return "OK"

    def processChecksum(self, message):
        pass

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
        encoding = message["encoding"]
        if (encoding == "binary"):
            decoder = lambda x: x
        elif (encoding == "base64"):
            decoder = base64.decodestring

        while (bytesReceived < size):
            chunk = self.messenger.recvMessage()
            bytes = decoder(chunk["data"])
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

        return "OK"


    def processMessage(self, message):
        """ Dispatch a message to the correct handlers """
        messageType = message['message']

        if messageType == "DIR":
            return self.processDir(message)
        elif messageType == "SGR":
            return self.processSignature(message)
        elif messageType == "DEL":
            return self.processDelta(message)
        elif messageType == "CON":
            return self.processContent(message)
        else:
            raise Exception("Unknown message type", messageType)

    def getDB(self, host):
        self.basedir = os.path.join(basedir, host)
        self.cache = CacheDir.CacheDir(self.basedir, 2, 2)
        self.dbname = os.path.join(self.basedir, "tardis.db")
        self.db = TardisDB.TardisDB(self.dbname)


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
            os.rmdir(self.tempdir)
        except OSError as error:
            self.logger.warning("Unable to delete temporary directory: {}: {}".format(self.tempdir, error.strerror))

    def handle(self):
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

            self.request.sendall("OK {}".format(str(self.sessionid)))

            if encoding == "JSON":
                self.messenger = Messages.JsonMessages(self.request)
            else:
                raise Exception("Unknown encoding", encoding)

            done = False;

            while not done:
                message = self.messenger.recvMessage()
                self.logger.debug("Received: " + str(message).encode("utf-8"))
                if message == "BYE":
                    done = True
                else:
                    response = self.processMessage(message)
                    self.logger.debug("Sending : " + str(response))
                    self.messenger.sendMessage(response)

            self.db.completeBackup()
        finally:
            self.request.close()
            self.endSession()

if __name__ == "__main__":
    defaultConfig = './tardis-server.cfg'

    parser = argparse.ArgumentParser(description='Tardis Backup Server')

    parser.add_argument('--config', dest='config', default=defaultConfig, help="Location of the configuration file")
    parser.add_argument('--single', dest='single', action='store_true', help='Run a single transaction and quit')
    parser.add_argument('--version', action='version', version='%(prog)s 0.1', help='Show the version')
    parser.add_argument('--logcfg', '-l', dest='logcfg', default=None, help='Logging configuration file');

    args = parser.parse_args()

    configDefaults = {
        'Port' : '9999',
        'BaseDir' : './cache',
        'LogCfg'  : args.logcfg
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
        logger.setLevel(logging.INFO)


    basedir = config.get('Tardis', 'BaseDir')
    logger.debug("BaseDir: " + basedir)

    try:
        server = SocketServer.TCPServer(("localhost", config.getint('Tardis', 'Port')), TardisServerHandler)
        logger.info("Starting server");
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    except:
        logger.critical("Unable to run server: {}".format(sys.exc_info()[1].strerror))
