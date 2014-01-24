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
import sys
import argparse
import uuid
import logging
import logging.config
import ConfigParser
import SocketServer
import ssl
import tempfile
import hashlib
import base64
import subprocess
import daemon
import daemon.pidfile
import pprint

# For profiling
import cProfile
import StringIO
import pstats

import Messages
import CacheDir
import TardisDB
import Regenerate

sessions = {}

DONE    = 0
CONTENT = 1
CKSUM   = 2
DELTA   = 3

config = None
profiler = None

databaseName = 'tardis.db'
schemaName   = 'tardis.sql'
configName   = '/etc/tardis/tardisd.cfg'

pp = pprint.PrettyPrinter(indent=2, width=200)

logging.TRACE = logging.DEBUG - 1

class TardisServerHandler(SocketServer.BaseRequestHandler):
    numfiles = 0
    logger = logging.getLogger('Tardis')
    sessionid = None
    tempdir = None
    cache   = None
    db      = None

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
                        self.db.setChecksum(inode, old['checksum'])
                        retVal = DONE
                    else:
                        retVal = CONTENT
                elif f["size"] < 4096 or old["size"] is None:
                    # Just ask for content if the size is under 4K, or the old filesize is marked as 0.
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

            # TODO: Break the signature out of here.
            response = {
                "message": "SIG",
                "inode": inode,
                "status": "OK",
                "encoding": self.messenger.getEncoding(),
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
            if self.server.savefull:
                # Save the full output, rather than just a delta.  Save the delta to a file
                output = tempfile.NamedTemporaryFile(dir=self.tempdir, delete=True)
            else:
                output = self.cache.open(checksum, "wb")

        bytesReceived = 0
        size = message["size"]

        while True:
            chunk = self.messenger.recvMessage()
            if chunk['chunk'] == 'done':
                break
            bytes = self.messenger.decode(chunk["data"])
            if output:
                output.write(bytes)
            bytesReceived += len(bytes)
        if output:
            output.flush()
            if self.server.savefull:
                # Process the delta file into the new file.
                subprocess.call(["rdiff", "patch", self.cache.path(basis), output.name], stdout=self.cache.open(checksum, "wb"))
                self.db.insertChecksumFile(checksum, size)
            else:
                self.db.insertChecksumFile(checksum, size, basis=basis)
            output.close()
            # TODO: This has gotta be wrong.
        self.db.setChecksum(inode, checksum)

        return None

    def processSignature(self, message):
        """ Receive a signature message. """
        self.logger.debug("Processing signature message: {}".format(str(message)))
        output = None
        temp = None
        checksum = message["checksum"]
        basis    = message["basis"]
        inode    = message["inode"]

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
            #digest = hashlib.md5()

        bytesReceived = 0
        size = message["size"]

        while True:
            chunk = self.messenger.recvMessage()
            if chunk['chunk'] == 'done':
                checksum = chunk['checksum']
                break

            bytes = self.messenger.decode(chunk["data"])
            output.write(bytes)
            bytesReceived += len(bytes)
        output.close()

        if temp:
            if self.cache.exists(checksum):
                self.logger.debug("Checksum file {} already exists".format(checksum))
                os.remove(temp.name)
            else:
                self.cache.mkdir(checksum)
                self.logger.debug("Renaming {} to {}".format(temp.name, self.cache.path(checksum)))
                os.rename(temp.name, self.cache.path(checksum))
                self.db.insertChecksumFile(checksum, bytesReceived)
        self.db.setChecksum(message["inode"], checksum)

        #return {"message" : "OK", "inode": message["inode"]}
        return None

    def processPurge(self, message):
        self.logger.debug("Processing purge message: {}".format(str(message)))
        if message['relative']:
            prevTime = float(self.db.prevBackupDate) - float(message['time'])
        else:
            prevTime = float(message['time'])

        # Purge the files
        (files, sets) = self.db.purgeFiles(message['priority'], prevTime)
        self.logger.info("Purged {} files in {} backup sets".format(files, sets))
        return {"message" : "PURGEOK"}

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
                self.logger.debug("No match on clone.  Inode: {} Rows: {} {} Checksums: {} {}".format(inode, numfiles, d['numfiles'], checksum, d['cksum']))
                content.append(d['inode'])
            else:
                rows = self.db.cloneDir(d['inode'])
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
            script = schemaName
        self.db = TardisDB.TardisDB(self.dbname, initialize=script)
        self.regenerator = Regenerate.Regenerator(self.cache, self.db)

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
                # Clean out the temp dir
                for f in os.listdir(self.tempdir):
                    os.remove(os.path.join(self.tempdir, f))
                # And delete it
                os.rmdir(self.tempdir)
        except OSError as error:
            self.logger.warning("Unable to delete temporary directory: {}: {}".format(self.tempdir, error.strerror))

    def removeOrphans(self):
        # Now remove any leftover orphans
        if self.db:
            # Get a list of orphan'd files
            orphans = self.db.listOrphanChecksums()
            self.logger.debug("Attempting to remove")
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
                    self.logger.warning("No checksum file for checksum {}".format(c))
                except:
                    e = sys.exc_info()[0]
                    self.logger.exception(e)
                self.db.deleteChecksum(c)
            self.logger.info("Removed {} orphans, {} bytes".format(count, size))


    def handle(self):
        if profiler:
            profiler.enable()

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
                message = self.messenger.recvMessage()
                self.logger.log(logging.TRACE, "Received:\n" + str(pp.pformat(message)).encode("utf-8"))
                if message["message"] == "BYE":
                    done = True
                else:
                    response = self.processMessage(message)
                    if response:
                        self.logger.log(logging.TRACE, "Sending:\n" + str(pp.pformat(response)))
                        self.messenger.sendMessage(response)

            self.db.completeBackup()
        except:
            e = sys.exc_info()[0]
            self.logger.error("Caught exception: {}".format(e))
            self.logger.exception(e)
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

        def finish(self):
            self.logger.info("Removing orphans")
            self.removeOrphans()

class TardisSocketServer(SocketServer.ForkingMixIn, SocketServer.TCPServer):
    config = None

    def __init__(self, config):
        self.config = config
        SocketServer.TCPServer.__init__(self, ("", config.getint('Tardis', 'Port')), TardisServerHandler)

        self.basedir    = config.get('Tardis', 'BaseDir')
        self.savefull   = config.getboolean('Tardis', 'SaveFull')
        self.ssl        = config.getboolean('Tardis', 'SSL')
        if self.ssl:
            certfile   = config.get('Tardis', 'CertFile')
            keyfile    = config.get('Tardis', 'KeyFile')
            self.socket = ssl.wrap_socket(self.socket, server_side=True, certfile=certfile, keyfile=keyfile, ssl_version=ssl.PROTOCOL_TLSv1)



def setupLogging(config):
    levels = [logging.WARNING, logging.INFO, logging.DEBUG, logging.TRACE]

    logging.addLevelName(logging.TRACE, 'Message')

    if config.get('Tardis', 'LogCfg'):
        logging.config.fileConfig(config.get('Tardis', 'LogCfg'))
        logger = logging.getLogger('')
    else:
        logger = logging.getLogger('')
        #format = logging.Formatter("%(asctime) %(levelname)s : %(name)s : %(message)s")
        format = logging.Formatter("%(asctime)s %(levelname)s : %(message)s")

        verbosity = config.getint('Tardis', 'Verbose')

        if config.get('Tardis', 'LogFile'):
            handler = logging.FileHandler(config.get('Tardis', 'LogFile'))
        elif config.getboolean('Tardis', 'Daemon'):
            handler = logging.SysLogHandler()
        else:
            handler = logging.StreamHandler()

        handler.setFormatter(format)
        logger.addHandler(handler)

        loglevel = levels[verbosity] if verbosity < len(levels) else logging.DEBUG
        logger.setLevel(loglevel)

    return logger

def run_server(config):
    try:
        logger = setupLogging(config)

        logger.info("Starting server");
        #server = SocketServer.TCPServer(("", config.getint('Tardis', 'Port')), TardisServerHandler)
        server = TardisSocketServer(config)

        if (config.getboolean('Tardis', 'Single')):
            server.handle_request()
        else:
            server.serve_forever()
        logger.info("Ending")
    except:
        logger.critical("Unable to run server: {}".format(sys.exc_info()[1]))
        #logger.exception(sys.exc_info()[1])


def main():

    parser = argparse.ArgumentParser(description='Tardis Backup Server')

    parser.add_argument('--config',         dest='config', default=configName, help="Location of the configuration file")
    parser.add_argument('--single',         dest='single', action='store_true', help='Run a single transaction and quit')
    parser.add_argument('--daemon', '-D',   action='store_true', dest='daemon', default=False, help='Run as a daemon')
    parser.add_argument('--logfile', '-l',  dest='logfile', default=None, help='Log to file')
    parser.add_argument('--version',        action='version', version='%(prog)s 0.1', help='Show the version')
    parser.add_argument('--logcfg', '-L',   dest='logcfg', default=None, help='Logging configuration file');
    parser.add_argument('--verbose', '-v',  action='count', default=0, dest='verbose', help='Increase the verbosity')
    parser.add_argument('--profile',        dest='profile', default=None, help='Generate a profile')

    sslgroup = parser.add_mutually_exclusive_group()
    sslgroup.add_argument('--ssl', '-s',    dest='ssl', action='store_true', default=False, help='Use SSL connections')
    sslgroup.add_argument('--nossl',        dest='ssl', action='store_false', help='Do not use SSL connections')

    parser.add_argument('--certfile', '-c', dest='certfile', default=None, help='Path to certificate file for SSL connections')
    parser.add_argument('--keyfile', '-k',  dest='keyfile',  default=None, help='Path to key file for SSL connections')

    args = parser.parse_args()

    configDefaults = {
        'Port'      : '9999',
        'BaseDir'   : './cache',
        'SaveFull'  : str(True),
        'LogCfg'    : args.logcfg,
        'Profile'   : args.profile,
        'LogFile'   : args.logfile,
        'Single'    : str(args.single),
        'Verbose'   : str(args.verbose),
        'Daemon'    : str(args.daemon),
        'SSL'       : str(args.ssl),
        'CertFile'  : args.certfile,
        'KeyFile'   : args.keyfile
    }

    config = ConfigParser.ConfigParser(configDefaults)
    config.read(args.config)

    if config.get('Tardis', 'Profile'):
        profiler = cProfile.Profile()
    try:
        if config.getboolean('Tardis', 'Daemon'):
            pidfile = daemon.pidfile.TimeoutPIDLockFile("/var/run/testdaemon/tardis.pid")
            with daemon.DaemonContext(pidfile=pidfile, working_directory='.'):
                run_server(config)
        else:
            run_server(config)
    except KeyboardInterrupt:
        pass
    except:
        print "Unable to run server: {}".format(sys.exc_info()[1])
        #logger.exception(sys.exc_info()[1])

if __name__ == "__main__":
    sys.exit(main())
