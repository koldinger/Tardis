#! /usr/bin/python

import os
import sys
import argparse
import ConfigParser
import SocketServer
import uuid
import json

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

    def checkFile(self, parent, file):
        """ Process an individual file.  Check to see if it's different from what's there already """
        # Get the last backup information
        fileInfo = self.db.getFileInfoByName(file["name"], parent)
        # Insert the current file info
        self.db.insertFile(file, parent)
        if fileInfo != None:
            if (fileInfo["inode"] == file["inode"]) and (fileinfo["size"] == file["size"]) and (fileinfo["mtime"] == file["mtime"]):
                self.db.copyChecksum(parent, file)
                retVal = DONE
            else:
                retVal = DELTA
        else:
            # TODO: Lookup based on inode.
            retVal = CONTENT
            
        return retVal

    def processDir(self, data):
        """ Process a directory message.  Lookup each file in the previous backup set, and determine if it's changed. """
        print "Processing directory entry: {} : {}".format(data["path"], str(data["inode"]))
        done = []
        cksum = []
        content = []
        delta = []

        for file in data['files']:
            print "Processing file: {} {}".format(file["name"], str(file["inode"]))
            res = self.checkFile(data["path"], file)
            inode = data["inode"]
            if res == 0:
                done.append(inode)
            elif res == 1:
                content.append(inode)
            elif res == 2:
                cksum.append(inode)
            elif res == 3:
                delta.append(inode)

        self.db.commit()

        response = {}
        response["message"] = "ACKDIR"
        response["inode"] = data["inode"]
        response["status"] = "OK"

        response["done"] = done
        response["cksum"] = cksum
        response["content"] = content
        response["delta"] = delta

        return response

    def processMessage(self, message):
        """ Dispatch a message to the correct handlers """
        messageType = message['message']

        if messageType == "DIR":
            return self.processDir(message)
        elif messageType == "CKS":
            return "Not Yet Implemented"
        elif messageType == "DEL":
            return "Not Yet Implemented"
        elif messageType == "CON":
            return "Not Yet Implemented"
        else:
            raise Exception("Unknown message type", messageType)

    def getDB(self, host):
        self.basedir = os.path.join(basedir, host)
        self.cache = CacheDir.CacheDir(self.basedir, 2, 2)
        self.dbname = os.path.join(basedir, "tardis.db")
        self.db = TardisDB.TardisDB(self.dbname)

    def startSession(self, name):
        self.sessionid = uuid.uuid1()
        self.name = name
        sid = str(self.sessionid)
        sessions[sid] = self

    def endSession(self):
        if str(self.sessionid):
            try:
                del sessions[str(self.sessionid)]
            except KeyError:
                pass

    def handle(self):
        try:
            self.request.sendall("TARDIS 1.0")
            message = self.request.recv(256).strip()
            print message
            fields = message.split()
            if (len(fields) != 4 or fields[0] != 'BACKUP'):
                self.request.sendall("FAIL")
                raise Exception("Unrecognized command", message)
            host     = fields[1]
            name     = fields[2]
            encoding = fields[3]

            self.db = self.getDB(host)
            self.startSession(name)

            self.request.sendall("OK {}".format(str(self.sessionid)))

            if encoding == "JSON":
                self.messenger = Messages.JsonMessages(self.request)
            else:
                raise Exception("Unknown encoding", encoding)

            done = False;

            while not done:
                message = self.messenger.recvMessage()
                print "Received: ", message
                if message == "BYE":
                    done = True
                else:
                    response = self.processMessage(message)
                    print "Sending : ", response
                    self.messenger.sendMessage(response)
        finally:
            pass
            #self.request.close()
            #self.endSession()

if __name__ == "__main__":
    defaultConfig = './tardis-server.cfg'

    parser = argparse.ArgumentParser(description='Tardis Backup Server')

    parser.add_argument('--config', dest='config', default=defaultConfig, help="Location of the configuration file")
    parser.add_argument('--single', dest='single', action='store_true', help='Run a single transaction and quit')
    parser.add_argument('--verbose', '-v', action='count', dest='verbose', help='Increase the verbosity')
    parser.add_argument('--version', action='version', version='%(prog)s 0.1', help='Show the version')

    args = parser.parse_args()
    print args

    configDefaults = {
        'Port' : '9999',
        'BaseDir' : './cache',
        'Verbose' : str(args.verbose)
    }

    config = ConfigParser.ConfigParser(configDefaults)
    config.read(args.config)

    print config.get('DEFAULT', 'Port')
    print config.get('DEFAULT', 'BaseDir')
    print config.get('DEFAULT', 'Verbose')

    basedir = config.get('DEFAULT', 'BaseDir')

    server = SocketServer.TCPServer(("localhost", config.getint('DEFAULT', 'Port')), TardisServerHandler)

    server.serve_forever()
