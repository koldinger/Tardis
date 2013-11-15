#! /usr/bin/python

import argparse
import os
import sys
import ConfigParser
import SocketServer
import uuid
import Messages
import json
import hashlib

class TardisServerHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        print "Got connection"
        h = hashlib.md5()
        i = 1
        try:
            m = Messages.JsonMessages(self.request)

            done = False;

            while not done:
                message = m.recvMessage()
                print "Received: ", message
                h.update(message)
                if message == "BYE":
                    done = True
                else:
                    response = {}
                    response["message"] = message
                    response["id"] = i
                    response["length"] = len(message)
                    response["cksum"] = h.hexdigest()
                    i += 1
                    print "Sending : ", response
                    m.sendMessage(response)
        finally:
            self.request.close()


if __name__ == "__main__":
    server = SocketServer.TCPServer(("localhost", 9999), TardisServerHandler)

    server.serve_forever()
