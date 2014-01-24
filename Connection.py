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

import socket
import json
import uuid
import sys
import time
import Messages
import ssl

class Connection(object):
    lastTimestamp = None
    """ Root class for handling connections to the tardis server """
    def __init__(self, host, port, name, encoding, priority, use_ssl=False, hostname=None):
        self.stats = { 'messages' : 0, 'bytes': 0 }


        if hostname is None:
            hostname = socket.gethostname()

        # Create and open the socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, int(port)))
        if use_ssl:
            self.sock = ssl.wrap_socket(sock)
        else:
            self.sock = sock

        try:
            # Receive a string.  TARDIS proto=1.0
            message = self.get(10)
            if message != "TARDIS 1.0":
                raise Exception
            message = "BACKUP {} {} {} {} {}".format(hostname, name, encoding, priority, time.time())
            self.put(message)

            message = self.sock.recv(256).strip()
            fields = message.split()
            if len(fields) != 3:
                print message
                raise Exception("Unexpected response: {}".format(message))
            if fields[0] != 'OK':
                raise Exception
            self.sessionid = uuid.UUID(fields[1])
            self.lastTimestamp = float(fields[2])
        except:
            self.sock.close()
            raise

    def put(self, message):
        self.sock.sendall(message)
        self.stats['messages'] += 1
        self.stats['bytes'] += len(message)
        return

    def recv(n):
        msg = ''
        while len(msg) < n:
            chunk = self.sock.recv(n-len(msg))
            if chunk == '':
                raise RuntimeError("socket connection broken")
            msg = msg + chunk
        return msg

    def get(self, size):
        message = self.sock.recv(size).strip()
        self.stats['messages'] += 1
        self.stats['bytes'] += len(message)
        return message

    def close(self):
        self.sock.close()

    def getSessionId(self):
        return str(self.sessionid)

    def getLastTimestap(self):
        return self.lastTimestamp

class ProtocolConnection(Connection):
    sender = None
    def __init__(self, host, port, name, protocol, priority, use_ssl, hostname):
        Connection.__init__(self, host, port, name, protocol, priority, use_ssl, hostname)

    def send(self, message):
        self.sender.sendMessage(message)

    def receive(self):
        return self.sender.recvMessage()

    def close(self):
        self.sender.sendMessage({"message" : "BYE" })
        super(ProtocolConnection, self).close()

    def encode(self, string):
        return self.sender.encode(string)

    def decode(self, string):
        return self.sender.decode(string)

class JsonConnection(ProtocolConnection):
    """ Class to communicate with the Tardis server using a JSON based protocol """
    def __init__(self, host, port, name, priority=0, use_ssl=False, hostname=None):
        ProtocolConnection.__init__(self, host, port, name, 'JSON', priority, use_ssl, hostname)
        # Really, cons this up in the connection, but it needs access to the sock parameter, so.....
        self.sender = Messages.JsonMessages(self.sock)

class BsonConnection(ProtocolConnection):
    def __init__(self, host, port, name, priority=0, use_ssl=False, hostname=None):
        ProtocolConnection.__init__(self, host, port, name, 'BSON', priority, use_ssl, hostname)
        # Really, cons this up in the connection, but it needs access to the sock parameter, so.....
        self.sender = Messages.BsonMessages(self.sock)

class NullConnection(Connection):
    def __init__(self, host, port, name):
        pass

    def send(self, message):
        print json.dumps(message)

    def receive(self):
        return None

if __name__ == "__main__":
    """ Test Code """
    conn = JsonConnection("localhost", 9999, "HiMom")
    print conn.getSessionId()
    conn.send({ 'x' : 1 })
    print conn.receive()
    conn.send({ 'y' : 2 })
    print conn.receive()
    conn.close()
