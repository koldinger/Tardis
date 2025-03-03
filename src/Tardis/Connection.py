# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2025, Eric Koldinger, All Rights Reserved.
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
import ssl
import queue

import Tardis
from . import Messages
from . import Messenger

protocolVersion = "1.6"
headerString    = "TARDIS " + protocolVersion
sslHeaderString = headerString + "/SSL"

class ConnectionException(Exception):
    pass

class Connection:
    """ Root class for handling connections to the tardis server """
    def __init__(self, host, port, encoding, compress, timeout, validate):
        self.stats = { 'messagesRecvd': 0, 'messagesSent' : 0, 'bytesRecvd': 0, 'bytesSent': 0 }

        # Create and open the socket
        if host:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if timeout:
                sock.settimeout(timeout)
            sock.connect((host, int(port)))
            self.sock = sock
        else:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            if timeout:
                self.sock.settimeout(timeout)
            self.sock.connect(port)

        try:
            # Receive a string.  TARDIS proto=1.5
            message = str(self.sock.recv(32).strip(), 'utf8')
            if message == sslHeaderString:
                # Overwrite self.sock
                self.sslCtx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                if not validate:
                    self.sslCtx.check_hostname=False
                    self.sslCtx.verify_mode=ssl.CERT_NONE

                self.sock = self.sslCtx.wrap_socket(self.sock, server_side=False, server_hostname=host)
            elif not message:
                raise Exception("No header string.")
            elif message != headerString:
                raise Exception(f"Unknown protocol: {message}")
            resp = { 'encoding': encoding, 'compress': compress }
            self.put(bytes(json.dumps(resp), 'utf8'))

            message = self.sock.recv(256).strip()
            fields = json.loads(message)
            if fields['status'] != 'OK':
                raise ConnectionException("Unable to connect")
        except Exception as e:
            self.sock.close()
            raise e

    def put(self, message):
        self.sock.sendall(message)
        self.stats['messagesSent'] += 1
        return

    def recv(self, n):
        msg = ''
        while len(msg) < n:
            chunk = self.sock.recv(n-len(msg))
            if chunk == '':
                raise RuntimeError("socket connection broken")
            msg = msg + chunk
        return msg

    def get(self, size):
        message = self.sock.recv(size).strip()
        self.stats['messagesRecvd'] += 1
        return message

    def close(self):
        self.sock.close()

    def getStats(self):
        return self.stats

class ProtocolConnection(Connection):
    sender = None

    def send(self, message, compress=True):
        self.sender.sendMessage(message, compress)
        self.stats['messagesSent'] += 1

    def receive(self, wait):
        message = self.sender.recvMessage()
        self.stats['messagesRecvd'] += 1
        return message

    def close(self, error=None):
        message = {"message": "BYE" }
        if error:
            message["error"] = error
        try:
            self.send(message)
        except Exception:
            pass
        super().close()

    def encode(self, string):
        return self.sender.encode(string)

    def decode(self, string):
        return self.sender.decode(string)

class MsgPackConnection(ProtocolConnection):
    def __init__(self, host, port, compress, timeout, validate):
        ProtocolConnection.__init__(self, host, port, 'MSGP', compress, timeout, validate)
        # Really, cons this up in the connection, but it needs access to the sock parameter, so.....
        self.sender = Messages.MsgPackMessages(self.sock, stats=self.stats, compress=compress)

class QueuedMsgPackConnection(MsgPackConnection):
    def __init__(self, host, port, compress, timeout, validate):
        super().__init__(host, port, compress, timeout, validate)
        self.sender = Messenger.Messenger(self.sender)
        self.sender.run()

class DirectConnection:

    def __init__(self, timeout):
        self.timeout = timeout
        self.toClientQueue = queue.SimpleQueue()
        self.toServerQueue = queue.SimpleQueue()
        self.clientMessages = Messages.ObjectMessages(self.toClientQueue, self.toServerQueue, self.stats, timeout)
        self.serverMessages = Messages.ObjectMessages(self.toServerQueue, self.toClientQueue)
        self.sender = self.clientMessages

        self.stats = {
            'messagesRecvd': 0,
            'messagesSent' : 0,
            'bytesRecvd': 0,
            'bytesSent': 0
        }

    def send(self, message, compress=True):
        self.sender.sendMessage(message, compress)
        self.stats['messagesSent'] += 1

    def receive(self):
        message = self.sender.recvMessage()
        self.stats['messagesRecvd'] += 1
        return message

    def close(self, error=None):
        message = {"message": "BYE" }
        if error:
            message["error"] = error
        self.send(message)
        self.send(Exception("Terminate connection"))

    def encode(self, string):
        return self.sender.encode(string)

    def decode(self, string):
        return self.sender.decode(string)

    def getStats(self):
        return self.stats


if __name__ == "__main__":
    """
    Test Code
    conn = JsonConnection("localhost", 9999, "HiMom")
    print(conn.getSessionId())
    conn.send({ 'x' : 1 })
    print(conn.receive())
    conn.send({ 'y' : 2 })
    print(conn.receive())
    conn.close()
    """

    conn = DirectConnection(None)
    server = conn.serverMessages

    conn.send({"a" : 1})
    print(server.recvMessage())
    server.sendMessage({"b": 2, "c": ['a', 'b', 'c']})
    print(conn.receive())
