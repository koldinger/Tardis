import socket
import os
import sys
import json
import bson
import base64
import struct

class Messages(object):
    __socket = None

    def __init__(self, socket):
        self.__socket = socket

    def receiveBytes(self, n):
        msg = ''
        while len(msg) < n:
            chunk = self.__socket.recv(n-len(msg))
            if chunk == '':
                raise RuntimeError("socket connection broken")
            msg = msg + chunk
        return msg

    def sendBytes(self, bytes):
        self.__socket.sendall(bytes)

class BinMessages(Messages):
    def __init__(self, socket):
        Messages.__init__(self, socket)

    def sendMessage(self, message):
        length = struct.pack("!i", len(message))
        self.sendBytes(length)
        self.sendBytes(message)

    def recvMessage(self):
        x = self.receiveBytes(4)
        n = struct.unpack("!i", x)[0]
        return self.receiveBytes(n)

class TextMessages(Messages):
    def __init__(self, socket):
        Messages.__init__(self, socket)

    def sendMessage(self, message):
        length = len(message)
        output = "{:06d}".format(length)
        self.sendBytes(output)
        self.sendBytes(message)

    def recvMessage(self):
        n = self.receiveBytes(6)
        return self.receiveBytes(int(n))

class JsonMessages(TextMessages):
    def __init__(self, socket):
        TextMessages.__init__(self, socket)
    
    def sendMessage(self, message):
        super(JsonMessages, self).sendMessage(json.dumps(message))

    def recvMessage(self):
        return json.loads(super(JsonMessages, self).recvMessage())

    def encode(self, data):
        return base64.b64encode(data)

    def decode(self, data):
        return base64.b64decode(data)

class BsonMessages(BinMessages):
    def __init__(self, socket):
        BinMessages.__init__(self, socket)
    
    def sendMessage(self, message):
        super(BsonMessages, self).sendMessage(bson.dumps(message))

    def recvMessage(self):
        return bson.loads(super(BsonMessages, self).recvMessage())

    def encode(self, data):
        return data

    def decode(self, data):
        return data
