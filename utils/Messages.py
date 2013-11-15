import socket
import os
import sys
import json

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
