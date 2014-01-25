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

    def getEncoding(self):
        return "base64"

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

    def getEncoding(self):
        return "bin"
