# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2016, Eric Koldinger, All Rights Reserved.
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
import msgpack
import base64
import struct
import zlib
import snappy

try:
    import bson
    _supportBson = True
except:
    _supportBson = False
    pass


class Messages(object):
    __socket = None

    def __init__(self, socket, stats=None):
        self.__socket = socket
        self.__stats = stats

    def receiveBytes(self, n):
        msg = bytearray()
        while len(msg) < n:
            chunk = self.__socket.recv(n-len(msg))
            if chunk == b'':
                raise RuntimeError("socket connection broken")
            msg.extend(chunk)
        if self.__stats != None:
            self.__stats['bytesRecvd'] += len(msg)
        return msg

    def sendBytes(self, bytes):
        if self.__stats != None:
            self.__stats['bytesSent'] += len(bytes)
        self.__socket.sendall(bytes)

class zlibCompressor:
    def __init__(self):
        self.compressor = zlib.compressobj()
        self.decompressor = zlib.decompressobj()

    def compress(self, message):
        message = self.compressor.compress(message)
        message += self.compressor.flush(zlib.Z_SYNC_FLUSH)
        return message

    def decompress(self, message):
        message = self.decompressor.decompress(message)
        return message

class BinMessages(Messages):
    compress = None
    decompress = None
    def __init__(self, socket, stats=None, compress='none'):
        Messages.__init__(self, socket, stats)
        if compress == 'zlib-stream':
            self.compressor = zlibCompressor()
            self.compress = self.compressor.compress
            self.decompress = self.compressor.decompress
        elif compress == 'zlib':
            self.compress = zlib.compress
            self.decompress = zlib.decompress
        elif compress == 'snappy':
            self.compress = snappy.compress
            self.decompress = snappy.decompress
        elif compress != 'none':
            raise Exception("Unrecognized compression method: %s" % str(compress))

    def sendMessage(self, message, compress=True, raw=False):
        if compress and self.compress:
            message = self.compress(message)
        length = len(message)
        if compress and self.compress:
            length |= 0x80000000
        lBytes = struct.pack("!I", length)
        self.sendBytes(lBytes)
        self.sendBytes(message)

    def recvMessage(self):
        comp = False
        x = self.receiveBytes(4)
        n = struct.unpack("!I", x)[0]
        if (n & 0x80000000) != 0:
            n &= 0x7fffffff
            comp = True
        data = self.receiveBytes(n)
        if comp:
            data = self.decompress(bytes(data))
        return data

class TextMessages(Messages):
    def __init__(self, socket, stats=None):
        Messages.__init__(self, socket, stats)

    def sendMessage(self, message, compress=True):
        length = len(message)
        output = "{:06d}".format(length)
        self.sendBytes(output)
        self.sendBytes(message)

    def recvMessage(self):
        n = self.receiveBytes(6)
        return self.receiveBytes(int(n))

class JsonMessages(TextMessages):
    def __init__(self, socket, stats=None, compress=False):
        TextMessages.__init__(self, socket, stats)
    
    def sendMessage(self, message, compress=False, raw=False):
        if raw:
            super(JsonMessages, self).sendMessage(message)
        else:
            super(JsonMessages, self).sendMessage(json.dumps(message))

    def recvMessage(self, raw=False):
        if raw:
            message = super(JsonMessages, self).recvMessage()
        else:
            message = json.loads(super(JsonMessages, self).recvMessage())
        return message

    def encode(self, data):
        return base64.b64encode(data)

    def decode(self, data):
        return base64.b64decode(data)

    def getEncoding(self):
        return "base64"

class MsgPackMessages(BinMessages):
    def __init__(self, socket, stats=None, compress=True):
        BinMessages.__init__(self, socket, stats, compress=compress)
    
    def sendMessage(self, message, compress=True, raw=False):
        if raw:
            super(MsgPackMessages, self).sendMessage(message, compress=compress, raw=True)
        else:
            super(MsgPackMessages, self).sendMessage(msgpack.packb(message, use_bin_type=True), compress=compress)

    def recvMessage(self, raw=False):
        if raw:
            message = super(MsgPackMessages, self).recvMessage()
        else:
            mess = super(MsgPackMessages, self).recvMessage()
            message = msgpack.unpackb(mess, encoding='utf-8')
        return message

    def encode(self, data):
        return data

    def decode(self, data):
        return data

    def getEncoding(self):
        return "bin"

class BsonMessages(BinMessages):
    def __init__(self, socket, stats=None, compress=True):
        BinMessages.__init__(self, socket, stats, compress=compress)
    
    def sendMessage(self, message, compress=True, raw=False):
        if raw:
            super(BsonMessages, self).sendMessage(message, compress=compress, raw=True)
        else:
            super(BsonMessages, self).sendMessage(bson.dumps(message), compress=compress)

    def recvMessage(self, raw=False):
        if raw:
            message = super(BsonMessages, self).recvMessage()
        else:
            message = bson.loads(super(BsonMessages, self).recvMessage())
        return message

    def encode(self, data):
        return data

    def decode(self, data):
        return data

    def getEncoding(self):
        return "bin"
