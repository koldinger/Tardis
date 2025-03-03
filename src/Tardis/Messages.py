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

import json
import base64
import struct
import zlib

import msgpack
import snappy

class Messages:
    def __init__(self, socket, stats=None):
        self.socket = socket
        self.stats = stats

    def receiveBytes(self, n):
        chunks = []
        bytes_recd = 0
        while bytes_recd < n:
            chunk = self.socket.recv(min(n - bytes_recd, 2048))
            if chunk == b'':
                raise RuntimeError("socket connection broken")
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)
        msg = b''.join(chunks)
        if self.stats:
            self.stats['bytesRecvd'] += len(msg)
        return msg

    def sendBytes(self, bytes):
        if self.stats:
            self.stats['bytesSent'] += len(bytes)
        self.socket.sendall(bytes)

    def closeSocket(self):
        if self.socket:
            self.socket.close()
            self.socket = None

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
    def __init__(self, socket, stats=None, compress='none'):
        Messages.__init__(self, socket, stats)
        match compress:
            case 'zlib-stream':
                self.compressor = zlibCompressor()
                self.compress = self.compressor.compress
                self.decompress = self.compressor.decompress
            case 'zlib':
                self.compress = zlib.compress
                self.decompress = zlib.decompress
            case 'snappy':
                self.compress = snappy.compress
                self.decompress = snappy.decompress
            case 'none':
                pass
            case _:
                raise Exception(f"Unrecognized compression method: {str(compress)}")

        self.sendstream = None
        self.recvstream = None
        self.sent = 0
        self.received = 0

    def closeSocket(self):
        if self.sendstream:
            self.sendstream.close()
        if self.recvstream:
            self.recvstream.close()
        super().closeSocket()

    def sendMessage(self, message, compress=True):
        if compress and self.compress:
            message = self.compress(message)
        length = len(message)
        if compress and self.compress:
            length |= 0x80000000
        lBytes = struct.pack("!I", length)
        self.sendBytes(lBytes)
        self.sendBytes(message)
        self.sent += 1
        if self.stats:
            self.stats['messagesSent'] += 1
        if self.sendstream:
            self.sendstream.write(lBytes)
            self.sendstream.write(message)

    def recvMessage(self):
        comp = False
        x = self.receiveBytes(4)
        n = struct.unpack("!I", x)[0]
        if (n & 0x80000000) != 0:
            n &= 0x7fffffff
            comp = True
        data = self.receiveBytes(n)
        self.received += 1
        if self.stats:
            self.stats['messagesRecvd'] += 1
        if comp:
            data = self.decompress(bytes(data))
        if self.recvstream:
            self.recvstream.write(x)
            self.recvstream.write(data)
        return data

class TextMessages(Messages):
    def __init__(self, socket, stats=None):
        Messages.__init__(self, socket, stats)

    def sendMessage(self, message, compress=True):
        length = len(message)
        output = f"{length:06d}"
        self.sendBytes(output)
        self.sendBytes(message)
        if self.stats:
            self.stats['messagesSent']

    def recvMessage(self):
        n = self.receiveBytes(6)
        if self.stats:
            self.stats['messagesRecvd']
        return self.receiveBytes(int(n))

class JsonMessages(TextMessages):
    def __init__(self, socket, stats=None, compress=False):
        TextMessages.__init__(self, socket, stats)

    def sendMessage(self, message, compress=False):
        super().sendMessage(json.dumps(message))

    def recvMessage(self):
        message = json.loads(super().recvMessage())

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

    def sendMessage(self, message, compress=True):
        super().sendMessage(msgpack.packb(message), compress=compress)

    def recvMessage(self, wait=False):
        mess = super().recvMessage()
        try:
            message = msgpack.unpackb(mess)
        except Exception as e:
            print(self.received, mess)
            raise e

        return message

    def encode(self, data):
        return data

    def decode(self, data):
        return data

    def getEncoding(self):
        return "bin"

class ObjectMessages():
    def __init__(self, inQueue, outQueue, stats=None, compress=True, timeout=None):
        self.inQueue  = inQueue
        self.outQueue = outQueue
        self.timeout  = timeout

    def sendMessage(self, message, compress=False):
        self.outQueue.put(message)

    def recvMessage(self):
        ret = self.inQueue.get(timeout=self.timeout)
        if isinstance(ret, BaseException):
            raise ret
        return ret

    def encode(self, data):
        return data

    def decode(self, data):
        return data

    def getEncoding(self):
        return "bin"

    def closeSocket(self):
        pass
