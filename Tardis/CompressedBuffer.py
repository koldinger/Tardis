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

import zlib
import base64
import sys
import StringIO
import hashlib
import librsync

_defaultChunksize = 128 * 1024

class BufferedReader(object):
    def __init__(self, stream, chunksize=_defaultChunksize, checksum=False, signature=False):
        self.stream = stream
        self.chunksize = chunksize
        self.numbytes = 0
        self.buffer = ""
        self.md5 = hashlib.md5() if checksum else None
        self.sig = librsync.SignatureJob() if signature else None

    def _get(self):
        #print "_get called"
        buf = self.stream.read(self.chunksize)
        #print "back from stream read: {}", buf
        if buf:
            self.numbytes += len(buf)
            if self.md5:
                self.md5.update(buf)
        if self.sig:
            self.sig.step(buf)
        return buf

    def read(self, size=0x7fffffff):
        #avail = 0
        #if self.buffer:
        #    avail = len(self.buffer)
        #print "read called: {}  {} bytes available".format(size, avail)
        out = ""
        left = size
        while(len(out) < size):
            #print "read loop: so far: {}".format(len(out))
            if (not self.buffer) or (len(self.buffer) == 0):
                #print "Calling _get"
                self.buffer = self._get()
                #print "Back from _get"
                if not self.buffer:
                    #print "_get return None, leaving read: {}".format(len(out))
                    return out
                #print "_get returned {} bytes".format(len(self.buffer))
            amount = min(left, len(self.buffer))
            #print "Adding {} bytes to output".format(amount)
            out = out + self.buffer[:amount]
            self.buffer = self.buffer[amount:]
            left -= amount

        #print "leaving read: {}".format(len(out))
        return out

    def checksum(self):
        return self.md5.hexdigest() if self.md5 else None

    def signatureFile(self):
        return self.sig.sigfile() if self.sig else None

    def size(self):
        return self.numbytes

    def isCompressed(self):
        return False

class CompressedBufferedReader(BufferedReader):
    def __init__(self, stream, chunksize=_defaultChunksize, checksum=False, threshold=0.80, signature=False):
        super(CompressedBufferedReader, self).__init__(stream, chunksize=chunksize, checksum=checksum, signature=signature)
        self.compressor = None
        self.compressed = 0
        self.uncompressed = 0
        self.first = True
        self.threshold = threshold

    def _get(self):
        #print "_get called"
        ret = None
        if self.stream:
            while not ret:
                buffer = self.stream.read(self.chunksize)
                self.uncompressed += len(buffer)
                if self.md5:
                    self.md5.update(buffer)
                if self.sig:
                    self.sig.step(buffer)
                # First time around, create a compressor and check the compression ratio
                if self.first:
                    self.first = False
                    buflen = len(buffer)
                    self.compressor = zlib.compressobj()
                    ret = self.compressor.compress(buffer) 
                    # Flush the buffer and colculate the size
                    ret += self.compressor.flush(zlib.Z_SYNC_FLUSH)
                    # Now, check what we've got back.
                    if ret:
                        ratio = float(len(ret)) / float(len(buffer))
                        #print "Initial ratio: {} {} {}".format(ratio, len(ret), len(buffer))
                        if ratio > self.threshold:
                            ret = buffer
                            self.compressor = None
                elif self.compressor:
                    if not buffer:
                        #print "_get: Done"
                        ret = self.compressor.flush(zlib.Z_FINISH)
                        self.stream = None
                    else:
                        #print "_get: {} bytes read".format(len(buffer))
                        ret = self.compressor.compress(buffer)
                else:
                    ret = buffer
                    break       # Make sure we don't got around the loop at the EOF

            self.compressed += len(ret)
            return ret
        return None

    def origsize(self):
        return self.uncompressed

    def compsize(self):
        return self.compressed

    def ratio(self):
        return (float(self.compressed) / float(self.uncompressed))

    def size(self):
        return self.origsize()
    
    def isCompressed(self):
        return self.compressor != None

class UncompressedBufferedReader(BufferedReader):
    def __init__(self, stream, chunksize=_defaultChunksize):
        super(UncompressedBufferedReader, self).__init__(stream, chunksize=chunksize)
        self.compressor = zlib.decompressobj()
        self.compressed = 0.0
        self.uncompressed = 0.0

    def _get(self):
        #print "_get called"
        ret = None
        while not ret:
            if self.stream:
                buffer = self.stream.read(self.chunksize)
                if not buffer:
                    #print "_get: Done"
                    ret = self.compressor.flush()
                    self.uncompressed = self.uncompressed + len(ret)
                    self.stream = None
                else:
                    #print "_get: {} bytes read".format(len(buffer))
                    ret = self.compressor.decompress(buffer)
                    self.compressed = self.uncompressed + len(buffer)
                    self.uncompressed = self.compressed + len(ret)
            return ret
        return None

if __name__ == "__main__":
    print "Opening {}".format(sys.argv[1])
    x = CompressedBufferedReader(file(sys.argv[1], "rb"), checksum=True)
    #line = x.get()
    with file(sys.argv[2], "wb") as f:
        line = x.read(16384)
        while line:
            f.write(line)
            #print "==== ",  len(line), " :: ", base64.b64encode(line)
            #line = x.get()
            line = x.read(16384)

    print x.origsize(), "  ", x.compsize(), "  ", x.ratio(), " :: ", x.checksum()

"""
    print "Opening {}".format(sys.argv[2])
    y = UncompressedBufferedReader(file(sys.argv[2], "rb"))
    total = 0
    line = y.read(size=80)
    while line:
        #print "==== ",  len(line), ":", total, " :: ", line #base64.b64encode(line)
        #print line
        total += len(line)
        #line = x.get()
        line = y.read(size=80)
"""
