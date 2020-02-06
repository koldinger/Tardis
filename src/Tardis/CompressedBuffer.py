# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2019, Eric Koldinger, All Rights Reserved.
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

import sys
import zlib
import bz2
import lzma
import zstandard as zstd

import Tardis.librsync as librsync

_defaultChunksize = 1024 * 1024

# Dummy class to just pass empty data through
# Looks like a compressor, but doesn't do anything.
class _NullCompressor(object):
    def compress(self, data):
        return data

    def decompress(self, data):
        return data

    def flush(self):
        return None

_zstdCtxC = zstd.ZstdCompressor()
_zstdCtxD = zstd.ZstdDecompressor()

_compressors = { 'zlib': (zlib.compressobj, zlib.decompressobj),
                 'bzip': (bz2.BZ2Compressor, bz2.BZ2Decompressor),
                 'lzma': (lzma.LZMACompressor, lzma.LZMADecompressor),
                 'zstd': (_zstdCtxC.compressobj, _zstdCtxD.decompressobj),
                 'none': (_NullCompressor, _NullCompressor) }

# Pick a selected compressor or decompressor
def _updateAlg(alg):
    if (alg is None) or (alg == 0) or (alg == 'None'):
        alg = 'none'
    if (alg == 1) or (alg == 'True'):
        alg = 'zlib'
    return alg

def getCompressor(alg='zlib'):
    alg = _updateAlg(alg)
    return _compressors[alg][0]()

def getDecompressor(alg='zlib'):
    alg = _updateAlg(alg)
    #print alg
    return _compressors[alg][1]()

def getCompressors():
    return list(_compressors.keys())

class BufferedReader(object):
    def __init__(self, stream, chunksize=_defaultChunksize, hasher=None, signature=False):
        self.stream = stream
        self.chunksize = chunksize
        self.numbytes = 0
        self.buffer = ""
        self.hasher = hasher
        self.sig = librsync.SignatureJob() if signature else None

    def _get(self):
        #print "_get called"
        buf = self.stream.read(self.chunksize)
        #print "back from stream read: {}", buf
        if buf:
            self.numbytes += len(buf)
            if self.hasher:
                self.hasher.update(buf)
        # Always send the buffer, even if it's null at eof.  Will cause the signature job to clean up.
        if self.sig:
            self.sig.step(buf)
        return buf

    def read(self, size=0x7fffffff):
        #avail = 0
        #if self.buffer:
        #    avail = len(self.buffer)
        #print "read called: {}  {} bytes available".format(size, avail)
        out = b''
        left = size
        while len(out) < size:
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
        return self.hasher.hexdigest() if self.hasher else None

    def signatureFile(self):
        return self.sig.sigfile() if self.sig else None

    def size(self):
        return self.numbytes

    def compsize(self):
        return self.size()

    def isCompressed(self):
        return False

class CompressedBufferedReader(BufferedReader):
    def __init__(self, stream, chunksize=_defaultChunksize, hasher=None, threshold=0.80, signature=False, compressor='zlib'):
        super(CompressedBufferedReader, self).__init__(stream, chunksize=chunksize, hasher=hasher, signature=signature)
        self.compressor = None
        self.compressed = 0
        self.uncompressed = 0
        self.first = True
        self.flushed = False
        self.threshold = threshold
        self.compressor = getCompressor(compressor)

    def _get(self):
        #print "_get called"
        ret = b''
        uncomp = b''
        if self.stream:
            while not ret:
                buf = self.stream.read(self.chunksize)
                self.uncompressed += len(buf)
                if self.hasher:
                    self.hasher.update(buf)
                if self.sig:
                    self.sig.step(buf)
                if self.first and buf:
                    uncomp = uncomp + buf
                if self.compressor:
                    if not buf:
                        #print "_get: Done"
                        #ret = self.compressor.flush(zlib.Z_FINISH)
                        ret = ret + self.compressor.flush()
                        self.stream = None
                    else:
                        #print "_get: {} bytes read".format(len(buf))
                        ret = ret + self.compressor.compress(buf)
                else:
                    ret = buf
                    break       # Make sure we don't got around the loop at the EOF
                # end while
            # First time around, create a compressor and check the compression ratio
            if self.first:
                self.first = False
                # Flush the buf and colculate the size
                #ret += self.compressor.flush(zlib.Z_SYNC_FLUSH)
                # Now, check what we've got back.
                if ret:
                    ratio = float(len(ret)) / float(self.uncompressed)
                    #print "Initial ratio: {} {} {}".format(ratio, len(ret), len(buf))
                    if ratio > self.threshold:
                        ret = uncomp
                        self.compressor = None
            self.compressed += len(ret)
            return ret
            # End if self.stream
        return None

    def origsize(self):
        return self.uncompressed

    def compsize(self):
        return self.compressed

    def ratio(self):
        return float(self.compressed) / float(self.uncompressed)

    def size(self):
        return self.origsize()

    def isCompressed(self):
        return self.compressor != None

class UncompressedBufferedReader(BufferedReader):
    def __init__(self, stream, chunksize=_defaultChunksize, compressor='zlib'):
        super(UncompressedBufferedReader, self).__init__(stream, chunksize=chunksize)
        self.compressed = 0.0
        self.uncompressed = 0.0
        self.compressor = getDecompressor(compressor)

    def _get(self):
        #print "_get called"
        ret = None
        while not ret:
            if self.stream:
                buf = self.stream.read(self.chunksize)
                if not buf:
                    #print "_get: Done"
                    try:
                        ret = self.compressor.flush()
                    except AttributeError:
                        ret = ''
                    if ret:
                        self.uncompressed = self.uncompressed + len(ret)
                    self.stream = None
                else:
                    #print "_get: {} bytes read".format(len(buf))
                    ret = self.compressor.decompress(buf)
                    self.compressed = self.uncompressed + len(buf)
                    self.uncompressed = self.compressed + len(ret)
            return ret
        return None

if __name__ == "__main__":
    print("Opening {}".format(sys.argv[1]))
    x = CompressedBufferedReader(file(sys.argv[1], "rb"))
    #line = x.get()
    with file(sys.argv[2], "wb") as f:
        line = x.read(16384)
        while line:
            f.write(line)
            #print "==== ",  len(line), " :: ", base64.b64encode(line)
            #line = x.get()
            line = x.read(16384)

    print(x.origsize(), "  ", x.compsize(), "  ", x.ratio(), " :: ", x.checksum())
