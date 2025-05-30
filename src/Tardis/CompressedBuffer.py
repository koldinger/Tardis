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

import bz2
import lzma
import sys
import zlib

import lz4.frame
import zstandard as zstd

from . import librsync

_defaultChunksize = 1024 * 1024

# Dummy class to just pass empty data through
# Looks like a compressor, but doesn't do anything.
class _NullCompressor:
    def compress(self, data):
        return data

    def decompress(self, data):
        return data

    def flush(self):
        return None

_zstdCtxC = zstd.ZstdCompressor(level=5)
_zstdCtxD = zstd.ZstdDecompressor()

class Lz4Compressor:
    def __init__(self):
        self.compressor = lz4.frame.LZ4FrameCompressor()
        self.first = True

    def compress(self, buffer):
        if self.first:
            self.first = False
            return self.compressor.begin() + self.compressor.compress(buffer)
        else:
            return self.compressor.compress(buffer)

    def flush(self):
        return self.compressor.flush()

_compressors = {
                 'zstd': (_zstdCtxC.compressobj, _zstdCtxD.decompressobj, {}),
                 'zlib': (zlib.compressobj, zlib.decompressobj, {}),
                 'bzip': (bz2.BZ2Compressor, bz2.BZ2Decompressor, {}),
                 'lzma': (lzma.LZMACompressor, lzma.LZMADecompressor, {}),
                 'lz4' : (Lz4Compressor, lz4.frame.LZ4FrameDecompressor, {}),
                 'none': (_NullCompressor, _NullCompressor, {})
               }

# Pick a selected compressor or decompressor
def _updateAlg(alg):
    if alg in [None, 0, 'None', False]:
        alg = 'none'
    if alg in [1, 'True', True]:
        alg = 'zlib'
    return alg

def getCompressor(alg='zlib'):
    alg = _updateAlg(alg)
    return _compressors[alg][0](**(_compressors[alg][2]))

def getDecompressor(alg='zlib'):
    alg = _updateAlg(alg)
    return _compressors[alg][1]()

def getCompressors():
    return list(_compressors.keys())

class BufferedReader:
    def __init__(self, stream, chunksize=_defaultChunksize, hasher=None, signature=False):
        self.stream = stream
        self.chunksize = chunksize
        self.numbytes = 0
        self.position = 0
        self.buffer = ""
        self.hasher = hasher
        self.sig = librsync.SignatureJob() if signature else None

    def _get(self):
        buf = self.stream.read(self.chunksize)
        if buf:
            self.numbytes += len(buf)
            if self.hasher:
                self.hasher.update(buf)
        # Always send the buffer, even if it's null at eof.  Will cause the signature job to clean up.
        if self.sig:
            self.sig.step(buf)
        return buf

    def read(self, size=0x7fffffffffffffff):
        out = b''
        left = size
        while len(out) < size:
            if (not self.buffer) or (len(self.buffer) == 0):
                self.buffer = self._get()
                if not self.buffer:
                    return out
            amount = min(left, len(self.buffer))
            out = out + self.buffer[:amount]
            self.buffer = self.buffer[amount:]
            left -= amount

        self.position += len(out)
        return out

    def tell(self):
        return self.position

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
        super().__init__(stream, chunksize=chunksize, hasher=hasher, signature=signature)
        self.compressed = 0
        self.uncompressed = 0
        self.first = True
        self.threshold = threshold
        self.compressor = getCompressor(compressor)

    def _get(self):
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
                        ret = ret + self.compressor.flush()
                        self.stream = None
                    else:
                        ret = ret + self.compressor.compress(buf)
                else:
                    ret = buf
                    break       # Make sure we don't got around the loop at the EOF
            # First time around, create a compressor and check the compression ratio
            if self.first:
                self.first = False
                # Flush the buf and colculate the size
                # Now, check what we've got back.
                if ret:
                    ratio = float(len(ret)) / float(self.uncompressed)
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
        return self.compressor is not None

class UncompressedBufferedReader(BufferedReader):
    def __init__(self, stream, chunksize=_defaultChunksize, compressor='zlib'):
        super().__init__(stream, chunksize=chunksize)
        self.compressed = 0.0
        self.uncompressed = 0.0
        self.compressor = getDecompressor(compressor)

    def _get(self):
        ret = None
        while not ret:
            if self.stream:
                buf = self.stream.read(self.chunksize)
                if not buf:
                    try:
                        ret = self.compressor.flush()
                    except AttributeError:
                        ret = ''
                    if ret:
                        self.uncompressed = self.uncompressed + len(ret)
                    self.stream = None
                else:
                    ret = self.compressor.decompress(buf)
                    self.compressed = self.uncompressed + len(buf)
                    self.uncompressed = self.compressed + len(ret)
            return ret
        return None

if __name__ == "__main__":
    import time

    from . import Util
    print(f"Opening {sys.argv[1]}")
    readsize = 4 * 1024 * 1024
    for c in getCompressors():
        print(f"{c} => ", end='', flush=True)
        start = time.time()
        x = CompressedBufferedReader(open(sys.argv[1], "rb"), compressor=c)
        try:
            line = x.read(readsize)
            while line:
                line = x.read(readsize)
            end = time.time()
            duration = end - start
            print(f"{x.origsize()} ({Util.fmtSize(x.origsize())})  -- {x.compsize()} ({Util.fmtSize(x.compsize())})  -- {x.ratio():.2%} {duration:3.3f}  {(x.origsize() / (1024 * 1024) / duration):2.2f} MB/s :: {x.checksum()}")
        except Exception as e:
            print(f"Caught exception: {str(e)}")
