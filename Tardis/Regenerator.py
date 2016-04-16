# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2015, Eric Koldinger, All Rights Reserved.
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

import os
import types

import TardisDB
import TardisCrypto
import CacheDir
import RemoteDB
import Util
import CompressedBuffer
import Defaults

import binascii
import logging
import subprocess
import time
import base64

import librsync
import tempfile
import shutil

import hashlib
import hmac

import Tardis

class RegenerateException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class Regenerator:
    def __init__(self, cache, db, crypt=None, tempdir="/tmp"):
        self.logger = logging.getLogger("Regenerator")
        self.cacheDir = cache
        self.db = db
        self.tempdir = tempdir
        self.crypt = crypt

    def decryptFile(self, filename, size, iv=None, authenticate=True):
        self.logger.debug("Decrypting %s", filename)
        if self.crypt == None:
            raise Exception("Encrypted file.  No password specified")
        infile = self.cacheDir.open(filename, 'rb')
        hmac = self.crypt.getHash(func=hashlib.sha512)

        # Get the IV, if it's not specified.
        infile.seek(0, os.SEEK_SET)
        iv = infile.read(self.crypt.ivLength)

        self.logger.debug("Got IV: %d %s", len(iv), binascii.hexlify(iv))

        if authenticate:
            hmac.update(iv)

        # Create the cypher
        cipher = self.crypt.getContentCipher(iv)

        outfile = tempfile.TemporaryFile()

        ctSize = size - self.crypt.ivLength - hmac.digest_size
        #self.logger.info("Computed Size: %d.  Specified size: %d.  Diff: %d", ctSize, size, (ctSize - size))

        rem = ctSize
        blocksize = 64 * 1024
        while rem > 0:
            readsize = blocksize if rem > blocksize else rem
            ct = infile.read(readsize)
            if authenticate:
                hmac.update(ct)
            pt = cipher.decrypt(ct)
            if rem <= blocksize:
                # ie, we're the last block
                digest = infile.read(hmac.digest_size)
                self.logger.debug("Got HMAC Digest: %d %s", len(digest), binascii.hexlify(digest))
                readsize += len(digest)
                if digest != hmac.digest():
                    self.logger.debug("HMAC's:  File: %-128s Computed: %-128s", binascii.hexlify(digest), hmac.hexdigest())
                    raise RegenerateException("HMAC did not authenticate.")
                pt = self.crypt.unpad(pt)
            outfile.write(pt)
            rem -= readsize


        #outfile.truncate(size)      # Shouldn't be necessary
        outfile.seek(0)
        return outfile

    def recoverChecksum(self, cksum, authenticate=True):
        self.logger.debug("Recovering checksum: %s", cksum)
        cksInfo = self.db.getChecksumInfo(cksum)
        if cksInfo is None:
            self.logger.error("Checksum %s not found", cksum)
            return None

        #self.logger.debug(" %s: %s", cksum, str(cksInfo))

        try:
            if cksInfo['basis']:
                basis = self.recoverChecksum(cksInfo['basis'], authenticate)

                if cksInfo['iv']:
                    patchfile = self.decryptFile(cksum, cksInfo['disksize'], authenticate)
                else:
                    patchfile = self.cacheDir.open(cksum, 'rb')

                if cksInfo['compressed']:
                    self.logger.debug("Uncompressing %s", cksum)
                    temp = tempfile.TemporaryFile()
                    buf = CompressedBuffer.UncompressedBufferedReader(patchfile)
                    shutil.copyfileobj(buf, temp)
                    temp.seek(0)
                    patchfile = temp
                try:
                    output = librsync.patch(basis, patchfile)
                except librsync.LibrsyncError as e:
                    self.logger.error("Recovering checksum: {} : {}".format(cksum, e))
                    raise RegenerateException("Checksum: {}: Error: {}".format(chksum, e))

                #output.seek(0)
                return output
            else:
                if cksInfo['iv']:
                    output =  self.decryptFile(cksum, cksInfo['disksize'])
                else:
                    output =  self.cacheDir.open(cksum, "rb")

                if cksInfo['compressed']:
                    self.logger.debug("Uncompressing %s", cksum)
                    temp = tempfile.TemporaryFile()
                    buf = CompressedBuffer.UncompressedBufferedReader(output)
                    shutil.copyfileobj(buf, temp)
                    temp.seek(0)
                    output = temp

                return output

        except Exception as e:
            self.logger.error("Unable to recover checksum %s: %s", cksum, e)
            # self.logger.exception(e)
            raise RegenerateException("Checksum: {}: Error: {}".format(cksum, e))

    def recoverFile(self, filename, bset=False, nameEncrypted=False, permchecker=None, authenticate=True):
        global errors
        self.logger.info("Recovering file: {}".format(filename))
        name = filename
        if self.crypt and not nameEncrypted:
            name = self.crypt.encryptPath(filename)
        try:
            cksum = self.db.getChecksumByPath(name, bset, permchecker=permchecker)
            if cksum:
                return self.recoverChecksum(cksum, authenticate)
            else:
                self.logger.error("Could not locate file: %s ", filename)
                return None
        except RegenerateException as e:
            self.logger.error("Could not regenerate file: %s: %s", filename, str(e))
            return None
        except Exception as e:
            #logger.exception(e)
            self.logger.error("Error recovering file: %s: %s", filename, str(e))
            errors += 1
            return None
            #raise RegenerateException("Error recovering file: {}".format(filename))

