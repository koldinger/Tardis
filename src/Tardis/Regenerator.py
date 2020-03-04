# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2020, Eric Koldinger, All Rights Reserved.
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
import binascii
import logging
import tempfile
import shutil
import hashlib
import hmac

import Tardis.CompressedBuffer as CompressedBuffer

import Tardis.librsync as librsync


class RegenerateException(Exception):
    pass

class Regenerator:
    errors = 0

    def __init__(self, cache, db, crypt=None, tempdir="/tmp"):
        self.logger = logging.getLogger("Regenerator")
        self.cacheDir = cache
        self.db = db
        self.tempdir = tempdir
        self.crypt = crypt

    def decryptFile(self, filename, size, authenticate=True):
        self.logger.debug("Decrypting %s", filename)
        if self.crypt is None:
            raise Exception("Encrypted file.  No password specified")
        infile = self.cacheDir.open(filename, 'rb')
        mac = self.crypt.getHash(func=hashlib.sha512)

        # Get the IV, if it's not specified.
        infile.seek(0, os.SEEK_SET)
        iv = infile.read(self.crypt.ivLength)

        self.logger.debug("Got IV: %d %s", len(iv), binascii.hexlify(iv))

        # Create the cipher
        encryptor = self.crypt.getContentEncryptor(iv)

        outfile = tempfile.TemporaryFile()

        contentSize = size - self.crypt.ivLength - encryptor.getDigestSize()
        #self.logger.info("Computed Size: %d.  Specified size: %d.  Diff: %d", ctSize, size, (ctSize - size))

        rem = contentSize
        blocksize = 64 * 1024
        last = False
        while rem > 0:
            readsize = blocksize if rem > blocksize else rem
            if rem <= blocksize:
                last = True
            ct = infile.read(readsize)
            pt = encryptor.decrypt(ct, last)
            if last:
                # ie, we're the last block
                digest = infile.read(encryptor.getDigestSize())
                self.logger.debug("Got HMAC Digest: %d %s", len(digest), binascii.hexlify(digest))
                readsize += len(digest)
                if authenticate:
                    try:
                        encryptor.verify(digest)
                    except:
                        self.logger.debug("HMAC's:  File: %-128s Computed: %-128s", binascii.hexlify(digest), binascii.hexlify(encryptor.digest()))
                        raise RegenerateException("HMAC did not authenticate.")
            outfile.write(pt)
            rem -= readsize

        outfile.seek(0)
        return outfile

    def recoverChecksum(self, cksum, authenticate=True, chain=None, basisFile=None):
        self.logger.debug("Recovering checksum: %s", cksum)
        cksInfo = None
        if not chain:
            chain = self.db.getChecksumInfoChain(cksum)

        if chain:
            cksInfo = chain.pop(0)
            if cksInfo['checksum'] != cksum:
                self.logger.error("Unexpected checksum: %s.  Expected: %s", cksInfo['checksum'], cksum)
                return None
        else:
            cksInfo = self.db.getChecksumInfo(cksum)

        if cksInfo is None:
            self.logger.error("Checksum %s not found", cksum)
            return None

        #self.logger.debug(" %s: %s", cksum, str(cksInfo))

        try:
            if not cksInfo['isfile']:
                raise RegenerateException("{} is not a file".format(cksum))

            if cksInfo['basis']:
                if basisFile:
                    basis = basisFile
                    basis.seek(0)
                else:
                    basis = self.recoverChecksum(cksInfo['basis'], authenticate, chain)

                if cksInfo['encrypted']:
                    patchfile = self.decryptFile(cksum, cksInfo['disksize'], authenticate)
                else:
                    patchfile = self.cacheDir.open(cksum, 'rb')

                if cksInfo['compressed']:
                    self.logger.debug("Uncompressing %s", cksum)
                    temp = tempfile.TemporaryFile()
                    buf = CompressedBuffer.UncompressedBufferedReader(patchfile, compressor=cksInfo['compressed'])
                    shutil.copyfileobj(buf, temp)
                    temp.seek(0)
                    patchfile = temp
                try:
                    output = librsync.patch(basis, patchfile)
                    #output.seek(0)
                    return output
                except librsync.LibrsyncError as e:
                    self.logger.error("Recovering checksum: %s : %s", cksum, e)
                    raise RegenerateException("Checksum: {}: Error: {}".format(cksum, e))
            else:
                if cksInfo['encrypted']:
                    output =  self.decryptFile(cksum, cksInfo['disksize'])
                else:
                    output =  self.cacheDir.open(cksum, "rb")

                if cksInfo['compressed'] is not None and cksInfo['compressed'].lower() != 'none':
                    self.logger.debug("Uncompressing %s", cksum)
                    temp = tempfile.TemporaryFile()
                    buf = CompressedBuffer.UncompressedBufferedReader(output, compressor=cksInfo['compressed'])
                    shutil.copyfileobj(buf, temp)
                    temp.seek(0)
                    output = temp

                return output

        except RegenerateException:
            raise
        except Exception as e:
            self.logger.error("Unable to recover checksum %s: %s", cksum, e)
            #self.logger.exception(e)
            raise RegenerateException("Checksum: {}: Error: {}".format(cksum, e))

    def recoverFile(self, filename, bset=False, nameEncrypted=False, permchecker=None, authenticate=True):
        self.logger.info("Recovering file: %s", filename)
        name = filename
        if self.crypt and not nameEncrypted:
            name = self.crypt.encryptPath(filename)
        try:
            chain = self.db.getChecksumInfoChainByPath(name, bset, permchecker=permchecker)
            if chain:
                cksum = chain[0]['checksum']
                return self.recoverChecksum(cksum, authenticate, chain)
            else:
                self.logger.error("Could not locate file: %s ", name)
                return None
        except RegenerateException as e:
            self.logger.error("Could not regenerate file: %s: %s", filename, str(e))
            #self.logger.exception(e)
            return None
        except Exception as e:
            #logger.exception(e)
            self.logger.error("Error recovering file: %s: %s", filename, str(e))
            self.errors += 1
            return None
            #raise RegenerateException("Error recovering file: {}".format(filename))
