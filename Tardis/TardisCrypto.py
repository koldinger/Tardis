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

from Crypto.Cipher import AES, Blowfish
from Crypto.Protocol.KDF import PBKDF2
import Crypto.Random
import socket
import hashlib
import os
import os.path
import base64

import Defaults

class TardisCrypto:
    contentKey  = None
    filenameKey = None
    random      = None
    blocksize   = AES.block_size
    keysize     = AES.key_size[-1]                                              # last (largest) acceptable keysize
    altchars    = '#@'

    def __init__(self, password, client=None):
        self.random = Crypto.Random.new()
        if client == None:
            client = Defaults.getDefault('TARDIS_CLIENT')

        self.client = client
        self.salt = hashlib.sha256(client).digest()
        keys = PBKDF2(password, self.salt, count=20000, dkLen=self.keysize * 2)    # 2x256 bit keys
        self.contentKey = keys[0:self.keysize]                                     # First 256 bit key
        self.filenameKey = keys[self.keysize:]                                     # And the other one
        self.filenameEncryptor = AES.new(self.filenameKey, AES.MODE_ECB)

    def getContentCipher(self, iv):
        cipher = AES.new(self.contentKey, AES.MODE_CBC, IV=iv)
        return cipher

    def getFilenameCipher(self):
        cipher = AES.new(self.filenameKey, AES.MODE_ECB)
        return cipher

    def getIV(self, ivLength=16):
        iv = self.random.read(ivLength)
        return iv

    def pad(self, x):
        remainder = len(x) % self.blocksize
        if remainder == 0:
            return x
        else:
            return x + (self.blocksize - remainder) * '\0'

    def encryptPath(self, path):
        rooted = False
        comps = path.split(os.sep)
        encoder = self.getFilenameCipher()
        if comps[0] == '':
            rooted = True
            comps.pop(0)
        enccomps = [base64.b64encode(encoder.encrypt(self.pad(x)), self.altchars) for x in comps]
        encpath = reduce(os.path.join, enccomps)
        if rooted:
            encpath = os.path.join(os.sep, encpath)
        return encpath

    def decryptPath(self, path):
        rooted = False
        comps = path.split(os.sep)
        encoder = self.getFilenameCipher()
        if comps[0] == '':
            rooted = True
            comps.pop(0)
        enccomps = [encoder.decrypt(base64.b64decode(x, self.altchars)).rstrip('\0') for x in comps]
        encpath = reduce(os.path.join, enccomps)
        if rooted:
            encpath = os.path.join(os.sep, encpath)
        return encpath

    def encryptFilename(self, name):
        cipher = self.getFilenameCipher()
        return base64.b64encode(cipher.encrypt(self.pad(name)), self.altchars)

    def decryptFilename(self, name):
        cipher = self.getFilenameCipher()
        return cipher.decrypt(base64.b64decode(name, self.altchars)).rstrip('\0')

    def createToken(self, client=None):
        if client is None:
            client = self.client  
        token = self.encryptFilename(client)
        return token

if __name__ == "__main__":
    tc = TardisCrypto("I've got a password, do you?")
    print base64.b64encode(tc.filenameKey)
    print base64.b64encode(tc.contentKey)

    iv = tc.getIV()
    cc = tc.getContentCipher(iv)

    fc = tc.getFilenameCipher()

    print "---- Paths"
    a = tc.encryptPath('a/b/c/d/e')
    b = tc.encryptPath('/srv/music/MP3/CD/Classical/Bartók,_Béla_&_Kodaly,_Zoltan/Bartok_-_The_Miraculous_Mandarin_Kodály_-_Háry_Janos_Dances_Of_Galánta/02.Háry_János,_suite_from_the_opera_for_orchestra,_Prelude.mp3')
    c = tc.encryptPath(os.path.join('a' * 16, 'b' * 32, 'c' * 48, 'd' * 64, 'e' * 80, 'f' * 96, 'g' * 112))
    print "1", a
    print "2", b
    print "3", c

    print tc.decryptPath(a)
    print tc.decryptPath(b)
    print tc.decryptPath(c)

    print "---- Names ----"
    a =  tc.encryptFilename("srv")
    print a
    print tc.decryptFilename(a)

    print "------------------------------------------"
    b = tc.encryptFilename('02.Háry_János,_suite_from_the_opera_for_orchestra,_Prelude.mp3')
    print b
    print tc.decryptFilename(b)
