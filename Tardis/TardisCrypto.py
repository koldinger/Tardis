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

from Crypto.Cipher import AES, Blowfish
from Crypto.Protocol.KDF import PBKDF2
import Crypto.Random
import socket
import hashlib
import hmac
import os
import os.path
import base64
import struct
import binascii

import Defaults

class TardisCrypto:
    _contentKey  = None
    _filenameKey = None
    _tokenKey    = None
    _keyKey      = None
    _random      = None
    _filenameEnc = None
    _blocksize   = AES.block_size
    _keysize     = AES.key_size[-1]                                              # last (largest) acceptable _keysize
    _altchars    = '#@'

    ivLength    = _blocksize

    def __init__(self, password, client=None):
        self._random = Crypto.Random.new()
        if client == None:
            client = Defaults.getDefault('TARDIS_CLIENT')

        self.client = client
        self.salt = hashlib.sha256(client).digest()
        keys = PBKDF2(password, self.salt, count=20000, dkLen=self._keysize * 2)      # 2x256 bit keys
        self._keyKey     = keys[0:self._keysize]                                      # First 256 bit key
        self._tokenKey   = keys[self._keysize:]                                       # And the other one

    def getContentCipher(self, iv):
        cipher = AES.new(self._contentKey, AES.MODE_CBC, IV=iv)
        return cipher

    def getFilenameCipher(self):
        #cipher = AES.new(self._filenameKey, AES.MODE_ECB)
        return self._filenameEnc

    def getHash(self, func=hashlib.md5):
        return hmac.new(self._contentKey, digestmod=func)

    def getIV(self):
        iv = self._random.read(self.ivLength)
        return iv

    def pad(self, data, length=None):
        if length is None:
            length = len(data)
        pad = self._blocksize - (length % self._blocksize)
        data += chr(pad) * pad
        return data

    def unpad(self, data, validate=True):
        #if validate:
            #self.checkpad(data)
        l = struct.unpack('B', data[-1])[0]            # Grab the last byte
        x = len(data) - l
        return data[:x]

    def checkpad(self, data):
        l = struct.unpack('B', data[-1])[0]            # Grab the last byte
        # Make sure last L bytes are all set to L
        pad = str(l) * l
        if data[-l:] != pad:
            raise Exception("Invalid padding: %s (%d)", binascii.hexlify(data[-l:]), l)

    def padzero(self, x):
        remainder = len(x) % self._blocksize
        if remainder == 0:
            return x
        else:
            return x + (self._blocksize - remainder) * '\0'

    def encryptPath(self, path):
        rooted = False
        comps = path.split(os.sep)
        if comps[0] == '':
            rooted = True
            comps.pop(0)
        enccomps = [self.encryptFilename(x) for x in comps]
        encpath = reduce(os.path.join, enccomps)
        if rooted:
            encpath = os.path.join(os.sep, encpath)
        return encpath

    def decryptPath(self, path):
        rooted = False
        comps = path.split(os.sep)
        if comps[0] == '':
            rooted = True
            comps.pop(0)
        enccomps = [self.decryptFilename(x) for x in comps]
        encpath = reduce(os.path.join, enccomps)
        if rooted:
            encpath = os.path.join(os.sep, encpath)
        return encpath

    def encryptFilename(self, name):
        return base64.b64encode(self._filenameEnc.encrypt(self.padzero(name)), self._altchars)

    def decryptFilename(self, name):
        return self._filenameEnc.decrypt(base64.b64decode(str(name), self._altchars)).rstrip('\0')

    def createToken(self, client=None):
        if client is None:
            client = self.client  
        cipher = AES.new(self._tokenKey, AES.MODE_ECB)
        token = base64.b64encode(cipher.encrypt(self.padzero(client)), self._altchars)
        return token

    def genKeys(self):
        self._contentKey  = self._random.read(self._keysize)
        self._filenameKey = self._random.read(self._keysize)
        self._filenameEnc = AES.new(self._filenameKey, AES.MODE_ECB)

    def setKeys(self, _filenameKey, _contentKey):
        cipher = AES.new(self._keyKey, AES.MODE_ECB)
        self._contentKey  = cipher.decrypt(base64.b64decode(_contentKey))
        self._filenameKey = cipher.decrypt(base64.b64decode(_filenameKey))
        self._filenameEnc = AES.new(self._filenameKey, AES.MODE_ECB)

    def getKeys(self):
        if self._filenameKey and self._contentKey:
            cipher = AES.new(self._keyKey, AES.MODE_ECB)
            _contentKey  = base64.b64encode(cipher.encrypt(self._contentKey))
            _filenameKey = base64.b64encode(cipher.encrypt(self._filenameKey))
            return (_filenameKey, _contentKey)
        else:
            return (None, None)

    def setOldStyleKeys(self):
        self._contentKey  = self._tokenKey
        self._filenameKey = self._keyKey
        self._filenameEnc = AES.new(self._filenameKey, AES.MODE_ECB)

if __name__ == "__main__":
    enc = TardisCrypto("I've got a password, do you?")
    dec = TardisCrypto("I've got a password, do you?")

    print enc.createToken()
    print dec.createToken()

    enc.genKeys()
    (a, b) = enc.getKeys()
    print "Keys: ", a, b
    dec.setKeys(a, b)

    #print base64.b64encode(enc._filenameKey)
    #print base64.b64encode(enc._contentKey)

    iv = enc.getIV()
    cc = enc.getContentCipher(iv)

    fc = enc.getFilenameCipher()

    print "---- Paths"
    a = enc.encryptPath('a/b/c/d/e')
    b = enc.encryptPath('/srv/music/MP3/CD/Classical/Bartók,_Béla_&_Kodaly,_Zoltan/Bartok_-_The_Miraculous_Mandarin_Kodály_-_Háry_Janos_Dances_Of_Galánta/02.Háry_János,_suite_from_the_opera_for_orchestra,_Prelude.mp3')
    c = enc.encryptPath(os.path.join('a' * 16, 'b' * 32, 'c' * 48, 'd' * 64, 'e' * 80, 'f' * 96, 'g' * 112))
    print "1", a
    print "2", b
    print "3", c

    print "1", dec.decryptPath(a)
    print "2", dec.decryptPath(b)
    print "3", dec.decryptPath(c)

    print "---- Names"
    a =  enc.encryptFilename("srv")
    print a
    print dec.decryptFilename(a)

    print "---- More Names"
    b = enc.encryptFilename('02.Háry_János,_suite_from_the_opera_for_orchestra,_Prelude.mp3')
    print b
    print dec.decryptFilename(b)

    print "---- Data"
    pt = "This is a test.  This is only a test.  This is a test of the Emergency Broadcasting System.  Had this been an actual emergency, the attention signal you just heard"
    iv = enc.getIV()
    cipher = enc.getContentCipher(iv)
    ct = cipher.encrypt(enc.pad(pt))

    decipher = dec.getContentCipher(iv)
    dt = decipher.decrypt(ct)
    print dt
