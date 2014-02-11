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

class TardisCrypto:
    contentKey  = None
    filenameKey = None
    random      = None
    blocksize   = 16

    def __init__(self, password, hostname=None):
        self.random = Crypto.Random.new()
        if hostname == None:
            hostname = socket.gethostname()
        self.salt = hashlib.sha256(hostname).digest()
        self.contentKey = PBKDF2(password, self.salt)
        password2 = password #munge(password)
        self.filenameKey = PBKDF2(password2, self.salt)

    def getContentCipher(self, iv):
        cipher = AES.new(self.contentKey, AES.MODE_CBC, IV=iv)
        return cipher

    def getFilenameCipher(self):
        cipher = AES.new(self.filenameKey, AES.MODE_ECB)
        return cypher

    def getIV(self, ivLength=16):
        iv = self.random.read(ivLength)
        return iv

    def pad(self, x):
        remainder = len(x) % self.blocksize
        if remainder == 0:
            return x
        else:
            return x + (self.blocksize - remainder) * '\0'


if __name__ == "__main__":
    tc = TardisCrypto("password")
    print tc.filenameKey
    print tc.contentKey

    iv = tc.getIV()
    cc = tc.getContentCipher(iv)

    fc = tc.getFilenameCipher()

"""
#!/usr/bin/env python
from Crypto.Cipher import AES, Blowfish
import Crypto.Random
from Crypto.Protocol.KDF import PBKDF2
import base64
import os
import hashlib
import socket

# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = 32

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '\0'

# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
#EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
#DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
EncodeAES = lambda c, s: c.encrypt(pad(s))
DecodeAES = lambda c, e: c.decrypt(e).rstrip(PADDING)

#secrett =  generate a random secret key
#secret = os.urandom(BLOCK_SIZE)
password = 'Im henry the 8th I am'
salt = hashlib.sha256(socket.gethostname()).digest()
secret = PBKDF2(password, salt)

r = Crypto.Random.new()
iv = r.read(8)
print "--------------------------------------"
print "IV: ", str.lower(base64.b16encode(iv))
print "Key:", str.lower(base64.b16encode(secret))
print "--------------------------------------"

# create a cipher object using the random secret
#cipher = AES.new(secret, AES.MODE_CBC, IV=iv)
#cipher2 = AES.new(secret, AES.MODE_CBC, IV=iv)
cipher = AES.new(secret, AES.MODE_CBC, IV=iv)
cipher2 = AES.new(secret, AES.MODE_CBC, IV=iv)
#cipher = AES.new(secret, AES.MODE_ECB, IV=iv)

# encode a string
encoded = EncodeAES(cipher, 'password')
print 'Encrypted string:', base64.b64encode(encoded)

#encoded = EncodeAES(cipher, 'password')
#print 'Encrypted string:', base64.b64encode(encoded)

# decode the encoded string
decoded = DecodeAES(cipher2, encoded)
print 'Decrypted string:', decoded, base64.b64encode(decoded)
"""
