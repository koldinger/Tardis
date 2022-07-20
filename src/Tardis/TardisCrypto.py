# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2022, Eric Koldinger, All Rights Reserved.
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

import hashlib
import hmac
import os
import os.path
import sys
import base64
import binascii

from Cryptodome.Cipher import AES, ChaCha20_Poly1305
from Cryptodome.Protocol.KDF import PBKDF2, scrypt
from Cryptodome.Util.Padding import pad, unpad
import Cryptodome.Random
import srp

import Tardis.Defaults as Defaults
from functools import reduce

defaultCryptoScheme = 4
maxCryptoScheme = 4
noCryptoScheme = 0

def getCrypto(scheme, password, client=None, fsencoding=sys.getfilesystemencoding()):
    scheme = int(scheme)

    if scheme == 0:
        return Crypto_Null(password, client, fsencoding)
    elif scheme == 1:
        return Crypto_AES_CBC_HMAC__AES_ECB(password, client, fsencoding)
    elif scheme == 2:
        return Crypto_AES_CBC_HMAC__AES_SIV(password, client, fsencoding)
    elif scheme == 3:
        return Crypto_AES_GCM__AES_SIV(password, client, fsencoding)
    elif scheme == 4:
        return Crypto_ChaCha20_Poly1305__AES_SIV(password, client, fsencoding)
    else:
        raise Exception(f"Unknown Crypto Scheme: {scheme}")


def getCryptoNames(scheme=None):
    if scheme is None:
        x = range(0, 5)
    else:
        x = range(scheme, scheme + 1)

    names = []
    for i in x:
        crypto = getCrypto(i, 'password')
        names.append(f"{i}: {crypto._cryptoName}")
    return '\n'.join(names)


class HasherMixin:
    hasher = None

    def __init__(self, cipher, hasher):
        self.hasher = hasher
        super().__init__(cipher)

    def update(self, data):
        self.hasher.update(data)

    def encrypt(self, data):
        ct = super().encrypt(data)
        if ct:
            self.hasher.update(ct)
        return ct

    def finish(self):
        ct = super().finish()
        self.hasher.update(ct)
        return ct

    def decrypt(self, ct, last=False):
        self.hasher.update(ct)
        plain = super().decrypt(ct, last)
        return plain

    def digest(self):
        return self.hasher.digest()

    def verify(self, tag):
        if not hmac.compare_digest(tag, self.hasher.digest()):
            raise ValueError("MAC did not match")

    def getDigestSize(self):
        return self.hasher.digest_size

class BlockEncryptor:
    done = False
    prev = None
    iv = None

    def __init__(self, cipher):
        self.cipher = cipher
        self.iv = cipher.iv
        self.update(self.iv)

    def update(self, data):
        self.cipher.update(data)

    def encrypt(self, data):
        if self.done:
            raise Exception("Already completed")
        if self.prev:
            data = self.prev + data
            self.prev = None
        remainder = len(data) % self.cipher.block_size
        if remainder != 0:
            self.prev = data[-remainder:]
            data = data[0:-remainder]
        if data:
            ret = self.cipher.encrypt(data)
            if ret:
                return ret
            else:
                return b''
        else:
            return b''

    def decrypt(self, data, last=False):
        if self.done:
            raise Exception("Already completed")
        if self.prev:
            data = self.prev + data
            self.prev = None
        remainder = len(data) % self.cipher.block_size
        if remainder != 0:
            self.prev = data[-remainder:]
            data = data[0:-remainder]
        if data:
            output = self.cipher.decrypt(data)
            if last:
                self.done = True
                output = unpad(output, self.cipher.block_size)
            return output
        else:
            return b''

    def finish(self):
        if self.done:
            raise Exception("Already completed")
        self.done = True
        if self.prev:
            padded = pad(self.prev, self.cipher.block_size)
        else:
            padded = pad(b'', self.cipher.block_size)
        return self.cipher.encrypt(padded)

    def digest(self):
        if not self.done and self.prev:
            raise Exception("Not yet finished encrypting")
        self.done = True
        return self.cipher.digest()

    def verify(self, tag):
        self.cipher.verify(tag)

    def getDigestSize(self):
        # these all seem to be 128 hashers
        return 16

class HashingBlockEncryptor(HasherMixin, BlockEncryptor):
    def __init__(self, cipher, hasher):
        HasherMixin.__init__(self, cipher, hasher)

class StreamEncryptor:
    done = False
    iv = None

    def __init__(self, cipher):
        self.cipher = cipher
        self.iv = cipher.nonce
        self.update(self.iv)

    def update(self, data):
        self.cipher.update(data)

    def encrypt(self, data):
        return self.cipher.encrypt(data)

    def decrypt(self, data, last=False):
        return self.cipher.decrypt(data)

    def finish(self):
        return b''

    def digest(self):
        return self.cipher.digest()

    def verify(self, tag):
        self.cipher.verify(tag)

    def getDigestSize(self):
        # these all seem to be 128 hashers
        return 16

def HashingStreamEncryptor(HasherMixin, StreamEncryptor):
    pass


class NullEncryptor:
    iv = b''

    def encrypt(self, data):
        return data
    def decrypt(self, data, last=False):
        return data
    def finish(self):
        return b''
    def digest(self):
        return b''
    def verify(self, tag):
        pass

class Crypto_Null:
    _cryptoScheme = '0'
    _cryptoName   = 'None'
    _contentKey  = None
    _filenameKey = None
    _keyKey      = None
    _random      = None
    _filenameEnc = None
    _fsEncoding  = None
    _blocksize   = AES.block_size
    _keysize     = AES.key_size[-1]                                              # last (largest) acceptable _keysize
    _altchars    = b'#@'

    ivLength    = 0

    class NullCipher():
        def encrypt(data):
            return data

    def __init__(self, password=None, client=None, fsencoding=sys.getfilesystemencoding()):
        pass

    def getCryptoScheme(self):
        return self._cryptoScheme

    def encrypting(self):
        return False

    def getContentCipher(self, iv):
        return NullCipher()

    def getContentEncryptor(self, iv=None):
        return NullEncryptor()

    def encryptFilename(self, name):
        return name

    def decryptFilename(self, name):
        if isinstance(name, bytes):
            return name.decode('utf8')
        else:
            return name


    def getHash(self, func=hashlib.md5):
        return func()

    def getIV(self):
        return None

    def pad(self, data, length=None):
        return data

    def unpad(self, data):
        return data

    def checkpad(self, data):
        pass

    def padzero(self, data, length=None):
        return 

    def encryptPath(self, path):
        return path

    def decryptPath(self, path):
        return path

    def encryptFilename(self, name):
        return name

    def genKeys(self):
        pass

    def setKeys(self, filenameKey, contentKey):
        pass

    def getKeys(self):
        return (None, None)




class Crypto_AES_CBC_HMAC__AES_ECB(Crypto_Null):
    """ Original Crypto Scheme.
    AES-256 CBC encyrption for files, with HMAC/SHA-512 for authentication.
    AES-256 ECB for filenames with no authentictaion.
    No authentication of key values.
    For backwards compatibility only.
    """
    _cryptoScheme = '1'
    _cryptoName   = 'AES-CBC-HMAC/AES-ECB/PBKDF2'
    _contentKey  = None
    _filenameKey = None
    _keyKey      = None
    _random      = None
    _filenameEnc = None
    _fsEncoding  = None
    _blocksize   = AES.block_size
    _keysize     = AES.key_size[-1]                                              # last (largest) acceptable _keysize
    _altchars    = b'#@'

    ivLength    = _blocksize

    def __init__(self, password, client=None, fsencoding=sys.getfilesystemencoding()):
        self._random = Cryptodome.Random.new()
        if client is None:
            client = Defaults.getDefault('TARDIS_CLIENT')

        self.client = bytes(client, 'utf8')
        self.salt = hashlib.sha256(self.client).digest()
        keys = self.genKeyKey(password)
        self._keyKey     = keys[0:self._keysize]                                      # First 256 bit key

        self._fsEncoding = fsencoding

    def encrypting(self):
        return True

    def genKeyKey(self, password):
        return PBKDF2(password, self.salt, count=20000, dkLen=self._keysize * 2)      # 2x256 bit keys

    def getContentCipher(self, iv):
        if iv is None:
            iv = self.getIV()
        return AES.new(self._contentKey, AES.MODE_CBC, IV=iv)

    def getContentEncryptor(self, iv=None):
        return HashingBlockEncryptor(self.getContentCipher(iv), self.getHash(hashlib.sha512))

    def getHash(self, func=hashlib.md5):
        return hmac.new(self._contentKey, digestmod=func)

    def getIV(self):
        return self._random.read(self.ivLength)

    def pad(self, data, length=None):
        if length is None:
            length = len(data)
        pad = self._blocksize - (length % self._blocksize)
        data += bytes(chr(pad) * pad, 'utf8')
        return data

    def unpad(self, data):
        #if validate:
            #self.checkpad(data)
        l = data[-1]
        x = len(data) - l
        return data[:x]

    def checkpad(self, data):
        l = data[-1]
        # Make sure last L bytes are all set to L
        pad = chr(l) * l
        if data[-l:] != pad:
            raise Exception("Invalid padding: %s (%d)", binascii.hexlify(data[-l:]), l)

    def padzero(self, x):
        remainder = len(x) % self._blocksize
        if remainder == 0:
            return x
        else:
            return x + (self._blocksize - remainder) * b'\0'

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
        n = self.padzero(bytes(name, 'utf8'))
        return str(base64.b64encode(self._filenameEnc.encrypt(n), self._altchars), 'utf8')

    def decryptFilename(self, name):
        return str(self._filenameEnc.decrypt(base64.b64decode(name, self._altchars)), 'utf8').rstrip('\0')

    def genKeys(self):
        self._contentKey  = self._random.read(self._keysize)
        self._filenameKey = self._random.read(self._keysize)
        self._filenameEnc = AES.new(self._filenameKey, AES.MODE_ECB)

    def setKeys(self, filenameKey, contentKey):
        cipher = AES.new(self._keyKey, AES.MODE_ECB)
        self._contentKey  = cipher.decrypt(base64.b64decode(contentKey))
        self._filenameKey = cipher.decrypt(base64.b64decode(filenameKey))
        self._filenameEnc = AES.new(self._filenameKey, AES.MODE_ECB)

    def getKeys(self):
        if self._filenameKey and self._contentKey:
            cipher = AES.new(self._keyKey, AES.MODE_ECB)
            _contentKey  = str(base64.b64encode(cipher.encrypt(self._contentKey)), 'utf8')
            _filenameKey = str(base64.b64encode(cipher.encrypt(self._filenameKey)), 'utf8')
            return (_filenameKey, _contentKey)
        else:
            return (None, None)


class Crypto_AES_CBC_HMAC__AES_SIV(Crypto_AES_CBC_HMAC__AES_ECB):
    """
    Improved crypto scheme.
    Still uses AES-256 CBC with HMAC/SHA-512 Authentication.
    Changes Filename encryption to using AES-256 SIV encryption and authentication.  On upgraded systems (ie,
    those formerly using Crypto_AES_CBC_HMAC__AES_ECB), AES-128 SIV encryption and authentication is used.
    Uses AES-128 SIV encryption and validation on the keys.
    """
    _cryptoScheme = '2'
    _cryptoName   = 'AES-CBC-HMAC/AES-SIV/scrypt'

    def __init__(self, password, client=None, fsencoding=sys.getfilesystemencoding()):
        super().__init__(password, client, fsencoding)

    def genKeyKey(self, password):
        return scrypt(password, self.salt, 32, 65536, 8, 1)

    def _encryptSIV(self, key, value, name=None):
        cipher = AES.new(key, AES.MODE_SIV)
        if name:
            cipher.update(name.encode('utf8'))
        (ctext, tag) = cipher.encrypt_and_digest(value)
        return ctext + tag

    def _decryptSIV(self, key, value, name=None):
        cipher = AES.new(key, AES.MODE_SIV)
        if name:
            cipher.update(name.encode('utf8'))

        ctext = value[0:-cipher.block_size]
        tag   = value[-cipher.block_size:]
        return cipher.decrypt_and_verify(ctext, tag)

    def encryptFilename(self, name):
        encrypted = self._encryptSIV(self._filenameKey, name.encode('utf8'))
        return base64.b64encode(encrypted, self._altchars).decode('utf8')

    def decryptFilename(self, name):
        return self._decryptSIV(self._filenameKey, base64.b64decode(name, self._altchars)).decode('utf8')

    def genKeys(self):
        self._contentKey  = self._random.read(self._keysize)
        self._filenameKey = self._random.read(2 * self._keysize)

    def setKeys(self, filenameKey, contentKey):
        ckey = base64.b64decode(contentKey)
        fkey = base64.b64decode(filenameKey)

        try:
            self._contentKey   = self._decryptSIV(self._keyKey, ckey, "ContentKey")
            self._filenameKey  = self._decryptSIV(self._keyKey, fkey, "FilenameKey")
        except ValueError as e:
            raise ValueError(f"Keys failed to authenticate: {str(e)}")

    def getKeys(self):
        if self._filenameKey and self._contentKey:
            _contentKey  = str(base64.b64encode(self._encryptSIV(self._keyKey, self._contentKey, "ContentKey")), 'utf8')
            _filenameKey = str(base64.b64encode(self._encryptSIV(self._keyKey, self._filenameKey, "FilenameKey")), 'utf8')
            return (_filenameKey, _contentKey)
        else:
            return (None, None)


class Crypto_AES_GCM__AES_SIV(Crypto_AES_CBC_HMAC__AES_SIV):
    """
    Improved crypto scheme.
    Still uses AES-256 GCM for encryption and authentication
    Uses ASE-256 SIV encryption and authentaction for files
    """
    _cryptoScheme = '3'
    _cryptoName   = 'AES-GCM/AES-SIV/scrypt'

    def __init__(self, password, client=None, fsencoding=sys.getfilesystemencoding()):
        super().__init__(password, client, fsencoding)

    def getContentCipher(self, iv=None):
        if iv is None:
            iv = self.getIV()
        return AES.new(self._contentKey, AES.MODE_GCM, nonce=iv)

    def getContentEncryptor(self, iv=None):
        return StreamEncryptor(self.getContentCipher(iv))


class Crypto_ChaCha20_Poly1305__AES_SIV(Crypto_AES_CBC_HMAC__AES_SIV):
    """
    Improved crypto scheme.
    Uses ChaCha20/Poly1305  for encryption and authentication
    Uses ASE-256 SIV encryption and authentaction for files
    """
    _cryptoScheme = '4'
    _cryptoName   = 'ChaCha20-Poly1305/AES-SIV/scrypt'

    ivLength    = 12

    def __init__(self, password, client=None, fsencoding=sys.getfilesystemencoding()):
        super().__init__(password, client, fsencoding)

    def getContentCipher(self, iv):
        return ChaCha20_Poly1305.new(key=self._contentKey, nonce=iv)

    def getContentEncryptor(self, iv=None):
        return StreamEncryptor(self.getContentCipher(iv))


if __name__ == '__main__':
    string = b'abcdefghijknlmnopqrstuvwxyz' + \
             b'ABCDEFGHIJKNLMNOPQRSTUVWXYZ' + \
             b'1234567890!@#$%&*()[]{}-_,.<>'

    #print(string)
    path = '/srv/home/kolding/this is a/test.onlyATest/X'
    fname ='test.only1234'

    print(getCryptoNames())
    print(getCryptoNames(3))

    for i in range(0, 5):
        print(f"\nTesting {i}")
        try:
            c = getCrypto(i, 'PassWordXYZ123')
            print(f"Type: {c._cryptoName}")
            c.genKeys()

            print(f"DigestSize: {c.getDigestSize()}")

            print("--- Testing Content Encryptor ---")
            e = c.getContentEncryptor()
            d = c.getContentEncryptor(e.iv)

            ct = e.encrypt(string) + e.finish()
            pt = d.decrypt(ct, True)

            assert(pt == string)
            d.verify(e.digest())

            print("--- Testing Filename Encryptor ---")
            cf = c.encryptFilename(fname)
            #print(cf)
            df = c.decryptFilename(cf)

            assert(fname == df)

            print("--- Testing FilePath Encryptor ---")
            cp = c.encryptPath(path)
            #print(cp)
            dp = c.decryptPath(cp)

            assert(path == dp)
            
        except Exception as e:
            print(f"Caught exception: {e}")
            print(e)



