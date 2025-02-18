#! /usr/bin/env python3
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

import os.path
import logging
import argparse
import hashlib
import base64

import srp
from Cryptodome.Cipher import AES

from Tardis import Defaults, Util, TardisDB, TardisCrypto

def getToken(db):
    return db._getConfigValue('Token')

def checkToken(db, token):
    dbToken = getToken(db)
    if dbToken is None:
        print("No token in DB.  Password is not set.")
        return False
    s = hashlib.sha1()
    s.update(token)
    tokenhash = s.hexdigest()
    return dbToken == tokenhash

def createToken(crypto, client):
    cipher = AES.new(crypto._tokenKey, AES.MODE_ECB)
    token = base64.b64encode(cipher.encrypt(crypto.padzero(client)), crypto._altchars)
    return token

def processArgs():
    parser = argparse.ArgumentParser(description='Set directory hashes.')
    parser.add_argument('--repo', '-R',     dest='repo', default=Defaults.getDefault('TARDIS_REPO'),    help="Repository to use.  Default: %(default)s")

    passgroup= parser.add_argument_group("Password/Encryption specification options")
    pwgroup = passgroup.add_mutually_exclusive_group(required=True)
    pwgroup.add_argument('--password', '-p',dest='password', default=None, nargs='?', const=True,       help='Encrypt files with this password')
    pwgroup.add_argument('--password-file', dest='passwordfile', default=None,                          help='Read password from file')
    pwgroup.add_argument('--password-url',  dest='passwordurl', default=None,                           help='Retrieve password from the specified URL')
    pwgroup.add_argument('--password-prog', dest='passwordprog', default=None,                          help='Use the specified command to generate the password on stdout')

    return parser.parse_args()

def main():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()
    crypto = None
    args = processArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordurl, args.passwordprog)

    if password:
        crypto = TardisCrypto.TardisCrypto(password, args.client)

    path = os.path.join(args.repo, 'tardis.db')
    db = TardisDB.TardisDB(path, backup=False)

    token = createToken(crypto, args.client)
    if not checkToken(db, token):
        logger.error("Password does not match")
        raise Exception()

    salt, vkey = srp.create_salted_verification_key(args.client, password)
    db.setSrpValues(salt, vkey)
    db._setConfigValue('Token', None)

if __name__ == "__main__":
    main()
