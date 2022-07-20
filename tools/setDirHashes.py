#! /usr/bin/env python3
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

import sys
sys.path.insert(0, '.')

from Tardis import Defaults, Util, TardisDB, TardisCrypto
import os.path
import logging
import argparse
import hashlib


def processArgs():
    parser = argparse.ArgumentParser(description='Set a token/password')
    parser.add_argument('--database', '-D', dest='database', default=Defaults.getDefault('TARDIS_DB'),      help="Database to use.  Default: %(default)s")
    parser.add_argument('--client', '-C',   dest='client',   default=Defaults.getDefault('TARDIS_CLIENT'),  help="Client to list on.  Default: %(default)s")
    parser.add_argument('--dbname',         dest='dbname',   default=Defaults.getDefault('TARDIS_DBNAME'),  help="Name of the database file. Default: %(default)s")

    passgroup= parser.add_argument_group("Password/Encryption specification options")
    pwgroup = passgroup.add_mutually_exclusive_group()
    pwgroup.add_argument('--password', '-p',dest='password', default=None, nargs='?', const=True,       help='Encrypt files with this password')
    pwgroup.add_argument('--password-file', dest='passwordfile', default=None,                          help='Read password from file')
    pwgroup.add_argument('--password-url',  dest='passwordurl', default=None,                           help='Retrieve password from the specified URL')
    pwgroup.add_argument('--password-prog', dest='passwordprog', default=None,                          help='Use the specified command to generate the password on stdout')

    return parser.parse_args()

def main():
    logging.basicConfig(level=logging.INFO)
    crypto = None
    token = None
    args = processArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordurl, args.passwordprog)

    if password:
        crypto = TardisCrypto.TardisCrypto(password, args.client)

    path = os.path.join(args.database, args.client, args.dbname)
    db = TardisDB.TardisDB(path, token=token, backup=False)

    if crypto:
        (a, b) = db.getKeys()
        crypto.setKeys(a, b)

    conn = db.conn
    dirs = conn.execute("SELECT Name as name, Inode AS inode, Device AS device, FirstSet as firstset, LastSet AS lastset FROM Files JOIN Names ON Files.NameId = Names.NameId WHERE Dir = 1")
    while True:
        batch = dirs.fetchmany(1000)
        if not batch:
            break

        for d in batch:
            name     = d['name']
            inode    = d['inode']
            device   = d['device']
            firstset = d['firstset']
            lastset  = d['lastset']

            files = db.readDirectory((inode, device), current=lastset)
            (checksum, nfiles) = Util.hashDir(crypto, files, True)

            print(("%-20s (%d, %d) [%d %d] -- %s %d") % (name, inode, device, firstset, lastset, checksum, nfiles))
            ckinfo = db.getChecksumInfo(checksum)
            if ckinfo:
                cksid = ckinfo['checksumid']
            else:
                cksid = db.insertChecksumFile(checksum, size=nfiles, isFile=False)

            db.updateDirChecksum((inode, device), cksid, current=lastset)
        conn.commit()

if __name__ == "__main__":
    main()
