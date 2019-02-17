#! /usr/bin/env python3
# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2017, Eric Koldinger, All Rights Reserved.
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
import os, os.path
import sys
import xattr
import hashlib
import sqlite3
import time
import logging

from Tardis import Regenerate, TardisDB, CacheDir, TardisCrypto, Util, Defaults

import progressbar as pb

checked = {}

try:
    for x in file("valid", "r"):
        x = x.rstrip()
        checked[x] = 1
except:
    pass

print("Loaded %d checksums." % (len(checked)))

output = file('output', 'a')
valid = file('valid', 'a')

def validate(root, client, dbname, password):
    crypto = None
    token = None
    base = os.path.join(root, client)
    cache = CacheDir.CacheDir(base)
    if password:
        crypto = TardisCrypto.TardisCrypto(password, client)
        token = crypto.encryptFilename(client)
    db = TardisDB.TardisDB(os.path.join(base, dbname), token=token, backup=False)
    regen = Regenerate.Regenerator(cache, db, crypto)

    conn = db.conn

    cur = conn.execute("SELECT count(*) FROM CheckSums WHERE IsFile = 1")
    row = cur.fetchone()
    num = row[0]
    print("Checksums: %d" % (num))

    cur = conn.execute("SELECT Checksum FROM CheckSums WHERE IsFile = 1 ORDER BY Checksum ASC");
    pbar = pb.ProgressBar(widgets=[pb.Percentage(), ' ', pb.Counter(), ' ', pb.Bar(), ' ', pb.ETA(), ' ', pb.Timer() ], maxval=num)
    pbar.start()

    row = cur.fetchone()
    i = 1
    while row is not None:
        pbar.update(i)
        i += 1
        try:
            checksum = row['Checksum']
            if not checksum in checked:
                try:
                    f = regen.recoverChecksum(checksum)
                    if f:
                        m = hashlib.md5()
                        d = f.read(128 * 1024)
                        while d:
                            m.update(d)
                            d = f.read(128 * 1024)
                        res = m.hexdigest()
                        if res != checksum:
                            print("Checksums don't match.  Expected: %s, result %s" % (checksum, res))
                            checked[checksum] = 0
                            output.write(checksum + '\n')
                            output.flush()
                        else:
                            checked[checksum] = 1
                            valid.write(checksum + "\n")
                except Exception as e:
                    print("Caught exception processing %s: %s" % (checksum, str(e)))
                    output.write(checksum + '\n')
                    output.flush()

            row = cur.fetchone()
        except sqlite3.OperationalError as e:
            print("Caught operational error.  DB is probably locked.  Sleeping for a bit")
            time.sleep(90)
    pbar.finish()

if __name__ == "__main__":
    root   = Defaults.getDefault('TARDIS_DB')
    client = Defaults.getDefault('TARDIS_CLIENT')
    dbname = Defaults.getDefault('TARDIS_DBNAME')
    password = None # 'PassWord'

    logging.basicConfig(level=logging.INFO)

    validate(root, client, dbname, password)
