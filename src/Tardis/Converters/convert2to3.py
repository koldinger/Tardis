# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2023, Eric Koldinger, All Rights Reserved.
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

import sqlite3
import sys
import os.path
import logging

from . import convertutils

from Tardis import CacheDir

version = 2

def upgrade(conn, logger, db):
    convertutils.checkVersion(conn, version, logger)

    conn.execute("ALTER TABLE Files ADD COLUMN XattrId INTEGER")
    conn.execute("ALTER TABLE Files ADD COLUMN AclId INTEGER")
    conn.execute("ALTER TABLE CheckSums ADD COLUMN DiskSize INTEGER")
    conn.execute("ALTER TABLE CheckSums ADD COLUMN ChainLength INTEGER")

    conn.execute('INSERT OR REPLACE INTO Config (Key, Value) VALUES ("SchemaVersion", "3")')


    print("Setting chain lengths")
    conn.execute("UPDATE Checksums SET ChainLength = 0 WHERE Basis IS NULL")

    rnd = 0

    while True:
        c = conn.execute("SELECT COUNT(*) FROM Checksums WHERE ChainLength IS NULL")
        r = c.fetchone()
        print("Round %d: Remaining empty chainlengths: %d" % (rnd, r[0]))
        rnd += 1
        if r[0] == 0:
            break
        conn.execute("UPDATE Checksums "
                     "SET ChainLength = 1 + (SELECT ChainLength FROM Checksums C WHERE C.Checksum == CheckSums.Basis) "
                     "WHERE (Basis IS NOT NULL) AND (ChainLength IS NULL) AND "
                     "Basis IN (SELECT Checksum FROM Checksums WHERE Chainlength IS NOT NULL)")


    print("Setting data sizes")
    cache = CacheDir.CacheDir(os.path.dirname(db))

    c = conn.execute("SELECT COUNT(*) FROM Checksums WHERE DiskSize IS NULL")
    r = c.fetchone()
    numrows = r[0]
    print(numrows)

    # Get all non-sized files.  Order by checksum so that we can get locality in the directories we read
    c = conn.execute("SELECT Checksum FROM Checksums WHERE DiskSize IS NULL ORDER BY Checksum")
    checksums = c.fetchall()
    # Build a progress bar, if we have that module.  Just for grins.


    c2 = conn.cursor()
    x = 0
    for i in checksums:
        checksum = i[0]
        size = os.path.getsize(cache.path(checksum))
        #print "Setting size of %s to %d" % (checksum, size)
        c2.execute("UPDATE Checksums SET DiskSize = ? WHERE Checksum = ?", (size, checksum))
        x += 1

    convertutils.updateVersion(conn, version, logger)
    conn.commit()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('')

    if len(sys.argv) > 1:
        db = sys.argv[1]
    else:
        db = "tardis.db"

    conn = sqlite3.connect(db)
    upgrade(conn, logger, db)
