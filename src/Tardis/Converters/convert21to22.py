# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2024, Eric Koldinger, All Rights Reserved.
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
import logging

from . import convertutils

version = 21

def upgrade(conn, logger):
    convertutils.checkVersion(conn, version, logger)

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS Users (
        UserId      INTEGER PRIMARY KEY AUTOINCREMENT,
        NameId      INTEGER REFERENCES Names(NameId)
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS Groups (
        GroupId     INTEGER PRIMARY KEY AUTOINCREMENT,
        NameId      INTEGER REFERENCES Names(NameId)
        )
        """
    )

    try:
        conn.execute("ALTER TABLE Files ADD COLUMN UserID INTEGER;")
        conn.execute("ALTER TABLE Files ADD COLUMN GroupID INTEGER;")
    except Exception as e:
        print("Caught exception", e)

    # Here we put the name insertion but it really doesn't work, because we really want to insert
    # encrypted names.

    conn.execute("INSERT INTO Users (NameId) SELECT DISTINCT Uid FROM Files;")
    conn.execute("INSERT INTO Groups (NameId) SELECT DISTINCT Gid FROM Files;")

    conn.execute("UPDATE Files SET UserID = (SELECT UserID FROM Users WHERE Users.NameId = Files.UID);")
    conn.execute("UPDATE Files SET GroupID = (SELECT GroupID FROM Groups WHERE Groups.NameId = Files.GID);")

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
    upgrade(conn, logger)
