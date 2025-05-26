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

import functools
import logging
import os.path
import sqlite3
import sys

from Tardis import Util

from . import convertutils

version = 22

@functools.cache
def getName(conn, nameid):
    c = conn.execute("SELECT Name FROM Names WHERE NameID = :nameid", {"nameid": nameid})
    r = c.fetchone()
    return r[0]

def findpath(conn, row):
    name = getName(conn, row[0])
    if row[5] == 0 and row[6] == 0:
        pName = "/"
    else:
        cur = conn.execute( "SELECT NameID, FirstSet, LastSet, Inode, Device, Parent, ParentDev FROM Files WHERE Inode = :inode AND Device = :device AND :firstset BETWEEN FirstSet AND LastSet", {"inode": row[5], "device": row[6], "firstset": row[1]})
        parent = cur.fetchone()
        pName = findpath(conn, parent)
    return os.path.join(pName, name)

@functools.cache
def getDeviceId(conn, virtualDevice):
    cur = conn.execute("SELECT DeviceID FROM Devices WHERE VirtualID = :virtualDev", {"virtualDev": virtualDevice})
    row = cur.fetchone()
    if row:
        deviceId = row[0]
    else:
        c = conn.execute("INSERT INTO Devices (VirtualID) VALUES (:virtualDev)", {"virtualDev": virtualDevice})
        deviceId = c.lastrowid
    return deviceId

def upgrade(conn, logger):
    convertutils.checkVersion(conn, version, logger)

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS Devices (
            DeviceID    INTEGER PRIMARY KEY AUTOINCREMENT,
            VirtualID   TEXT UNIQUE NOT NULL
        )
        """
    )

    #conn.execute("ALTER TABLE Files ADD COLUMN DeviceID INTEGER REFERENCES Devices(DeviceID)")
    #conn.execute("ALTER TABLE Files ADD COLUMN ParentDevID INTEGER REFERENCES Devices(DeviceID)")

    # Create a root device.
    rootVId = Util.hashPath("/")
    conn.execute("INSERT INTO Devices (DeviceID, VirtualID) VALUES (0, :virtid)", {"virtid": rootVId})

    # Here we put the name insertion but it really doesn't work, because we really want to insert
    # encrypted names.
    cursor = conn.execute("SELECT DISTINCT(Device) FROM Files UNION SELECT DISTINCT(ParentDev) FROM Files")
    rows = cursor.fetchall()

    total = 0
    for row in rows:
        device = row[0]
        if device == 0:
            deviceId = getDeviceId(conn, Util.hashPath("/"))
        else:
            deviceId = getDeviceId(conn, Util.hashPath(str(device)))
        #name = row[0]
        c = conn.execute("UPDATE Files SET Device = :deviceid WHERE Device = :device", {"deviceid": deviceId, "device": device})
        total += c.rowcount
        c = conn.execute("UPDATE Files SET ParentDev = :deviceid WHERE ParentDev = :device", {"deviceid": deviceId, "device": device})
        total += c.rowcount

    conn.executescript("""
        DROP VIEW  VFiles;

        CREATE VIEW IF NOT EXISTS VFiles AS
            SELECT Names.Name AS Name, Inode, D1.VirtualID AS Device, Parent, D2.VirtualID AS ParentDev, Dir, Link, Size, MTime, CTime, ATime, Mode, UID, GID, NLinks, Checksum, Backups.BackupSet, Backups.Name AS Backup
            FROM Files
            JOIN Names ON Files.NameID = Names.NameID
            JOIN Backups ON Backups.BackupSet BETWEEN Files.FirstSet AND Files.LastSet
            JOIN Devices D1 ON Files.Device = D1.DeviceID
            JOIN Devices D2 ON Files.ParentDev = D2.ParentDevID
            LEFT OUTER JOIN CheckSums ON Files.ChecksumId = CheckSums.ChecksumId;
        """)
    
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
