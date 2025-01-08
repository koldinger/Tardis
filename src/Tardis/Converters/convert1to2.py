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

import sqlite3
import sys
import os.path


def processDir(path, bset, parent, device):
    #print u"  Processing {}".format(path)
    s = conn.execute("UPDATE Files SET ParentDev = :device WHERE Parent = :parent AND :bset BETWEEN FirstSet AND LastSet",
                    {"parent": parent, "device": device, "bset": bset})
    s = conn.execute("UPDATE Files SET Device = :device WHERE Parent = :parent AND Device IS NULL AND :bset BETWEEN FirstSet AND LastSet",
                    {"parent": parent, "device": device, "bset": bset})
    s = conn.execute("SELECT Name, INode, Device, ParentDev FROM Files JOIN Names ON Files.Nameid = Names.Nameid WHERE Parent = :parent AND ParentDev != Device AND ParentDev != 0 AND :bset BETWEEN FirstSet AND LastSet",
                    {"parent": parent, "device": device, "bset": bset})
    for row in s.fetchall():
        name  = row[0]
        inode = row[1]
        device = row[2]
        parentdev = row[3]
        sub = os.path.join(path, name)
        print("    {} ({}) has different device from parent: {} {}".format(sub, inode, device, parentdev))
    s = conn.execute("SELECT Name, inode, device FROM Files JOIN Names ON Files.Nameid = Names.Nameid WHERE Parent = :parent AND dir = 1 AND :bset BETWEEN FirstSet AND LastSet",
                    {"parent": parent, "bset": bset})
    for row in s.fetchall():
        name  = row[0]
        inode = row[1]
        device = row[2]
        sub = os.path.join(path, name)
        processDir(sub, bset, inode, device)

schemaFile = "schema/tardis.sql"
## Update this list of files to express all top level mount points.
## At this point, interior mounted files are not updated.
topfiles = [
            ("etc", 2082),
            ("GITROOT", 2305),
            ("CVSROOT", 2305),
            ("home", 2305),
            ("music", 2305),
            ("pictures", 2305),
            ("videos", 2097),
            ]

if len(sys.argv) > 1:
    db = sys.argv[1]
else:
    db = "tardis.db"

conn = sqlite3.connect(db)

s = conn.execute('SELECT Value FROM Config WHERE Key = "SchemaVersion"')
t = s.fetchone()
if t[0] != 1:
    print(("Invalid database schema version: {}".format(t[0])))
    sys.exit(1)

conn.execute("ALTER TABLE Files ADD COLUMN Device INTEGER")
conn.execute("ALTER TABLE Files ADD COLUMN ParentDev INTEGER")
conn.execute("UPDATE Files SET ParentDev = 0 WHERE Parent = 0")

for i in topfiles:
    (name, device) = i
    print(("Updating {} to device {}".format(name, device)))
    s = conn.execute("UPDATE Files SET Device = :device "
                     "WHERE Inode = (SELECT Inode FROM Files JOIN Names ON Files.nameid = Names.nameid AND ParentDev = 0 and Names.name = :name)",
                     {"name": name, "device": device})

s = conn.execute("SELECT BackupSet, Name FROM Backups ORDER BY BackupSet ASC")
for row in s.fetchall():
    bset = row[0]
    name = row[1]
    print("Processing set {} ({})".format(name, bset))
    processDir("/", bset, 0, 0)

print("Done updating.  Rearranging tables to meet new schema")

# Rename the orginal table and delete the vfiles
conn.execute("ALTER TABLE Files RENAME TO Temp")
conn.execute("DROP VIEW VFiles")

with open(schemaFile, "r") as f:
    script = f.read()
    conn.executescript(script)

conn.execute("INSERT INTO Files(NameId, FirstSet, LastSet, Inode, Device, Parent, ParentDev, ChecksumId, Dir, Link, MTime, CTime, ATime, Mode, UID, GID, NLinks)"
             "SELECT NameId, FirstSet, LastSet, Inode, Device, Parent, ParentDev, ChecksumId, Dir, Link, MTime, CTime, ATime, Mode, UID, GID, NLinks FROM Temp")
conn.execute("DROP TABLE Temp")
conn.execute('INSERT OR REPLACE INTO Config (Key, Value) VALUES ("SchemaVersion", "2")')
