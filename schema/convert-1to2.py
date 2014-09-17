import sqlite3
import sys

schemaFile = "schema/tardis.sql"
topfiles = [
            ("CVSROOT", 2305),
            ("GITROOT", 2305),
            ("etc", 2082),
            ("home", 2305),
            ("music", 2305),
            ("pictures", 2305),
            ("videos", 2097),
            ]

conn = sqlite3.connect("tardis.db")

s = conn.execute('SELECT Value FROM Config WHERE Key = "SchemaVersion"')
t = s.fetchone()
if t[0] != 1:
    print("Invalid database schema version: {}".format(t[0]))
    sys.exit(1)

conn.execute("ALTER TABLE Files ADD COLUMN Device INTEGER")
conn.execute("ALTER TABLE Files ADD COLUMN ParentDev INTEGER")
conn.execute("UPDATE Files SET ParentDev = 0 WHERE Parent = 0");

for i in topfiles:
    (name, device) = i
    print("Updating {} to device {}".format(name, device))
    s = conn.execute("UPDATE Files SET Device = :device "
                     "WHERE Inode = (SELECT Inode FROM Files JOIN Names ON Files.nameid = Names.nameid AND ParentDev = 0 and Names.name = :name)",
                     {"name": name, "device": device})

s = conn.execute("SELECT Inode, Device FROM Files WHERE Device IS NOT NULL AND Parent = 0;");
for row in s.fetchall():
    inode = row[0]
    device = row[1]

    print("Inode: {} Device: {}".format(inode, device))

    t = conn.execute("WITH RECURSIVE x(n) AS (VALUES(:inode) UNION SELECT Inode FROM Files, x WHERE Files.Parent = x.n) "
                     "UPDATE Files SET Device = :device, ParentDev = :device WHERE Parent in x",
                     #"SELECT Name, Inode, Parent FROM Files JOIN Names ON Files.Nameid = Names.Nameid WHERE Parent IN x",
                     {"inode": inode, "device": device});

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
