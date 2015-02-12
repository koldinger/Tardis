import sqlite3
import sys
import os.path
from Tardis import CacheDir


if len(sys.argv) > 1:
    db = sys.argv[1]
else:
    db = "tardis.db"

conn = sqlite3.connect(db)

s = conn.execute('SELECT Value FROM Config WHERE Key = "SchemaVersion"')
t = s.fetchone()
if int(t[0]) != 2:
    print("Invalid database schema version: {}".format(t[0]))
    sys.exit(1)

conn.execute("ALTER TABLE Files ADD COLUMN XattrId INTEGER")
conn.execute("ALTER TABLE Files ADD COLUMN AclID INTEGER")
conn.execute("ALTER TABLE CheckSums ADD COLUMN DiskSize INTEGER")

conn.execute('INSERT OR REPLACE INTO Config (Key, Value) VALUES ("SchemaVersion", "3")')

cache = CacheDir.CacheDir(os.path.dirname(db))

c = conn.execute("SELECT Checksum FROM Checksums WHERE DiskSize IS NULL")
checksums = c.fetchall()
c2 = conn.cursor()
for i in checksums:
    checksum = i[0]
    size = os.path.getsize(cache.path(checksum))
    print "Setting size of %s to %d" % (checksum, size)
    c2.execute("UPDATE Checksums SET DiskSize = ? WHERE Checksum = ?", (size, checksum))

conn.commit()
