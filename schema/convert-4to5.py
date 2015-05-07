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
if int(t[0]) != 4:
    print("Invalid database schema version: {}".format(t[0]))
    sys.exit(1)

conn.execute("ALTER TABLE Checksums ADD COLUMN Added INTEGER")

# This can be really slow.  It can be removed if you feel it's not worth it.
conn.execute("UPDATE Checksums SET Added = (SELECT MIN(FirstSet) FROM Files WHERE Files.ChecksumID = Checksums.ChecksumID)")

conn.execute('INSERT OR REPLACE INTO Config (Key, Value) VALUES ("SchemaVersion", "5")')

conn.commit()
