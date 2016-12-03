import sqlite3
import sys
import os.path
from Tardis import CacheDir

version = 9

if len(sys.argv) > 1:
    db = sys.argv[1]
else:
    db = "tardis.db"

conn = sqlite3.connect(db)

s = conn.execute('SELECT Value FROM Config WHERE Key = "SchemaVersion"')
t = s.fetchone()
if int(t[0]) != version:
    print("Invalid database schema version: {}".format(t[0]))
    sys.exit(1)

conn.execute("ALTER TABLE Backups ADD COLUMN ServerSession TEXT")

conn.execute('INSERT OR REPLACE INTO Config (Key, Value) VALUES ("SchemaVersion", ?)', str(version + 1))

conn.commit()
