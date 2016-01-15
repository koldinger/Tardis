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
if int(t[0]) != 5:
    print("Invalid database schema version: {}".format(t[0]))
    sys.exit(1)

conn.execute("INSERT INTO Config SELECT 'ClientID', lower(hex(randomblob(16)))");

conn.commit()
