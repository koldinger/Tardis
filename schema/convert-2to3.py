import sqlite3
import sys
import os.path
from Tardis import CacheDir
try:
    import progressbar
    progress = True
except Exception:
    progress=False


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
conn.execute("ALTER TABLE CheckSums ADD COLUMN ChainLength INTEGER")

conn.execute('INSERT OR REPLACE INTO Config (Key, Value) VALUES ("SchemaVersion", "3")')


print "Setting chain lengths"
conn.execute("UPDATE Checksums SET ChainLength = 0 WHERE Basis IS NULL")

rnd = 0

while True:
    c = conn.execute("SELECT COUNT(*) FROM Checksums WHERE ChainLength IS NULL")
    r = c.fetchone()
    print "Round %d: Remaining empty chainlengths: %d" % (rnd, r[0])
    rnd += 1
    if r[0] == 0:
        break
    conn.execute("UPDATE Checksums "
                 "SET ChainLength = 1 + (SELECT ChainLength FROM Checksums C WHERE C.Checksum == CheckSums.Basis) "
                 "WHERE (Basis IS NOT NULL) AND (ChainLength IS NULL) AND "
                 "Basis IN (SELECT Checksum FROM Checksums WHERE Chainlength IS NOT NULL)")


print "Setting data sizes"
cache = CacheDir.CacheDir(os.path.dirname(db))

c = conn.execute("SELECT COUNT(*) FROM Checksums WHERE DiskSize IS NULL")
r = c.fetchone()
numrows = r[0]
print numrows

c = conn.execute("SELECT Checksum FROM Checksums WHERE DiskSize IS NULL ORDER BY Checksum")
checksums = c.fetchall()
# Build a progress bar, if we have that module.  Just for grins.
if progress:
    widgets = [ progressbar.Counter(), ' ', progressbar.Bar(), ' ', progressbar.ETA() ]
    pbar = progressbar.ProgressBar(widgets=widgets, maxval=numrows)
    pbar.start()

c2 = conn.cursor()
x = 0
for i in checksums:
    checksum = i[0]
    size = os.path.getsize(cache.path(checksum))
    #print "Setting size of %s to %d" % (checksum, size)
    c2.execute("UPDATE Checksums SET DiskSize = ? WHERE Checksum = ?", (size, checksum))
    x += 1
    if progress:
        pbar.update(x)

if progress:
    pbar.finish()


conn.commit()
