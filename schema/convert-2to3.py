import sqlite3
import sys
import os.path
import logging

version = 2

def upgrade(conn, logger):
    s = conn.execute('SELECT Value FROM Config WHERE Key = "SchemaVersion"')
    t = s.fetchone()
    if int(t[0]) != version:
        logger.error("Invalid database schema version: {}".format(t[0]))
        raise Exception("Invalid version {}.  Expected {}".format(t[0], version))

    conn.execute("ALTER TABLE Files ADD COLUMN XattrId INTEGER")
    conn.execute("ALTER TABLE Files ADD COLUMN AclId INTEGER")
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

    # Ugh, make sure the last element is a tuple, otherwise the string will get broken into multiple characters
    conn.execute('INSERT OR REPLACE INTO Config (Key, Value) VALUES ("SchemaVersion", ?)', (str(version + 1),) )
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
