import sqlite3
import sys
import os.path
import logging

version = 4

def upgrade(conn, logger):
    s = conn.execute('SELECT Value FROM Config WHERE Key = "SchemaVersion"')
    t = s.fetchone()
    if int(t[0]) != version:
        logger.error("Invalid database schema version: {}".format(t[0]))
        raise Exception("Invalid version {}.  Expected {}".format(t[0], version)
	
	conn.execute("ALTER TABLE Checksums ADD COLUMN Added INTEGER")
	conn.execute("ALTER TABLE Checksums ADD COLUMN IsFile INTEGER")         # Old version only uses checksums for files.

	conn.execute("UPDATE Checksums SET IsFile = 1")

	# This can be really slow.  Only enable it if you really want it.
	# conn.execute("UPDATE Checksums SET Added = (SELECT MIN(FirstSet) FROM Files WHERE Files.ChecksumID = Checksums.ChecksumID OR Files.XattrID = Checksums.ChecksumID OR Files.AclID = Checksums.ChecksumId)")

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