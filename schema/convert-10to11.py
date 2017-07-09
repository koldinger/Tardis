import sqlite3
import sys
import os.path
import logging

version = 10

def upgrade(conn, logger):
    s = conn.execute('SELECT Value FROM Config WHERE Key = "SchemaVersion"')
    t = s.fetchone()
    if int(t[0]) != version:
        logger.error("Invalid database schema version: {}".format(t[0]))
        raise Exception("Invalid version {}.  Expected {}".format(t[0], version)

	conn.execute('UPDATE Checksums SET Compressed = "zlib" WHERE Compressed IS 1')
	conn.execute('UPDATE Checksums SET Compressed = "none" WHERE Compressed IS 0')

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
