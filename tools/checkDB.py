# /usr/bin/python

import os, os.path
import sys
import sqlite3
import gettext

from Tardis import Util

def hexcount(lower, upper, digits):
    fmt = "%0" + str(digits) + "x"
    for i in range(lower, upper):
        out = fmt % (i)
        yield out

def getdbfiles(conn, prefix):
    prefix += "%"
    ret = set()
    cur = conn.execute('SELECT Checksum FROM Checksums WHERE Checksum LIKE :prefix AND IsFile = 1', {"prefix": prefix})
    while True:
        batch = cur.fetchmany()
        if not batch:
            break
        ret.update([i[0] for i in batch])
    return ret

def main():
    d = sys.argv[1]


    db = os.path.join(d, "tardis.db")
    conn = sqlite3.connect(db)

    sigNoData = set()
    missingData = set()
    unreferenced = set()

    for i in hexcount(0, 256, 2):
        print "Starting: ", i
        # Get all the files which start with i
        dbfiles = getdbfiles(conn, i)
        alldatafiles = set()
        # Grab each subdirectory, 
        for j in hexcount(0, 256, 2):
            path = os.path.join(d, i, j)
            if os.path.isdir(path):
                contents = os.listdir(path)
                sigfiles  = set([x for x in contents if x.endswith(".sig")])
                datafiles = set([x for x in contents if not x.endswith(".sig")])

                alldatafiles.update(datafiles)
                
                #print path, " :: ", len(contents), len(sigfiles), len(datafiles), " :: ", len(dbfiles)
                # Process the signature files
                for sig in sigfiles:
                    data = sig[:-4]
                    if not data in datafiles:
                        print "Signature {} without matching data file".format(sig)
                        sigNoData.add(sig)

        # Find missing data files
        missing = dbfiles.difference(alldatafiles)
        missingData.update(missing)
        for i in missing:
            print "Missing data files {}".format(i)
        # Find files which aren't in the DB
        unref = alldatafiles.difference(dbfiles)
        unreferenced.update(unref)
        for i in unref:
            print "Unreferenced data file: {}".format(i)
        """
        for dbf in dbfiles:
            if not dbf in alldatafiles:
                print "Unreferenced data file: {}".format(data)

        for data in alldatafiles:
            if not data in dbfiles:
                print "Missing data files {}".format(dbf)
        """

    conn.close()

if __name__ == "__main__":
    main()
