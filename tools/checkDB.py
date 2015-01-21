import os, os.path
import sys
import sqlite3
import gettext

def hexcount(lower, upper, digits):
    fmt = "%0" + str(digits) + "x"
    for i in range(lower, upper):
        out = fmt % (i)
        yield out

def getdbfiles(conn, prefix):
    prefix += "%"
    cur = conn.execute('SELECT Checksum FROM Checksums WHERE Checksum LIKE :prefix', {"prefix": prefix})
    ret = [i[0] for i in cur.fetchall()]
    return ret

def main():
    d = sys.argv[1]

    db = os.path.join(d, "tardis.db")
    conn = sqlite3.connect(db)

    for i in hexcount(0, 256, 2):
        print "Starting: ", i
        for j in hexcount(0, 256, 2):
            path = os.path.join(d, i, j)
            dbfiles = getdbfiles(conn, i + j)
            if os.path.isdir(path):
                contents = os.listdir(path)
                sigfiles = [x for x in contents if x.endswith(".sig")]
                datafiles = [x for x in contents if not x.endswith(".sig")]

                #print path, " :: ", len(contents), len(sigfiles), len(datafiles)
                for sig in sigfiles:
                    data = sig[:-4]
                    if not data in datafiles:
                        print "Signature {} without matching data file".format(sig)

                for dbf in dbfiles:
                    if not dbf in datafiles:
                        print "Missing data files {}".format(dbf)

                for data in datafiles:
                    if not data in dbfiles:
                        print "Unreferenced data file: {}".format(data)

    conn.close()

if __name__ == "__main__":
    main()
