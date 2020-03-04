#! /usr/bin/env python3
# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2020, Eric Koldinger, All Rights Reserved.
# kolding@washington.edu
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

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

def hasExt(x):
    (_, e) = os.path.splitext(x)
    return (e is not '' and e is not None)

def main():
    d = sys.argv[1]

    db = os.path.join(d, "tardis.db")
    print("Opening DB: " + db)
    conn = sqlite3.connect(db)
    print("Connected")

    missingData = set()
    unreferenced = set()

    for i in hexcount(0, 256, 2):
        print("Starting: ", i)
        # Get all the files which start with i
        dbfiles = getdbfiles(conn, i)
        alldatafiles = set()
        # Grab each subdirectory, 
        for j in hexcount(0, 256, 2):
            path = os.path.join(d, i, j)
            try:
                if os.path.isdir(path):
                    contents = os.listdir(path)
                    metafiles = set(filter(hasExt, contents))
                    datafiles = set(filter(lambda x: not hasExt(x), contents))

                    alldatafiles.update(datafiles)

                    #print path, " :: ", len(contents), len(metafiles), len(datafiles), " :: ", len(dbfiles)
                    # Process the signature files
                    for f in metafiles:
                        (data, _) = os.path.splitext(f)
                        if not data in datafiles:
                            print "{} without matching data file".format(f)
            except Exception as e:
                print "Caught exception proecssing directory {}".format(path)

        # Find missing data files
        missing = dbfiles.difference(alldatafiles)
        missingData.update(missing)
        for i in missing:
            print("Missing data files {}".format(i))

        # Find files which aren't in the DB
        unref = alldatafiles.difference(dbfiles)
        unreferenced.update(unref)
        for i in unref:
            print("Unreferenced data file: {}".format(i))

    conn.close()

if __name__ == "__main__":
    main()
