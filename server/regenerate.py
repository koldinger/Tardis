#! /usr/bin/python

import os
import os.path
import argparse

database = "./tardisDB"

def readHeader(f):
    line = f.readline().rstrip()
    if line == "--- TARDIS 1.0":
        print line
        line = f.readline().rstrip()
        while line != "---":
            print line
            line = f.readline().rstrip()
        pos = f.tell()
        print pos
        print "------"
    else:
        f.seek(0)

def recoverFile(file):
    f = open(file)
    if f:
        header = readHeader(f)
        x = f.read(8192)
        print x

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Recover a file from the tardis DB")

    parser.add_argument("--database", help="Path to database directory", default=database)
    parser.add_argument("file")

    args = parser.parse_args()
    print args

    file = os.path.join(args.database, args.file)
    print file

    recoverFile(file)
