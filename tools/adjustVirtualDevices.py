#! /usr/bin/env python3
# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2025, Eric Koldinger, All Rights Reserved.
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

import argparse
import os.path
import logging
import pprint

from Tardis import Util, librsync, Regenerator, Config

logger: logging.Logger

def processArgs():
    parser = argparse.ArgumentParser(description='Encrypt the database', add_help = False)

    (_, remaining) = Config.parseConfigOptions(parser)
    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    Util.addGenCompletions(parser)

    args = parser.parse_args(remaining)
    return args

def getPath(db, crypt, bset, inode):
    fInfo = db.getFileInfoByInode(inode, bset)
    if fInfo:
        parent = (fInfo['parent'], fInfo['parentdev'])
        prefix = getPath(db, crypt, bset, parent)

        name = crypt.decryptName(fInfo['name'])
        path = os.path.join(prefix, name)
        return path
    return '/'

def main():
    global logger
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('')
    args = processArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog, allowNone=True)

    mounts = {}

    (db, _, crypto) = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname, args.dbdir, allow_upgrade=True)

    conn = db.conn
    cursor = conn.execute("SELECT DISTINCT Inode, DeviceId, VirtualId, FirstSet, LastSet FROM Files JOIN Devices ON Files.Device = Devices.DeviceID WHERE Device != ParentDev")
    data = cursor.fetchall()

    for i in data:
        #print(i)
        #f = db.getFileInfoByInode((i['Inode'], i['VirtualId']), i['FirstSet'])
        p = getPath(db, crypto, i['FirstSet'], (i['Inode'], i['VirtualId']))
        hp = Util.hashPath(p)
        mounts[i['VirtualId']] = (p, hp)

    pprint.pprint(mounts)

    rc = 0
    for i, j in mounts.items():
        if i == j[1]:
            print(f"{i} already adjusted")
            continue
        oldDev = db._getDeviceId(i)
        newDev = db._getDeviceId(j[1])
        print(f"{i} {j[1]} ::: {oldDev} -> {newDev}")
        c = conn.execute("UPDATE Files SET Device = :newDev WHERE Device = :oldDev", {"newDev": newDev, "oldDev": oldDev})
        print(f"Rows Changed Device: {c.rowcount}")
        rc += c.rowcount
        conn.execute("UPDATE Files SET ParentDev = :newDev WHERE ParentDev = :oldDev", {"newDev": newDev, "oldDev": oldDev})
        print(f"Rows Changed Parent: {c.rowcount}")
        rc += c.rowcount
    print(rc)

if __name__ == "__main__":
    main()
