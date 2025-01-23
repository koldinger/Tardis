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
import logging
import re

import pwd
import grp

from dataclasses import dataclass

from Tardis import Util, Config

logger = None

@dataclass
class Entry:
    current: str|None
    proposed: str|None
    nameid: int
    recordId: int
    old: str|None

def printData(data):
    print(f"{'Key':4}: {'System Name':20} {'Current Name':20}")
    for k, v in sorted(data.items()):
        print(f"{k:4}: {(v.proposed or ''):20} {(v.current or ''):20}")

def editEntry(data, key):
    entry = data.get(key, None)
    if entry:
        while True:
            print(f"Current Name: {entry.current or ''} System Name: {entry.proposed or ''}")
            choice = input("User (C)urrent name, (S)ystem name, (R)eset to previous name, (E)dit the name or (Q)uit: ").strip()
            match choice.lower():
                case 's':
                    if entry.proposed:
                        entry.current = entry.proposed
                        break
                    else:
                        print("Name not set. No System Name available")
                case 'c' | 'r':
                    entry.current = entry.old
                    break
                case 'e':
                    value = input("Enter new name: ").strip()
                    if re.match(r"^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)$", value):
                        entry.current = value
                        break
                    print(f"Invalid username: {value}")
                case 'q':
                    break

def asint(x):
    try:
        return int(x)
    except:
        return x

def editData(data):
    while True:
        printData(data)
        key = input("Line to edit (S to use all system names, C to use all current names, Q to quit, W to write and quit): ").strip()
        
        match key.lower():
            case 'q':
                return None
            case 'w':
                return data
            case value if value in data.keys():
                editEntry(data, value)
            case 's':
                for entry in data.values():
                    entry.current = entry.proposed
            case 'c':
                for entry in data.values():
                    entry.current = entry.old
            case value if asint(value) in data.keys():
                editEntry(data, int(value))
            case value:
                # Invalid entry
                print(f"Invalid entry: {value}")

def editUserNames(tardis, crypt):
    users = list(tardis.getUsers())
    data = {}
    for i in users:
        try:
            pwdEntry = pwd.getpwuid(i['NameId'])
            proposed = pwdEntry[0]
        except: 
            proposed = None
        curname = crypt.decryptFilename(i['Name'])
        userId = i['UserId']
        #print(f"{userId} {curname} {proposed}")
        data[userId] = Entry(curname, proposed, userId, i['NameId'], curname)

    data = editData(data)
    if data:
        for key, value in data.items():
            tardis.setUserInfo(key, crypt.encryptFilename(value.current))

def editGroupNames(tardis, crypt):
    groups = list(tardis.getGroups())
    data = {}
    for i in groups:
        try:
            grpEntry = grp.getgrgid(i['NameId'])
            proposed = grpEntry[0]
        except: 
            proposed = None
        curname = crypt.decryptFilename(i['Name'])
        grpId = i['GroupId']
        #print(f"{grpId} {curname} {proposed}")
        data[grpId] = Entry(curname, proposed, grpId, i['NameId'], curname)

    data = editData(data)
    if data:
        for key, value in data.items():
            tardis.setGroupInfo(key, crypt.encryptFilename(value.current))

def processArgs():
    parser = argparse.ArgumentParser(description='Decrypt a File', fromfile_prefix_chars='@', add_help=False)

    (_, remaining) = Config.parseConfigOptions(parser)
    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    parser.add_argument("--users", "-u",  default=False, action='store_true', help="Edit User Names")
    parser.add_argument("--groups", "-g", default=False, action='store_true', help="Edit Group Names")

    Util.addGenCompletions(parser)

    args = parser.parse_args(remaining)

    if not (args.users or args.groups):
        parser.error("Must specify either --users or --groups")

    return args

def main():
    global logger
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('')
    args = processArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog)

    tardis, _, crypto = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname, args.dbdir)

    if args.users:
        print("--------------------------")
        print("--- Editing User Names ---")
        print("--------------------------")
        editUserNames(tardis, crypto)
    if args.groups:
        print("---------------------------")
        print("--- Editing Group Names ---")
        print("---------------------------")
        editGroupNames(tardis, crypto)

if __name__ == "__main__":
    main()
