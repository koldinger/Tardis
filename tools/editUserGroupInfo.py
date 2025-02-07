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
import json

import pwd
import grp

from dataclasses import dataclass, asdict

from Tardis import Util, Config

logger = None

@dataclass
class Entry:
    current: str|None
    proposed: str|None
    nameid: int
    recordId: int
    old: str|None

def myinput(prompt="", default=None, validate=lambda _: True, errmesg="Invalid input"):
    while True:
        x = input(prompt)
        if not x:
            x = default
        if validate(x):
            return x
        print(errmesg)

def checkName(name):
    return re.match(r"^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)$", name)

def printData(data):
    print(f"{'Key':4}: {'ID':5}: {'System Name':20} {'Current Name':20}")
    for k, v in sorted(data.items()):
        print(f"{k:4}: {v.recordId:5}: {(v.proposed or ''):20} {(v.current or ''):20}")

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
                    value = myinput("Enter new name: ", default=entry.current, validate=checkName, errmesg="").strip()
                    entry.current = value
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
        print("Note: ID May be the User/Group ID, especially if the current ID is blank or not appopriate")
        key = input("Line to edit (S to use all system names, C to use all current names, U to set unknown names, Q to quit, W to write and quit): ").strip()

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
            case 'u':
                value = myinput("Name for unknown values: ", default='unknown', validate=checkName)
                for entry in data.values():
                    if not entry.current:
                        entry.current = value
            case 'x':
                filename = input("Enter filename: ")
                print(data)
                with open(filename, "w") as f:
                    json.dump(list(map(asdict, data.values())), f)
            case 'l':
                filename = input("Enter filename: ")
                with open(filename, "r") as f:
                    vals = json.load(f)
                    data = data | vals
                
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
        curname = i['Name']
        try:
            if curname:
                curname = crypt.decryptName(curname)
        except Exception as e:
            print(f"Couldn't decrypt {curname} {e}")
        userId = i['UserId']
        #print(f"{userId} {curname} {proposed}")
        data[userId] = Entry(curname, proposed, userId, i['NameId'], curname)

    data = editData(data)
    if data:
        for key, value in data.items():
            tardis.setUserInfo(key, crypt.encryptName(value.current or ''))

def editGroupNames(tardis, crypt):
    groups = list(tardis.getGroups())
    data = {}
    for i in groups:
        try:
            grpEntry = grp.getgrgid(i['NameId'])
            proposed = grpEntry[0]
        except: 
            proposed = None
        curname = i['Name']
        try:
            if curname:
                curname = crypt.decryptName(curname)
        except Exception as e:
            print(f"Couldn't decrypt {curname} {e}")
        grpId = i['GroupId']
        #print(f"{grpId} {curname} {proposed}")
        data[grpId] = Entry(curname, proposed, grpId, i['NameId'], curname)

    data = editData(data)
    if data:
        for key, value in data.items():
            tardis.setGroupInfo(key, crypt.encryptName(value.current or ''))

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
            print("")

    if args.groups:
        print("---------------------------")
        print("--- Editing Group Names ---")
        print("---------------------------")
        editGroupNames(tardis, crypto)

if __name__ == "__main__":
    main()
