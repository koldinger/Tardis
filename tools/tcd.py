#! /usr/bin/env python3
# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2022, Eric Koldinger, All Rights Reserved.
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

import os
import os.path
import sys
import pprint
import parsedatetime
import datetime
import re

usage = \
"""'target' can be a name of a backup set, a date or relative day, or a relative number of sets (+3, -1)
Examples:
    tcd -1              - Change to the previous backup set
    tcd +3              - Change 3 backup sets forward
    tcd "last week"     - Change to a backup set from a week ago.
    tcd Current         - Change to the current backup set.
    tcd Monthly-2022-01 - Change to the backup set namely "Monthly-2022-01" """

def findMount(path):
    origpath = os.path.realpath(path)
    path = origpath
    while path is not '/':
        path, f = os.path.split(path)
        if os.path.ismount(path):
            return path, f
        #if os.path.basename(path) == 'TardisFS':
        #    return path, f
    raise Exception(f"No mountpoint found in {origpath}")

def findByName(name, bSets):
    x = filter(lambda x: x.name == name, bSets)
    return next(x, None)

def findByTime(theTime, bSets):
    x = filter(lambda y: int(y.stat().st_mtime) < theTime, bSets)
    x = sorted(x, key=lambda y: y.stat().st_mtime, reverse=True)
    if x:
        return x[0]
    else:
        raise Exception("No best time found")

def findRelative(expr, current, bSets):
    names = [x.name for x in bSets if not x.is_symlink()]
    pos = names.index(current)
    newPos = eval(f"{pos} {expr}")
    if newPos < 0 or newPos >= len(names):
        raise Exception(f"{newPos} ({expr}) is out of range")
    return findByName(names[newPos], bSets)

def main():
    # Make sure the usage makes sense
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} target", file=sys.stderr)
        print(usage, file=sys.stderr)
        raise Exception("Usage")

    # Get the target
    target = sys.argv[1]

    # Find the root of the system
    root, current = findMount('.')

    # And where we are in the system
    me = os.path.relpath('.', start=os.path.join(root, current))

    #allSets = list(os.scandir(root))
    allSets = sorted(os.scandir(root), key=lambda x: x.stat().st_mtime)

    # Check if we're of the form +/-Number
    relative = re.match('[-+]\d+$', target)
    if relative:
        x = findRelative(target, current, allSets)
        print(os.path.join(x.path, me))
        sys.exit(0)

    # Else, see if this name exists
    x = findByName(target, allSets)
    if x:
        #print(f"Found target {target} -- {x}")
        print(os.path.realpath(os.path.join(x.path, me)))
        sys.exit(0)

    # Or perhaps we're a date
    cal = parsedatetime.Calendar()
    val, success = cal.parse(target)
    if success:
        timestamp = datetime.datetime(*val[:7]).timestamp()
        x = findByTime(timestamp, allSets)
        if x:
            #print(f"Found time {timestamp} -- {x} {x.stat().st_mtime}")
            print(os.path.join(x.path, me))
            sys.exit(0)
    else:
        raise Exception(f"Can't parse date: {target}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
