# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2014, Eric Koldinger, All Rights Reserved.
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
import logging
import argparse
import sys
import subprocess
import hashlib
import shlex
import StringIO
import getpass

import Messages
import Connection
import CompressedBuffer
from functools import partial

import pycurl


def fmtSize(num, base=1024):
    fmt = "%d %s"
    for x in ['bytes','KB','MB','GB']:
        #if num < base and num > -base:
        if -base < num < base:
            return fmt % (num, x)
        num /= base
        fmt = "%3.1f %s"
    return fmt % (num, 'TB')

def getIntOrNone(config, section, name):
    try:
        return config.getint(section, name)
    except:
        return None

def shortPath(path, width=80):
    """ Compress a path to only show the last elements if it's wider than specified.
    Replaces early elements with ".../"
    """
    if path == None or len(path) <= width:
        return path

    width -= 8
    while len(path) > width:
        try:
            head, path = str.split(path, os.sep, 1)
        except:
            break
    return ".../" + path

def getPassword(password, pwfile, pwurl, pwprog):
    methods = 0
    if password: methods += 1
    if pwfile:   methods += 1
    if pwurl:    methods += 1
    if pwprog:   methods += 1

    if methods > 1:
        raise Exception("Cannot specify more than one password retrieval mechanism")

    if password == True:
        password = getpass.getpass()
        password.rstrip()       # Delete trailing characters

    if pwfile:
        with open(pwfile, "r") as f:
            password = f.readline().rstrip()

    if pwurl:
        buffer = StringIO.StringIO()
        c = pycurl.Curl()
        c.setopt(c.URL, pwurl)
        c.setopt(c.WRITEDATA, buffer)
        c.perform()
        c.close()
        password = buffer.getvalue().rstrip()

    if pwprog:
        args = shlex.split(pwprog)
        output =subprocess.check_output(args)
        password = output.split('\n')[0].rstrip()

    return password

def sendData(sender, file, encrypt, chunksize=16536, checksum=False, compress=False, stats=None):
    """ Send a block of data, optionally encrypt and/or compress it before sending """
    #logger = logging.getLogger('Data')
    if isinstance(sender, Connection.Connection):
        sender = sender.sender
    num = 0
    size = 0
    status = "OK"
    ck = None

    if compress:
        stream = CompressedBuffer.CompressedBufferedReader(file, checksum=checksum)
    else:
        stream = CompressedBuffer.BufferedReader(file, checksum=checksum)

    try:
        for chunk in iter(partial(stream.read, chunksize), ''):
            data = sender.encode(encrypt(chunk))
            chunkMessage = { "chunk" : num, "data": data }
            sender.sendMessage(chunkMessage)
            num += 1
    except Exception as e:
        status = "Fail"
        #print e
        raise e
    finally:
        size = stream.size()
        compressed = stream.isCompressed()
        if stats and 'dataSent' in stats:
            if compressed:
                stats['dataSent'] += stream.compsize()
            else:
                stats['dataSent'] += size
        message = { "chunk": "done", "size": size, "status": status, "compressed": compressed }
        if checksum:
            ck = stream.checksum()
            message["checksum"] = ck
        #print message
        sender.sendMessage(message)
    return size, ck

def receiveData(receiver, output):
    """ Receive a block of data from the sender, and store it in the specified file.
    Collect some info sent, and return it.
    """
    # logger = logging.getLogger('Data')
    if isinstance(receiver, Connection.Connection):
        receiver = receiver.sender
    bytesReceived = 0
    checksum = None
    compressed = False
    while True:
        chunk = receiver.recvMessage()
        #print chunk
        # logger.debug("Chunk: %s", str(chunk))
        if chunk['chunk'] == 'done':
            status = chunk['status']
            size   = chunk['size']
            if 'checksum' in chunk:
                checksum = chunk['checksum']
            if 'compressed' in chunk:
                compressed = chunk['compressed']
            break
        bytes = receiver.decode(chunk["data"])
        if output:
            output.write(bytes)
            output.flush()
        bytesReceived += len(bytes)

    return (bytesReceived, status, size, checksum, compressed)

"""
Class to handle options of the form "--[no]argument" where you can specify --noargument to store a False,
or --argument to store a true.
"""
class StoreBoolean(argparse.Action):
    def __init__(self, option_strings, dest, negate="no", nargs=0, **kwargs):
        if nargs is not 0:
            raise ValueError("nargs not allowed")
        if len(option_strings) > 1:
            raise ValueError("Multiple option strings not allowed")
        self.negative_option = "--" + negate + option_strings[0][2:]
        self.help_option = "--[" + negate + "]" + option_strings[0][2:]
        option_strings.append(self.negative_option)
        super(StoreBoolean, self).__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, args, values, option_string=None):
        #print "Here: ", option_string, " :: ", self.option_strings
        if option_string == self.negative_option:
            value = False
        else:
            value = True
        setattr(args, self.dest, value)

"""
Class to handle toggling options.  -x = true -xx = false -xxx = true, etc
"""
class Toggle(argparse.Action):
    def __init__(self,
                 option_strings,
                 dest,
                 default=None,
                 required=False,
                 help=None):
        super(Toggle, self).__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=0,
            default=default,
            required=required,
            help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        new_value = not argparse._ensure_value(namespace, self.dest, False)
        setattr(namespace, self.dest, new_value)

"""
Help formatter to handle the StoreBoolean options.
Only handles overriding the basic HelpFormatter class.
"""
class HelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action):
        #print "_format_action_invocation", str(action)
        if hasattr(action, 'help_option'):
            ret = action.help_option
        else:
            ret = super(HelpFormatter, self)._format_action_invocation(action)
        #print "Got ", ret
        return ret

"""
'Test' code
"""

if __name__ == "__main__":
    p = argparse.ArgumentParser(formatter_class=MyHelpFormatter)

    p.add_argument("--doit", action=StoreBoolean, help="Yo mama")
    p.add_argument("-x", action=Toggle, help="Whatever")

    args = p.parse_args()
    print args
