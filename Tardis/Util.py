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
import Messages
import Connection
import hashlib
import StringIO
from functools import partial

import pycurl

import logging

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
    if path == None or len(path) <= width:
        return path

    width -= 8
    while len(path) > width:
        try:
            head, path = str.split(path, os.sep, 1)
        except:
            break
    return ".../" + path

def getPassword(password, pwfile, pwurl):
    methods = 0
    if password: methods += 1
    if pwfile:   methods += 1
    if pwurl:    methods += 1

    if methods > 1:
        raise Exception("Cannot specify more than one password retrieval mechanism")

    if pwfile:
        with open(pwfile, "r") as f:
            password = f.readline()

    if pwurl:
        buffer = StringIO.StringIO()
        c = pycurl.Curl()
        c.setopt(c.URL, pwurl)
        c.setopt(c.WRITEDATA, buffer)
        c.perform()
        c.close()
        password = buffer.getvalue()

    return password

def sendData(sender, file, encrypt, chunksize=16536, checksum=False):
    """ Send a block of data """
    # logger = logging.getLogger('Data')
    if isinstance(sender, Connection.Connection):
        sender = sender.sender
    num = 0
    size = 0
    status = "OK"
    ck = None

    if checksum:
        m = hashlib.md5()
    try:
        for chunk in iter(partial(file.read, chunksize), ''):
            if checksum:
                m.update(chunk)
            data = sender.encode(encrypt(chunk))
            chunkMessage = { "chunk" : num, "data": data }
            sender.sendMessage(chunkMessage)
            x = len(chunk)
            size += x
            num += 1
    except Exception as e:
        status = "Fail"
        raise e
    finally:
        message = { "chunk": "done", "size": size, "status": status }
        # logger.debug("Sent %d chunks, %d bytes", num, size);
        if checksum:
            ck = m.hexdigest()
            message["checksum"] = ck
        sender.sendMessage(message)
    return size, ck

def receiveData(receiver, output):
    # logger = logging.getLogger('Data')
    if isinstance(receiver, Connection.Connection):
        receiver = receiver.sender
    bytesReceived = 0
    checksum = None
    while True:
        chunk = receiver.recvMessage()
        # logger.debug("Chunk: %s", str(chunk))
        if chunk['chunk'] == 'done':
            status = chunk['status']
            size   = chunk['size']
            if 'checksum' in chunk:
                checksum = chunk['checksum']
            break
        bytes = receiver.decode(chunk["data"])
        if output:
            output.write(bytes)
            output.flush()
        bytesReceived += len(bytes)

    return (bytesReceived, status, size, checksum)
