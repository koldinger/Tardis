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

import collections
import time

class Cache(object):
    def __init__(self, size, timeout):
        self.size = size
        self.timeout = timeout
        self.cache = collections.OrderedDict()

    def insert(self, key, value, now=None, timeout=None):
        # Use the regular timeout if it's specified
        if timeout is None:
            timeout = self.timeout

        # If there is a timeout, set the timeout time
        if timeout:
            if now is None:
                now = time.time()
            timeout += now

        self.cache[key] = (value, timeout)
        if self.size != 0 and len(self.cache) > self.size:
            self.cache.popitem(False)
        
    def retrieve(self, key):
        if not key in self.cache:
            return None
        (value, timeout) = self.cache[key]
        if timeout and timeout < time.time():
            del self.cache[key]
            self.flush()
            return None
        return value

    def delete(self, key):
        if key in self.cache:
            del self.cache[key]
    
    def flush(self):
        now = time.time()
        i = self.cache.iteritems()
        z = i.next()
        try:
            while z:
                (key, item) = z
                (value, timeout) = item
                if timeout > now:
                    return
                self.cache.popitem(False)
                z = i.next()
        except:
            # If something goes wrong, just punt.
            pass

    def purge(self):
        self.cache = collection.OrderedDict()

if __name__ == "__main__":
    c = Cache(5, 2)
    for i in range(0, 5):
        c.insert(i, i * 100)
    for i in range(0, 10):
        print i, " :: ", c.retrieve(i)
    print "----"
    for i in range(5, 10):
        c.insert(i, i * 100)
    for i in range(0, 10):
        print i, " :: ", c.retrieve(i)
    time.sleep(2)
    for i in range(0, 10):
        print i, " :: ", c.retrieve(i)
