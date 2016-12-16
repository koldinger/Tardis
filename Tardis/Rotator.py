# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2016, Eric Koldinger, All Rights Reserved.
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

import shutil
import logging
import os
import os.path
import time
import gzip

class Rotator(object):
    def __init__(self, rotations=5, compress=32 * 1024):
        self.logger = logging.getLogger("Rotator")
        self.rotations = rotations
        self.compress = compress

    def backup(self, name):
        with file(name, 'rb') as infile:
            newname = name + "." +  time.strftime("%Y%m%d-%H%M%S")
            stat = os.stat(name)
            if self.compress and stat.st_size >= self.compress:
                newname += '.gz'
                self.logger.debug("Compressing %s to %s", name, newname)
                outfile = gzip.open(newname, "wb")
            else:
                self.logger.debug("Copying %s to %s", name, newname)
                outfile = file(newname, 'wb')
            try:
                shutil.copyfileobj(infile, outfile)
            finally:
                outfile.close()

    def rotate(self, name):
        d, f = os.path.split(os.path.abspath(name))
        prefix = f + '.'
        files = [i for i in os.listdir(d) if i.startswith(prefix)]
        self.logger.debug("Rotating %d files: %s", len(files), str(files))
        files = sorted(files, reverse=True)
        toDelete = files[self.rotations:]
        for i in toDelete:
            name = os.path.join(d, i)
            self.logger.debug("Deleting %s", name)
            os.remove(name)
