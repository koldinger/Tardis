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

import os

__version__ = "0.26"
__buildversion__ = ''
__versionstring__ = __version__

try:
    parentDir    = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    versionFile   = os.path.join(parentDir, 'info', 'tardisversion')
    __buildversion__ = file(versionFile, 'r').readline().strip()
except:
    try:
        import subprocess
        __buildversion__ = subprocess.check_output(['git', 'describe', '--dirty', '--tags', '--always'], stderr=subprocess.STDOUT).strip()
    except:
        pass

if __buildversion__:
    __versionstring__ = __version__ + ' (' + __buildversion__ + ')'

def __check_features():
    xattr_pkg = 'xattr'
    acl_pkg   = 'pylibacl'
    os_info = os.uname()
    if os_info[0] == 'Linux':
        return [xattr_pkg, acl_pkg]
    elif os_info[0] == 'Darwin':
        return [xattr_pkg]
    else:
        return []
