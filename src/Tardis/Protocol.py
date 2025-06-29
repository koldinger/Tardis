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

from enum import auto

from strenum import UppercaseStrEnum


class Commands(UppercaseStrEnum):
    BACKUP = auto()
    DIR = auto()
    DHSH = auto()
    SGR = auto()
    SGS = auto()
    SIG = auto()
    DEL = auto()
    CON = auto()
    CKS = auto()
    CLN = auto()
    BATCH = auto()
    PRG = auto()
    CLICONFIG = auto()
    COMMANDLINE = auto()
    META = auto()
    METADATA = auto()
    SETKEYS = auto()
    AUTH1 = auto()
    AUTH2 = auto()
    DONE = auto()

class Responses(UppercaseStrEnum):
    ACKDIR = auto()
    ACKCLN = auto()
    ACKPRG = auto()
    ACKSUM = auto()
    ACKMETA = auto()
    ACKMETADATA = auto()
    ACKDHSH = auto()
    ACKCLICONFIG = auto()
    ACKCMDLN = auto()
    ACKDONE = auto()
    ACKBTCH = auto()
    ACKBACKUP = "INIT"
    ACKSETKEYS = auto()
    ACKCON = auto()
    ACKDEL = auto()
    ACKSIG = auto()
    ACKSGR = "SIG"
    NEEDKEYS = auto()
    AUTH = auto()
