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

import time
import sys
import argparse
import tempfile

import qrcode

from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

import Tardis
from Tardis import Util
from Tardis import Config

def makePdf(output, qrCode, data, client):
    doc = SimpleDocTemplate(output, pagesize=letter,
                            rightMargin=72,leftMargin=72,
                            topMargin=72,bottomMargin=18)
    Story=[]

    im = Image(qrCode, 2*inch, 2*inch)
    Story.append(im)

    Story.append(Spacer(1, 12))


    styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Justify', alignment=TA_JUSTIFY))

    title = time.strftime("Keys for client %%s as of %a, %m/%d/%Y, %H:%M") % client

    Story.append(Paragraph(title, styles["Normal"]))
    Story.append(Spacer(1, 12))

    for line in data.split('\n'):
        Story.append(Paragraph(line, styles["Normal"]))

    doc.build(Story)

def mkQrFile(data):
    qrfile = tempfile.NamedTemporaryFile()
    qrimage = qrcode.make(data)
    qrimage.save(qrfile)
    qrfile.flush()
    return qrfile

def processArgs():
    parser = argparse.ArgumentParser(description='Generate a key backup', fromfile_prefix_chars='@', formatter_class=Util.HelpFormatter, add_help=False)

    (_, remaining) = Config.parseConfigOptions(parser)

    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    parser.add_argument('--output', '-o',   default=None, dest='output', required=True,           help='Output file')

    parser.add_argument('--verbose', '-v',  action='count', default=0, dest='verbose',                  help='Increase the verbosity')
    parser.add_argument('--version',        action='version', version='%(prog)s ' + Tardis.__versionstring__,    help='Show the version')
    parser.add_argument('--help', '-h',     action='help')

    Util.addGenCompletions(parser)

    return parser.parse_args(remaining)

def main():
    args = processArgs()

    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog)
    tardis, _, crypt, client = Util.setupDataConnection(args.repo, password, args.keys)

    (f, c) = crypt.getKeys()
    client = tardis.getConfigValue('ClientID')

    data = Util.mkKeyString(client, f, c)

    qrfile = mkQrFile(data)
    makePdf(args.output, qrfile.name, data, client)
    return 0

if __name__ == "__main__":
    sys.exit(main())
