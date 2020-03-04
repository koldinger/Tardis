# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2019, Eric Koldinger, All Rights Reserved.
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

import threading
import time
import signal
import shutil
import string

_ansiClearEol = '\x1b[K'
_startOfLine = '\r'
_statusBars = []

def fmtSize(num, base=1024, formats = ['bytes','KB','MB','GB', 'TB', 'PB']):
    fmt = "%d %s"
    if num is None:
        return 'None'
    num = float(num)
    for x in formats:
        #if num < base and num > -base:
        if -base < num < base:
            return (fmt % (num, x)).strip()
        num /= float(base)
        fmt = "%3.1f %s"
    return (fmt % (num, 'EB')).strip()


def _handle_resize(sig, frame):
    (width, _) = shutil.get_terminal_size((80, 32))  # getTerminalSize()
    for i in _statusBars:
        i.setWidth(width)

class StatusBarFormatter(string.Formatter):
    def __init__(self):
        self.starttime = time.time()

    def get_field(self, field_name, args, kwargs):
        #print(f"get_field({field_name}, {args}, {kwargs}")
        if field_name == "__elapsed__":
            seconds = time.time() - self.starttime
            if seconds > 3600:
                return (time.strftime("%H:%M:%S", time.gmtime(seconds)), field_name)
            else:
                return (time.strftime("%M:%S", time.gmtime(seconds)), field_name)
        else:
            return super().get_field(field_name, args, kwargs)

    def convert_field(self, value, conversion):
        if conversion == "B":
            return fmtSize(value)
        else:
            return super().convert_field(value, conversion)


class StatusBar():
    def __init__(self, base, live={}, formatter=None):
        self.base = base
        self.live = live
        self.trailer = None
        self.halt = False
        self.values = {}
        if formatter:
            self.formatter = formatter
        else:
            self.formatter = StatusBarFormatter()

        (width, _) = shutil.get_terminal_size((80, 32))

        _statusBars.append(self)

        _handle_resize(None, None)
        signal.signal(signal.SIGWINCH, _handle_resize)
        signal.siginterrupt(signal.SIGWINCH, False)

    def run(self, delay=0.25):
        starttime = time.time()
        self.halt = False
        while not self.halt:
            time.sleep(delay)
            self.printStatus()

    def start(self, delay=0.25, name="StatusBar"):
        thread = threading.Thread(name=name, target=self.run, args=(delay,))
        thread.setDaemon(True)
        thread.start()

    def shutdown(self):
        self.halt = True
        self.clearStatus()
        pass

    def pTime(self, seconds):
        if seconds > 3600:
            return time.strftime("%H:%M:%S", time.gmtime(seconds))
        else:
            return time.strftime("%M:%S", time.gmtime(seconds))

    def setWidth(self, width):
        self.width = width

    def setLiveValues(self, live):
        self.live = live

    def setTrailer(self, trailer):
        self.trailer = trailer

    def setValue(self, key, value):
        self.values[key] = value

    def setValues(self, values):
        self.values.update(values)

    def processTrailer(self, length, s):
        return s[:length]

    def printStatus(self):
        try:
            output = self.formatter.format(self.base, **{**self.live, **self.values})
            if self.trailer:
                output += self.processTrailer(self.width - len(output), self.trailer)
        except KeyError as k:
            output = "Error generating status message: Missing value for " + str(k)
        except Exception as e:
            output = "Error generating status message: " + str(e)

        print(output + _ansiClearEol + _startOfLine, end='', flush=True)

    def clearStatus(self):
        print(' ' +  _startOfLine + _ansiClearEol + _startOfLine, end=' ')



if __name__ == "__main__":
    import os, os.path
    myargs = {"files": 0}
    sb = StatusBar("{__elapsed__} :: Files: {files} Delta: {delta}: {amount!B} {mode} --> ", myargs)
    sb.setValue("mode", "Testing")
    sb.start()
    files = os.listdir(".")
    for i in range(0, 20):
        time.sleep(1.5)
        myargs["files"] = i
        myargs["delta"] = int(i / 3)
        sb.setTrailer(os.path.realpath(files[i % len(files)]))
        sb.setValue("mode", "Running" if i % 2 == 0 else "Walking")
        sb.setValue("amount", i * 1000000)
    sb.shutdown()


