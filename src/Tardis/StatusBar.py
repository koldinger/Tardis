# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2023, Eric Koldinger, All Rights Reserved.
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
import atexit
import sched

_ansiClearEol = '\x1b[K'
_startOfLine = '\r'
_hideCursor = '\x1b[?25l'
_showCursor = '\x1b[?25h'
_statusBars = []

def fmtSize(num, base=1024, suffixes=None):
    """
    Format into something like 4 ->"4 bytes", 4096 -> "4KB"
    Arguments:
    num:        The number to convert
    base:       The base value for each field, eg base^0, base^1, etc
    formats:    list of formats for each value
    """
    if num is None:
        return 'None'
    if suffixes is None:
        suffixes = ['bytes','KB','MB','GB', 'TB', 'PB', 'EB']
    fmt = "%d %s"
    num = float(num)
    for x in suffixes[:-1]:
        #if num < base and num > -base:
        if -base < num < base:
            return (fmt % (num, x)).strip()
        num /= float(base)
        fmt = "%3.1f %s"
    return (fmt % (num, suffixes[-1])).strip()


def _handle_resize(signal, frame):
    """
    Process a resize event, and change the width of all the status bars
    Parameters ignored.
    """
    (width, _) = shutil.get_terminal_size((80, 32))  # getTerminalSize()
    for sbar in _statusBars:
        sbar.setWidth(width)

class StatusBarFormatter(string.Formatter):
    def __init__(self):
        self.starttime = time.time()

    def get_field(self, field_name, args, kwargs):
        #print(f"get_field({field_name}, {args}, {kwargs}")
        if field_name == "__elapsed__":
            seconds = time.time() - self.starttime
            if seconds > 3600:
                return (time.strftime("%H:%M:%S", time.gmtime(seconds)), field_name)
            return (time.strftime("%M:%S", time.gmtime(seconds)), field_name)
        return super().get_field(field_name, args, kwargs)

    def convert_field(self, value, conversion):
        if conversion == "B":
            return fmtSize(value)

        return super().convert_field(value, conversion)

def resetCursor():
    print(_showCursor, end='')

class StatusBar():
    def __init__(self, base, live=None, formatter=None, delay=0.25, scheduler=None, priority=10):
        if live is None:
            live = {}
        self.base = base
        self.live = live
        self.trailer = None
        self.halt = False
        self.values = {}
        self.delay = delay
        self.formatter = formatter if formatter else StatusBarFormatter()
        self.scheduler = scheduler if scheduler else sched.scheduler()
        self.priority = priority

        (self.width, _) = shutil.get_terminal_size((80, 32))
        _statusBars.append(self)

        _handle_resize(None, None)
        signal.signal(signal.SIGWINCH, _handle_resize)
        signal.siginterrupt(signal.SIGWINCH, False)

        self.event = self.scheduler.enter(self.delay, self.priority, self.printStatus)
        atexit.register(resetCursor)

    def start(self, name="StatusBar"):
        """
        Start the status bar updating
        """
        self.thread = threading.Thread(name=name, target=self.scheduler.run)
        self.thread.setDaemon(True)
        self.thread.start()

    def shutdown(self):
        """
        Stop the status bar from further updating
        """
        self.scheduler.cancel(self.event)
        self.halt = True
        self.clearStatus()
        atexit.unregister(resetCursor)
        if self.thread:
            self.thread.join()

    def pTime(self, seconds):
        """
        Print the time
        """
        if seconds > 3600:
            return time.strftime("%H:%M:%S", time.gmtime(seconds))
        return time.strftime("%M:%S", time.gmtime(seconds))

    def setWidth(self, width):
        """
        Set the width of the status bar
        """
        self.width = width

    def setLiveValues(self, live):
        """
        Set a new dictionary to use for live values
        """
        self.live = live

    def setTrailer(self, trailer):
        """
        Set a trailing field for the status bar
        """
        self.trailer = trailer

    def setValue(self, key, value):
        """
        Set a value to be printed
        key:    The name of the value
        value:  The actual value, most likely an int
        """
        self.values[key] = value

    def setValues(self, values):
        """
        Set a dict of values into the values array
        """
        self.values.update(values)

    def processTrailer(self, length, string):
        """
        Process (shorten) the trailer to length, so things can fit.
        """
        return string[:length]

    def printStatus(self):
        """
        Print the status bar.
        Normally only handled by running thread, not meant to be called externally
        """
        try:
            output = self.formatter.format(self.base, **{**self.live, **self.values}).encode('utf8', 'backslashreplace').decode('utf8')
            if self.trailer:
                output += self.processTrailer(self.width - 2 - len(output), self.trailer)
        except KeyError as k:
            output = "Error generating status message: Missing value for " + str(k)
        except Exception as e:
            output = "Error generating status message: " + str(e)

        try:
            print(output + _ansiClearEol + _startOfLine + _hideCursor, end='', flush=True)
        except Exception:
            print(_ansiClearEol + _startOfLine, end='', flush=True)

        self.event = self.scheduler.enter(self.delay, self.priority, self.printStatus)

    def clearStatus(self):
        """
        Clear the status bar area.   Should only be used after a stop
        """
        print(_showCursor + _startOfLine + _ansiClearEol, end='')


if __name__ == "__main__":
    import os
    import os.path
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
    print("All done")
