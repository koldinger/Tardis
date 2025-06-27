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

import sched
import threading
import time


class ThreadedScheduler(sched.scheduler):
    def __init__(self, timefunc=time.monotonic, delayfunc=time.sleep):
        super().__init__(timefunc, delayfunc)

    def start(self, name="EventScheduler"):
      self.thread = threading.Thread(name=name, target=self.run)
      self.thread.setDaemon(True)
      self.thread.start()

    def shutdown(self):
        while not self.empty():
            try:
                self.cancel(self.queue[0])
            except:
                pass


if __name__ == "__main__":
    def print_time(a="default"):
        print("From print_time", time.time(), a)

    x = ThreadedScheduler()
    print("Starting")
    x.enter(10, 1, print_time, (10,))
    x.start()
    x.enter(5, 2, print_time, argument=("positional",))
    x.enter(5, 1, print_time, (5,))
    x.enter(15, 3, print_time, (15,))
    x.enter(25, 3, print_time, (25,))
    x.enter(30, 3, print_time, (30,))
    time.sleep(20)
