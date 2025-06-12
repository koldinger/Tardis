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

import errno
import logging
import queue
import threading

from . import StatusBar


class Messenger:
    def __init__(self, messages, needsData=lambda _: False, maxsize=1024 * 1024, timeout=None):
        self.messages = messages
        self.sendQ = queue.Queue(2048)
        self.recvQ = queue.Queue()
        self.sendlogger = logging.getLogger("Sender")
        self.recvlogger = logging.getLogger("Receiver")
        self.needsData = needsData
        self.maxsize = maxsize
        self.timeout = timeout
        self.stopped = False

        self.senderThread = threading.Thread(daemon=True, target=self._sender, name="Sender")
        self.receiverThread = threading.Thread(daemon=True, target=self._receiver, name="Receiver")

        self.exception = None

        self.sendEnqueued = 0
        self.pbar = None

    def run(self):
        self.senderThread.start()
        self.receiverThread.start()

    def stop(self):
        self.stopped = True
        self.sendQ.shutdown()

    def status(self):
        return (self.stopped, self.senderThread.is_alive(), self.receiverThread.is_alive())

    def _sender(self):
        self.sendlogger.debug("Sender starting")
        try:
            while not self.stopped:
                (mesg, compress, _) = self.sendQ.get()
                if mesg is None:
                    return
                self.messages.sendMessage(mesg, compress)
        except queue.ShutDown:
            pass
        except BaseException as e:
            self.sendlogger.exception("Caught an exception sending message %s", mesg)
            self.exception = e
            raise e

    def _receiver(self):
        self.recvlogger.debug("Receiver starting")
        try:
            while not self.stopped:
                try:
                    mesg = self.messages.recvMessage()
                    if mesg is None:
                        self.recvlogger.critical("'None' Message")
                    self.recvQ.put(mesg)
                except TimeoutError:
                    # Just swallow the timeout error.   We could just be stuck waiting to the server to respond to a large file.
                    self.recvlogger.error("Timeout encountered in recv loop")
        except RuntimeError as e:
            self.recvlogger.error("Caught Runtime error: %s", e)
            self.recvQ.put(e)
        except OSError as e:
            if e.errno == errno.EBADF:
                self.recvQ.shutdown()
        except BaseException as e:
            # Catch EVERYTHING and forward it on
            self.recvlogger.error("Caught exception: %s -- %s", e.__class__.__name__, e)
            if not self.stopped:
                self.recvQ.put(e)
            self.exception = e
            raise e

    def sendMessage(self, message, compress=True):
        if self.exception:
            raise self.exception
        if message is None:
            self.sendlogger.error("Sending None Message")

        self.sendQ.put((message, compress, self.sendEnqueued))

        self.sendEnqueued += 1
        self.reportQueueSizes()

    def recvMessage(self, wait=True, timeout=None):
        if self.exception:
            raise self.exception
        timeout = timeout or self.timeout
        try:
            ret = self.recvQ.get(block=wait, timeout=timeout)
        except queue.Empty:
            return None
        except queue.ShutDown:
            return None

        if isinstance(ret, BaseException):
            raise ret
        self.reportQueueSizes()
        if ret is None:
            self.recvlogger.critical("None value returned")

        return ret

    def reportQueueSizes(self):
        if self.pbar:
            s = self.sendQ.qsize()
            r = self.recvQ.qsize()
            self.pbar.setValues({"sendQ": s, "recvQ": r})

    def setProgressBar(self, pbar: StatusBar.StatusBar):
        self.pbar = pbar

    def encode(self, data):
        return self.messages.encode(data)

    def decode(self, data):
        return self.messages.decode(data)

if __name__ == "__main__":
    import time
    logging.basicConfig(level=logging.DEBUG)
    log = logging.getLogger("main")

    class TestJig:
        encode = None
        q = queue.SimpleQueue()

        def sendMessage(self, message, compress=True):
            self.q.put(message)

        def recvMessage(self):
            return self.q.get()

    jig = TestJig()

    m = Messenger(jig)
    m.run()
    time.sleep(1)
    for i in range(0, 20):
        m.sendMessage({"value": i})

    for i in range(0, 20):
        print(m.recvMessage(wait=True))
