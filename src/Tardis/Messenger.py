# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2024, Eric Koldinger, All Rights Reserved.
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

import queue
import threading
import logging
import tempfile

from . import log
from . import StatusBar
from . import Util

class Messenger:
    def __init__(self, messages, needsData=lambda _: False, maxsize=1024 * 1024, timeout=None):
        self.messages = messages
        self.sendQ = queue.Queue()
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

        self.encode = messages.encode

        self.sendEnqueued = 0
        self.pbar = None

    def run(self):
        self.senderThread.start()
        self.receiverThread.start()

    def stop(self):
        self.stopped = True

    def status(self):
        return (self.stopped, self.senderThread.is_alive(), self.receiverThread.is_alive())

    def _msgid(self, msg, t='msgid'):
        if isinstance(msg, dict):
            return msg.get(t, -1)
        return 'data'

    def _sender(self):
        self.sendlogger.debug("Sender starting")
        try:
            while not self.stopped:
                (mesg, compress, _) = self.sendQ.get()
                #self.sendlogger.info("Dequeued Sending Message: Queue size %d", self.sendQ.qsize())
                if mesg is None:
                    return
                #if not raw:
                #    self.sendlogger.info("Sending message: %s %s %s", mesg, compress, raw)
                self.messages.sendMessage(mesg, compress)
        except BaseException as e:
            self.sendlogger.exception("Caught an exception sending message %s", mesg)
            self.exception = e
            raise e

    def _receiver(self):
        self.recvlogger.debug("Receiver starting")
        try:
            while not self.stopped:
                data = None
                mesg = self.messages.recvMessage()
                self.recvQ.put((mesg, data))
        except RuntimeError as e:
            self.recvlogger.info("Caught Runtime error: %s", e)
            self.recvQ.put((None, None))
        except BaseException as e:
            # Catch EVERYTHING and forward it on
            self.recvlogger.error("Caught exception: %s -- %s", e.__class__.__name__, e)
            if not self.stopped:
                self.recvQ.put((e, None))
            self.exception = e
            raise e

    def sendMessage(self, message, compress=True):
        if self.exception:
            raise self.exception

        #self.sendlogger.info("Enqueuing message: %s %s %s", str(message)[:64], compress, raw)
        self.sendQ.put((message, compress, self.sendEnqueued))

        self.sendEnqueued += 1
        self.reportQueueSizes()
        #self.sendlogger.info("Inserted Sending Message.  Queue Size: %d", self.sendQ.qsize())

    def recvMessage(self, wait=False, timeout=None):
        if self.exception:
            raise self.exception
        timeout = timeout or self.timeout
        try:
            ret = self.recvQ.get(block=wait, timeout=timeout)
        except queue.Empty:
            return None
        #self.recvlogger.info("Dequeued Received Message: Queue size %d", self.recvQ.qsize())
        if isinstance(ret, BaseException):
            raise ret
        if ret is None:
            raise OSError("Socket closed")
        self.reportQueueSizes()
        return ret[0]

    def reportQueueSizes(self):
        if self.pbar:
            s = self.sendQ.qsize()
            r = self.recvQ.qsize()
            self.pbar.setValues({ "sendQ": s, "recvQ": r})

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
        m.sendMessage({ "value": i})

    for i in range(0, 20):
        print(m.recvMessage(wait=True))
