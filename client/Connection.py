import socket
import json
import uuid
import sys
import time

sys.path.append("../utils")

import Messages

class Connection(object):
    lastTimestamp = None
    """ Root class for handling connections to the tardis server """
    def __init__(self, host, port, name, encoding, priority=0):
        self.stats = { 'messages' : 0, 'bytes': 0 }

        # Create and open the socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, int(port)))

        try:
            # Receive a string.  TARDIS proto=1.0
            message = self.get(10)
            if message != "TARDIS 1.0":
                raise Exception
            message = "BACKUP {} {} {} {} {}".format(socket.gethostname(), name, encoding, priority, time.time())
            self.put(message)

            message = self.sock.recv(256).strip()
            fields = message.split()
            if len(fields) != 3:
                print message
                raise Exception
            if fields[0] != 'OK':
                raise Exception
            self.sessionid = uuid.UUID(fields[1])
            self.lastTimestamp = float(fields[2])
        except:
            self.sock.close()
            raise

    def put(self, message):
        self.sock.sendall(message)
        self.stats['messages'] += 1
        self.stats['bytes'] += len(message)
        return

    def recv(n):
        msg = ''
        while len(msg) < n:
            chunk = self.sock.recv(n-len(msg))
            if chunk == '':
                raise RuntimeError("socket connection broken")
            msg = msg + chunk
        return msg

    def get(self, size):
        message = self.sock.recv(size).strip()
        self.stats['messages'] += 1
        self.stats['bytes'] += len(message)
        return message

    def close(self):
        self.sock.close()

    def getSessionId(self):
        return str(self.sessionid)

    def getLastTimestap(self):
        return self.lastTimestamp

class ProtocolConnection(Connection):
    sender = None
    def __init__(self, host, port, name, protocol):
        Connection.__init__(self, host, port, name, protocol)

    def send(self, message):
        self.sender.sendMessage(message)

    def receive(self):
        return self.sender.recvMessage()

    def close(self):
        self.sender.sendMessage({"message" : "BYE" })
        super(ProtocolConnection, self).close()

    def encode(self, string):
        return self.sender.encode(string)

    def decode(self, string):
        return self.sender.decode(string)

class JsonConnection(ProtocolConnection):
    """ Class to communicate with the Tardis server using a JSON based protocol """
    def __init__(self, host, port, name):
        ProtocolConnection.__init__(self, host, port, name, 'JSON')
        # Really, cons this up in the connection, but it needs access to the sock parameter, so.....
        self.sender = Messages.JsonMessages(self.sock)

class BsonConnection(ProtocolConnection):
    def __init__(self, host, port, name):
        ProtocolConnection.__init__(self, host, port, name, 'BSON')
        # Really, cons this up in the connection, but it needs access to the sock parameter, so.....
        self.sender = Messages.BsonMessages(self.sock)

class NullConnection(Connection):
    def __init__(self, host, port, name):
        pass

    def send(self, message):
        print json.dumps(message)

    def receive(self):
        return None

if __name__ == "__main__":
    """ Test Code """
    conn = JsonConnection("localhost", 9999, "HiMom")
    print conn.getSessionId()
    conn.send({ 'x' : 1 })
    print conn.receive()
    conn.send({ 'y' : 2 })
    print conn.receive()
    conn.close()
