import socket
import json
import uuid
import sys
import time
import Messages
import ssl

class Connection(object):
    lastTimestamp = None
    """ Root class for handling connections to the tardis server """
    def __init__(self, host, port, name, encoding, priority, use_ssl=False, hostname=None):
        self.stats = { 'messagesRecvd': 0, 'messagesSent' : 0, 'bytesRecvd': 0, 'bytesSent': 0 }


        if hostname is None:
            hostname = socket.gethostname()

        # Create and open the socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, int(port)))
        if use_ssl:
            self.sock = ssl.wrap_socket(sock)
        else:
            self.sock = sock

        try:
            # Receive a string.  TARDIS proto=1.0
            message = self.get(10)
            if message != "TARDIS 1.0":
                raise Exception
            message = "BACKUP {} {} {} {} {}".format(hostname, name, encoding, priority, time.time())
            self.put(message)

            message = self.sock.recv(256).strip()
            fields = message.split()
            if len(fields) != 3:
                print message
                raise Exception("Unexpected response: {}".format(message))
            if fields[0] != 'OK':
                raise Exception
            self.sessionid = uuid.UUID(fields[1])
            self.lastTimestamp = float(fields[2])
        except:
            self.sock.close()
            raise

    def put(self, message):
        self.sock.sendall(message)
        self.stats['messagesSent'] += 1
        self.stats['bytesSent'] += len(message)
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
        self.stats['messagesRecvd'] += 1
        self.stats['bytesRecvd'] += len(message)
        return message

    def close(self):
        self.sock.close()

    def getSessionId(self):
        return str(self.sessionid)

    def getLastTimestap(self):
        return self.lastTimestamp

class ProtocolConnection(Connection):
    sender = None
    def __init__(self, host, port, name, protocol, priority, use_ssl, hostname):
        Connection.__init__(self, host, port, name, protocol, priority, use_ssl, hostname)

    def send(self, message):
        self.stats['messagesSent'] += 1
        self.stats['bytesSent'] += len(message)
        self.sender.sendMessage(message)

    def receive(self):
        self.stats['messagesRecvd'] += 1
        message = self.sender.recvMessage()
        self.stats['bytesRecvd'] += len(message)
        return message

    def close(self):
        self.send({"message" : "BYE" })
        super(ProtocolConnection, self).close()

    def encode(self, string):
        return self.sender.encode(string)

    def decode(self, string):
        return self.sender.decode(string)

class JsonConnection(ProtocolConnection):
    """ Class to communicate with the Tardis server using a JSON based protocol """
    def __init__(self, host, port, name, priority=0, use_ssl=False, hostname=None):
        ProtocolConnection.__init__(self, host, port, name, 'JSON', priority, use_ssl, hostname)
        # Really, cons this up in the connection, but it needs access to the sock parameter, so.....
        self.sender = Messages.JsonMessages(self.sock)

class BsonConnection(ProtocolConnection):
    def __init__(self, host, port, name, priority=0, use_ssl=False, hostname=None):
        ProtocolConnection.__init__(self, host, port, name, 'BSON', priority, use_ssl, hostname)
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
