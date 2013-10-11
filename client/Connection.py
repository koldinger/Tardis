import socket
import json
import uuid

class Connection:
    """ Root class for handling connections to the tardis server """
    def __init__(self, host, port, name, encoding):
        self.stats = { 'messages' : 0, 'bytes': 0 }

        # Create and open the socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, int(port)))

        try:
            # Receive a string.  TARDIS proto=1.0
            message = self.get(256)
            if message != "TARDIS 1.0":
                raise Exception
            message = "BACKUP {} {} {}".format(socket.gethostname(), name, encoding)
            self.put(message)

            message = self.sock.recv(256).strip()
            fields = message.split()
            if len(fields) != 2:
                raise Exception
            if fields[0] != 'OK':
                raise Exception
            self.sessionid = uuid.UUID(fields[1])
        except:
            self.sock.close()
            raise

    def put(self, message):
        self.sock.sendall(message)
        self.stats['messages'] += 1
        self.stats['bytes'] += len(message)
        return

    def get(self, size):
        message = self.sock.recv(size).strip()
        self.stats['messages'] += 1
        self.stats['bytes'] += len(message)
        return message

    def close(self):
        self.put("BYE")
        self.sock.close()

    def getSessionId(self):
        return str(self.sessionid)


class JsonConnection(Connection):
    """ Class to communicate with the Tardis server using a JSON based protocol """
    def __init__(self, host, port, name):
        Connection.__init__(self, host, port, name, 'JSON')

    def send(self, message):
        j = json.dumps(message)
        self.put("{:<10}".format(len(j)))
        self.put(j)

    def receive(self, size):
        message = self.get(size)
        return message

if __name__ == "__main__":
    """ Test Code """
    conn = JsonConnection("localhost", 9999, "HiMom")
    print conn.getSessionId()
    conn.send({ 'x' : 1 })
    print conn.receive(256)
    conn.send({ 'y' : 2 })
    print conn.receive(256)
    conn.close()
