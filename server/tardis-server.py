#! /usr/bin/python

import argparse
import os
import sys
import ConfigParser
import SocketServer
import uuid

class TardisServerHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall("TARDIS 1.0")
            message = self.request.recv(256).strip()
            print message
            fields = message.split()
            if (len(fields) != 4 or fields[0] != 'BACKUP'):
                self.request.sendall("FAIL")
                raise Exception
            host = fields[1]
            name = fields[2]

            sessionid = uuid.uuid1()

            self.request.sendall("OK {}".format(str(sessionid)))

            done = False;

            while not done:
                message = self.request.recv(16 * 1024)             # TODO: Change this 
                print message
                if message == "BYE":
                    done = True
                else:
                    self.request.sendall("ACK");

        finally:
            self.request.close()


defaultConfig = './tardis-server.cfg'

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Tardis Backup Server')

    parser.add_argument('--config', dest='config', default=defaultConfig, help="Location of the configuration file")
    parser.add_argument('--single', dest='single', action='store_true', help='Run a single transaction and quit')
    parser.add_argument('--verbose', '-v', action='count', dest='verbose', help='Increase the verbosity')
    parser.add_argument('--version', action='version', version='%(prog)s 0.1', help='Show the version')

    args = parser.parse_args()
    print args

    configDefaults = {
        'Port' : '9999',
        'BaseDir' : '.',
        'Verbose' : str(args.verbose)
    }

    config = ConfigParser.ConfigParser(configDefaults)
    config.read(args.config)


    print config.get('DEFAULT', 'Port')
    print config.get('DEFAULT', 'BaseDir')
    print config.get('DEFAULT', 'Verbose')

    server = SocketServer.TCPServer(("localhost", config.getint('DEFAULT', 'Port')), TardisServerHandler)

    server.serve_forever()

