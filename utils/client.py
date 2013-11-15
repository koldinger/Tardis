import socket
import Messages
import json
import os

#posix.stat_result(st_mode=33204, st_ino=59768888, st_dev=2305L, st_nlink=1, st_uid=1000, st_gid=1000, st_size=392, st_atime=1383689919, st_mtime=1383689918, st_ctime=1383689919)
def fileInfo(name):
    x = os.stat(name)
    y = {}
    y["name"] = name
    y["length"] = x.st_size
    y["mode"]   = x.st_mode
    y["inode"]  = x.st_ino
    y["mtime"]  = x.st_mtime
    y["ctime"]  = x.st_ctime
    y["atime"]  = x.st_atime

def parseMessage(message):
    print message["cksum"]


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", 9999))

m = Messages.JsonMessages(sock)

m.sendMessage("Hi there")
print m.recvMessage()
m.sendMessage("How are you")
m.sendMessage("will you be my friend?")
m.sendMessage("I like turtles")
m.sendMessage("this is a test")
m.sendMessage("this is only a test")
m.sendMessage("had this been an actual emergency, you would have been told to bend over and kiss your ass goodbye")
m.sendMessage("had this been an actual emergency, you would have been told to bend over and kiss your ass goodbye had this been an actual emergency, you would have been told to bend over and kiss your ass goodbye")
parseMessage(m.recvMessage())
parseMessage( m.recvMessage())
parseMessage( m.recvMessage())
parseMessage( m.recvMessage())
parseMessage( m.recvMessage())
parseMessage( m.recvMessage())
x = {}
x["message"] = "DIR"
x["inode"] = 12345
x["files"] = []
x["files"].append(fileInfo("client.py"))
x["files"].append(fileInfo("server.py"))
x["files"].append(fileInfo("Messages.py"))

y = json.dumps(x)
m.sendMessage(y)
parseMessage( m.recvMessage())
parseMessage( m.recvMessage())
m.sendMessage("BYE")
