import socket
from scapy.all import *


def connect(ip, port, isUDP):
    if isUDP:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.settimeout(2)
    try:
        sock.connect((ip, port))#normal
        
        print("The connection is successful!")
        return sock
    except:
        print(port)
        print("The connection failed!")
        return False
    
def send_msg(ip, payload, protocol, isUDP):
    print("start sending")
    
    if protocol == "Enip":
        port = 44818
    elif protocol == "Libmodbus":
        port = 1502
    elif protocol == "Freemodbus":
        port = 502  
    elif protocol == "S7comm":
        port = 102
    elif protocol == "Iec104":
        port = 2404
    elif protocol == "Cip":
        port = 44818
    elif protocol == "Bacnet":
        port = 47808
    elif protocol == "Ftp":
        port = 8487
    elif protocol == "Dnp3":
        port = 20000

    reboot = False
    sock = connect(ip, port, isUDP)
    if sock: 
        sock.send(bytes(payload)) ## payload是报文列表形如[0x01, 0x11, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01]
        # recv = sock.recv(255)
        # print("send {}".format(" ".join(hex(c) for c in payload)))
        # print("recv {}".format(" ".join(hex(c) for c in recv)))
        return payload
    else:
        reboot = True
        return reboot