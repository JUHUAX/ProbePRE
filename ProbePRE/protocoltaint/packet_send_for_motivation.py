import socket
import time
from scapy.all import *
from scapy.all import IP, TCP, Raw, rdpcap

pcap_file = "/home/juhua/experiment/BinPRE/pcap/modbus.pcap"
protocol = "modbus"
ip = "127.0.0.1"
path_all_bbl_count = "/home/juhua/experiment/MY/coverage/all_basic_blocks.log"
path_part_bbl_count = "/home/juhua/experiment/MY/coverage/basic_blocks.log"
path_part_bbl_count_split_with_message = "/home/juhua/experiment/MY/coverage/{}message_part_bbl_count.log"
path_coverage_rate = "/home/juhua/experiment/MY/coverage/coverage_rate.log"

class Message:
    def __init__(self, ip_src, ip_dst, sport, dport, app_data):
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.sport = sport
        self.dport = dport
        self.app_data = app_data

def process_packet(packet, targetport):
    if IP in packet and TCP in packet:    #TCP 
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        srcport = packet[TCP].sport
        destport = packet[TCP].dport
        
        if packet.haslayer(Raw) and (packet.dport == targetport or packet.dport == 502):
            app_data = packet[Raw].load
            message = Message(ip_src, ip_dst, srcport, destport, app_data)
            return message
        
    elif IP in packet and UDP in packet:  #UDP
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        srcport = packet[UDP].sport
        destport = packet[UDP].dport

        if IP in packet and UDP in packet and DNS in packet and destport == targetport:
            app_data = bytes(packet[DNS])
            message = Message(ip_src, ip_dst, srcport, destport, app_data)
            return message
        
        elif IP in packet and UDP in packet and TFTP in packet and destport == targetport:
            app_data = bytes(packet[TFTP])
            message = Message(ip_src, ip_dst, srcport, destport, app_data)
            return message
        
    return None

def print_all_messages(all_messages):
    for message in all_messages:
        print(f"IP Source: {message.ip_src}, IP Destination: {message.ip_dst}")
        print(f"Source Port: {message.sport}, Destination Port: {message.dport}")
        print("Application Layer Data:")
        print(message.app_data)
        print("\n")

def connect(ip, port, isUDP, protocol):
    if isUDP:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.settimeout(2)
    try:
        if protocol == "tftp":
            sock.bind(('', 7788))
        else:
            sock.connect((ip, port))#normal
        
        print("The connection is successful!")
        return sock
    except:
        print("The connection failed!")
        return False

def fileoperate(path, path2):
    with open(path, "r+") as source:
        lines = source.readlines()
    
    with open(path2, 'w+') as target:
        target.writelines(lines)


def get_bbl_count(path):
    count = 0
    with open(path,'r') as f:
        lines = f.readlines()
    for line in lines:
        if "Basic Block" in line:
            count += 1
    return count


def count_coverage_rate(all, part, path, info, last):
    all_count = get_bbl_count(all)
    part_count = get_bbl_count(part)
    with open(path, "a+") as f:
        f.write(info)
        f.write("\n")
        f.write(str(part_count))
        f.write("       +" + str(part_count - last))
        f.write("\n")
        f.write(str(all_count))
        f.write("\n")
        f.write(str(part_count/all_count))
        f.write("\n")
    return part_count

def send_msg(pcap_file, ip, protocol, limit, start):
    print("start sending")
    isUDP = False

    '''Configuration information for the protocol port number. Modify or add as you need.'''
    if protocol == "dnp3":
        port = 20000
    elif protocol == "eip":
        port = 44818
    elif protocol == "modbus":
        #port = 502  
        port = 1502
    elif protocol == "s7":
        port = 102
    elif protocol =="ftp":
        port = 21
    elif protocol =="dns":
        port = 53
        isUDP = True
    elif protocol =="tftp":
        port = 69
        isUDP = True
    elif protocol =="http":
        port = 80
    elif protocol =="unknown":
        port = ""

    all_messages = []
    payload_message = []
    packets = rdpcap(pcap_file)
    for packet in packets:  
        '''Pcap packet parsing. Modify or add as you need.'''
        message = process_packet(packet, port)
        
        if(message is not None):
            all_messages.append(message)
            payload_message.append(message.app_data)

    # print_all_messages(all_messages)

    while 1:
        sock = connect(ip, port, isUDP, protocol)
        if sock: break
        time.sleep(3)

    index = start
    i = limit
    last = 0
    while i and index < len(payload_message):
        try:
            d = payload_message[index]
            sock.send(d) 
            # recv_content = sock.recv(255)
        except IndexError:
            print("Message samples exhausted")
            break
        print("index: {}".format(index))
        print("send {}".format(" ".join(hex(c) for c in d)))
        # print("recv {}".format(" ".join(hex(c) for c in recv_content)))
        time.sleep(3)
        # fileoperate(path_part_bbl_count, path_part_bbl_count_split_with_message.format(index))
        # last = count_coverage_rate(path_all_bbl_count, path_part_bbl_count_split_with_message.format(index), path_coverage_rate, f"{index} message coverage rate", last)

        index += 1
        i -= 1
        return len(payload_message[index])
    