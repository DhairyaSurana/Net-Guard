import sys
import socket
import dpkt

from dpkt.ip import IP
from dpkt.tcp import TCP

def inet_to_str(inet):
    
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def contains_SYN(segment):
    return segment.flags & dpkt.tcp.TH_SYN 

def contains_ACK(segment):
    return segment.flags & dpkt.tcp.TH_ACK 

def print_suspect_hosts(hosts):
   
    for ip in hosts:
        syn_count = hosts[ip]["SYN"]
        synack_count = hosts[ip]["SYN-ACK"]
       
        if(syn_count > synack_count * 3):
            print(ip)
  
def update_flag_count(hosts, frame, ts):

    packet = frame.data
    if(type(packet) == IP):

        segment = packet.data
        if(type(segment) == TCP):

            if(contains_SYN(segment) and contains_ACK(segment)):
                dst_ip = inet_to_str(packet.dst)
                if(dst_ip not in hosts):
                    hosts[dst_ip] = {"SYN": 0, "SYN-ACK": 0}
                hosts[dst_ip]["SYN-ACK"]+=1 
            elif(contains_SYN(segment) and not contains_ACK(segment)):
                src_ip = inet_to_str(packet.src)
                if(src_ip not in hosts):
                    hosts[src_ip] = {"SYN": 0, "SYN-ACK": 0}
                hosts[src_ip]["SYN"]+=1 
 
def get_hosts(file):
    
    hosts = {}
    pcap_file = dpkt.pcap.Reader(file)

    for ts, buf in pcap_file:
  
        try:    # Filters out malformed packets
            current_frame = dpkt.ethernet.Ethernet(buf)
        except (dpkt.dpkt.UnpackError, IndexError):
            continue
        
        update_flag_count(hosts, current_frame, ts)

    return hosts

if __name__ == "__main__":

    input_file = sys.argv[1]

    pcap_file = open(input_file, "rb")
    hosts = get_hosts(pcap_file)
    print_suspect_hosts(hosts)
    
    pcap_file.close()
   
        