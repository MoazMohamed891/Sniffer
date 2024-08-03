import os
import time
from scapy.all import sniff, IP, TCP, Raw
import re
import socket
################################################################################################################
print ("\033[31m")

os.system("figlet Hallo To Moaz Mohamed Script")

time.sleep(3)

os.system("clear")


print ("\033[1;31m")
os.system('figlet Sniffer')
print ("\033[35m")
print ("\033[93;5m⚡\033[0m \033[35mBY: Moaz Mohamed/Moaz_Mohamedx3\033[93;5m ⚡\033[0m")
print ("\033[36m")
print ("Linkedin : https://www.linkedin.com/in/moaz-mohamed-10b807318 ")
print ("Github : https://github.com/MoazMohamed891")
print("\033[1;36m" + "="*80)
print(" ")
print("\033[1;35m-----------------Starting network sniffer--------------------")

def resolve_domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.error:
        return None

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        tcp_layer = packet[TCP] if TCP in packet else None
        src_port = tcp_layer.sport if tcp_layer else None
        dst_port = tcp_layer.dport if tcp_layer else None
        
        raw_payload = packet[Raw].load.decode(errors='ignore') if Raw in packet else ''
        
        # Extract domain from HTTP Host header
        host_match = re.search(r'Host: ([^\r\n]+)', raw_payload)
        domain = host_match.group(1) if host_match else None
        
        if domain:
            real_ip = resolve_domain_to_ip(domain)
            real_ip_display = real_ip if real_ip else "Unable to resolve IP"
        else:
            real_ip_display = dst_ip
        
        # Print packet details
        print(f"\033[1;35mSource IP:\033[1;34m {src_ip} \033[1;31m--> \033[1;33mDestination IP:\033[1;34m {dst_ip}")
        if tcp_layer:
            print(f"\033[1;36mSource Port:\033[1;34m {src_port} \033[1;36mDestination Port:\033[1;34m {dst_port}")
        print(f"\033[1;32mDomain:\033[1;34m {domain if domain else 'Not Available'} \033[1;32mReal Website IP:\033[1;34m {real_ip_display}")

if __name__ == "__main__":
    try:
        # Sniff all incoming and outgoing packets on the network interface
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n\033[1;31mInterrupted by user. Exiting...\033[0m")
