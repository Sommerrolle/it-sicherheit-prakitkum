import pyshark
import sys
from time import time
from shutil import copyfileobj


interface_name = "br-attack"

capture = pyshark.LiveCapture(interface=interface_name)
log_file = open("data/packet_log.csv", mode="r+")
try:
    log_file.write("Source IP;Destination IP\n")
    for packet in capture.sniff_continuously():
        #print(packet.__dict__)
        if "arp" in packet:
            #print(packet.arp.layer_name)
            source_ip = packet.arp.get_field("arp.src.proto_ipv4")
            dst_ip = packet.arp.get_field("arp.dst.proto_ipv4")
            #print(source_ip, dst_ip)
            log_file.write(f"{source_ip};{dst_ip}\n")
        else:
            pass
            #print(packet.layers)
except KeyboardInterrupt:
    print("exception")
    timestamp = int(time())
    data = log_file.read()
    print(data)
    with open(f"data/packet_log_{timestamp}.csv", mode="w") as log_save_file:
        for line in data:
            log_save_file.write(line)

    log_file.close()
    sys.exit(0)


