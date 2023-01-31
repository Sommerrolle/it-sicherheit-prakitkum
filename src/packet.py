from datetime import datetime
import json
import netifaces as ni
import socket
from scapy import all as scapy
from scapy.all import IP, UDP, Raw


# type soll Start und Stop sein
def create_json_payload(attack: str, target: str, typ: str, mac: str):
    payload = {
        "attack": attack,
        "target": target,
        "MAC": mac,
        "type": typ,
        "time": int(datetime.now().timestamp() * 1000)
    }
    return json.dumps(payload)

# scapy send braucht sudo-Rechte
def send_packet(attack: str, target: str, typ: str, mac: str):
    payload = create_json_payload(attack, target, typ, mac)
    packet = IP(src=get_ip_address(), dst=target)/UDP()/payload
    packet.show()
    scapy.send(packet)

# Return ip address of the wlan0 interface
def get_ip_address():
    return ni.ifaddresses('wlan0')[ni.AF_INET][0]['addr']


if __name__ == "__main__":
    send_packet("nmap", "192.168.12.1", "start")
    send_packet("nmap", "192.168.12.1", "stop")


