from datetime import datetime
import json
import socket
from scapy import all as scapy
from scapy.all import IP, ICMP, UDP, Raw


# type soll Start und Stop sein
def create_json_payload(attack: str, target: str, typ: str):
    payload = {
        "attack": attack,
        "target": target,
        "MAC": "E4:A7:87:F9:89:1B",
        "type": typ,
        "time": datetime.now().isoformat()
    }
    return json.dumps(payload)

# scapy send braucht sudo-Rechte
def send_packet(attack: str, target: str, typ: str):
    payload = create_json_payload(attack, target, typ)
    packet = IP(src=get_ip_address(), dst=target)/ICMP()/payload
    packet.show()
    scapy.send(packet)


def get_ip_address():
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)


if __name__ == "__main__":
    send_packet("nmap", "192.168.12.1", "start")

