from datetime import datetime
import json
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
    packet = IP(src='192.168.12.110', dst=target)/UDP()/payload
    packet.show()
    scapy.send(packet)


def get_ip_address():
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)


if __name__ == "__main__":
    send_packet("nmap", "192.168.12.1", "start")
    send_packet("nmap", "192.168.12.1", "stop")
    #sudoprint(get_ip_address)

