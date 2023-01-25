from datetime import datetime
import json
import socket
from scapy import all as scapy
from scapy.all import IP, ICMP, UDP, Raw


SENDER_IP = '192.168.12.110'

# type soll Start und Stop sein
def create_json_payload(attack: str, target: str, typ: str):
    payload = {
        "attack": attack,
        "sender": SENDER_IP,
        "target": target,
        "type": typ,
        "time": int(datetime.now().timestamp() * 1000)
    }
    return json.dumps(payload)

# scapy send braucht sudo-Rechte
def send_packet(attack: str, target: str, typ: str):
    payload = create_json_payload(attack, target, typ)
    packet = IP(src=SENDER_IP, dst=target)/ICMP()/payload
    # packet.show()
    scapy.send(packet)
    print(f"Sent {typ} package for attack: {attack} from {SENDER_IP} to {target}")


def get_ip_address():
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)


if __name__ == "__main__":
    send_packet("nmap", "192.168.12.1", "start")
    send_packet("nmap", "192.168.12.1", "stop")
    #print(get_ip_address)

