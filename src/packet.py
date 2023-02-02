from datetime import datetime
import json
import netifaces as ni
from scapy import all as scapy
from scapy.all import IP, UDP


NETWORK_ADAPTER_NAME = "wlan0"


def create_json_payload(attack: str, target: str, typ: str, mac: str) -> str:
    """
    Creates JSON payload for the packet
    :param attack: Name of the attack
    :param target: IP address of the target
    :param typ: Start or stop
    :param mac: MAC address of the target
    :return: The payload as JSON string
    """
    payload = {
        "attack": attack,
        "target": target,
        "MAC": mac,
        "type": typ,
        "time": int(datetime.now().timestamp() * 1000)
    }
    return json.dumps(payload)


def send_packet(attack: str, target: str, typ: str, mac: str) -> None:
    """
    Sends a UDP packet with a JSON payload
    :param attack: Name of the attack
    :param target: IP address of the target
    :param typ: Start or stop
    :param mac: MAC address of the target
    """
    payload = create_json_payload(attack, target, typ, mac)
    packet = IP(src=get_ip_address(), dst=target)/UDP()/payload
    packet.show()
    scapy.send(packet)


class AttackNoticePackets:
    """
    Context manager class to send notice packets befor and after an attack
    """
    def __init__(self, attack: str, target: str, mac: str = None) -> None:
        self.attack = attack
        self.target = target
        if not mac:
            self.mac = get_mac_address()
        else:
            self.mac = mac

    def __enter__(self):
        send_packet(self.attack, self.target, "start", self.mac)

    def __exit__(self, exc_type, exc_val, exc_tb):
        send_packet(self.attack, self.target, "stop", self.mac)


def get_ip_address() -> str:
    """
    Returns the IP address of the network adapter connected to the network to attack
    :return: ip address as string
    """
    return ni.ifaddresses(NETWORK_ADAPTER_NAME)[ni.AF_INET][0]['addr']


def get_mac_address() -> str:
    """
    Returns the MAC address of the network adapter connected to the network to attack
    :return: MAC address as string
    """
    return ni.ifaddresses(NETWORK_ADAPTER_NAME)[ni.AF_LINK][0]["addr"]


if __name__ == "__main__":
    send_packet("test", "192.168.12.1", "start", "00:00:00:00:00:00")
    send_packet("test", "192.168.12.1", "stop", "00:00:00:00:00:00")
