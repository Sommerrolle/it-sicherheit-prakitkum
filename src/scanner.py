import struct
import socket
from nmap import PortScanner
from netifaces import interfaces, ifaddresses, AF_INET


class Scanner:

    def __init__(self):
        self.connected_cidrs = _get_all_cidr_adresses()
        self.nm = PortScanner()
        self.hosts = []
        self.search_hosts()
        # jetzt haben wir eine Liste aller sich im Netzwerk befindlichen Adressen. Was wollen wir damit anstellen?

    # Todo: Es muss sichergestellt sein, dass das Skript per sudo ausgeführt wird,
    #  sonst ist das Argument -PA21,23,80,3389 quasi nutzlos
    def search_hosts(self):
        for network in self.connected_cidrs:
            self.nm.scan(hosts=network, arguments='-n -sP -PE -PA21,23,80,3389')
            for x in self.nm.all_hosts():
                if self.nm[x]['status']['state'] == "up":
                    self.hosts.append(x)


def _get_all_cidr_adresses():
    ips = []
    for i in interfaces():
        try:
            for j in range(0, len(ifaddresses(i)[AF_INET])):
                if ifaddresses(i)[AF_INET][j]["addr"] != "127.0.0.1":
                    ips.append((ifaddresses(i)[AF_INET][j]["addr"], ifaddresses(i)[AF_INET][j]["netmask"]))
        except KeyError:
            pass
    return [f"{_int2ip(_ip2int(addr) & _ip2int(mask))}/{bin(_ip2int(mask)).count('1')}" for addr, mask in ips]


def _ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def _int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))