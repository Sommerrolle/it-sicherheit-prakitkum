import concurrent.futures
import struct
import socket
from nmap import PortScanner
from netifaces import interfaces, ifaddresses, AF_INET
from typing import Optional
from telnetlib import Telnet
from concurrent.futures import ThreadPoolExecutor


class Host:
    def __init__(self, ip: str, ports: Optional[list[int]] = None):
        self.ip: str = ip
        self.ports = [] if ports is None else ports
        self.filtered_ports = {"all": self.ports}
        self.filter_needs_update = False
        self.new_ports = []

    def add_port(self, port: int):
        if port not in self.ports:
            self.ports.append(port)
            self.filtered_ports["all"].append(port)
            if len(self.filtered_ports.keys()) > 1:
                self.filter_needs_update = True
                self.new_ports.append(port)

    def add_filtered_port(self, name: str, ports: list[int]):
            self.filtered_ports[name] = ports


class Filter:
    name = "generic"

    def __init__(self):
        pass

    def filter_ports(self):
        pass


# Filtert schnell die Ports eines gegebenen Hosts nach Telnet-Logins
# todo: gibt es auch Telnet Server ohne Logins?
# todo: könnte zu einem allgemeinem Filter abstrahiert werden der die jeweilige connect&consume Funktion bekommt.
#  kommt auf Menge an die wir brauchen
class TelnetFilter(Filter):
    name = "telnet"

    def __init__(self, ip: str, ports: list[int], threads=5):
        super(TelnetFilter, self).__init__()
        self.ip = ip
        self.ports = ports
        self.threads = threads
        self.executor: Optional[ThreadPoolExecutor] = None
        self.filtered_ports = []

    def filter_ports(self):
        self.executor = ThreadPoolExecutor(self.threads)
        futures = [self.executor.submit(connect_and_consume_login, self.ip, port) for port in self.ports]
        for future in concurrent.futures.as_completed(futures):
            if future.result() > 0:
                self.filtered_ports.append(future.result())
        self.executor.shutdown(wait=True, cancel_futures=False)
        return self.filtered_ports


class Scanner:
    def __init__(self, initial_scan: bool = True):
        self.connected_cidrs: list[str] = _get_all_cidr()
        self.nm = PortScanner()
        self.hosts: list[Host] = []
        if initial_scan:
            self.search_hosts()
            self.scan_ports()

    # Todo: Es muss sichergestellt sein, dass das Skript per sudo ausgeführt wird,
    #  sonst ist das Argument -PA21,23,80,3389 quasi nutzlos
    # Scanne die hosts nach offenen ports
    # spec_host Argument ist eher für debugging
    # todo: AsyncPortScanner verwenden

    def _scan_ports_routine(self, host):
        res = self.nm.scan(hosts=host.ip, arguments="-p-")
        print(f"Portscan for {host.ip} done.")
        for port in res["scan"][host.ip]["tcp"]:
            if res["scan"][host.ip]["tcp"][port]["state"] == "open":
                host.add_port(port)

    def scan_ports(self, spec_host: Optional[str] = None):
        if spec_host is not None:
            if spec_host not in [i.ip for i in self.hosts]:
                self.hosts.append(Host(spec_host))
            hosts = [self.hosts[-1]]
        else:
            hosts = self.hosts

        if len(hosts) == 0:
            print("There are no hosts to portscan. Please search for hosts or specify one.")
            return
        with ThreadPoolExecutor(10) as executor:
            for host in hosts:
                executor.submit(self._scan_ports_routine, host)
            pass


    def search_hosts(self):
        for network in self.connected_cidrs:
            # -n: Keine DNS Auflösung
            # -sP: Ping Scan
            # -PA: TCP-ACK-Ping test auf folgende ports
            self.nm.scan(hosts=network, arguments='-n -sP -PE -PA21,23,80,3389')
            for x in self.nm.all_hosts():
                if self.nm[x]['status']['state'] == "up":
                    self.hosts.append(Host(x))

    # todo: vielleicht auch async?
    def filter_ports(self, filter_class: Filter.__class__):
        for host in self.hosts:
            host.add_filtered_port(filter_class.name, filter_class(host.ip, host.ports, threads=5).filter_ports())


def connect_and_consume_login(ip, port, timeout=1):
    try:
        with Telnet(ip, port) as tn:
            bytes_rd = tn.read_until(b'login: ', timeout)
            if b'login: ' in bytes_rd:
                return port
            else:
                return -1
    except (ConnectionRefusedError, EOFError):
        return -1

def _get_all_cidr():
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


if __name__ == "__main__":
    scanner = Scanner(initial_scan=True)
    print(scanner.connected_cidrs)
    scanner.filter_ports(TelnetFilter)
    print(scanner)
