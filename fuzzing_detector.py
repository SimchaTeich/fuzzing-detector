from scapy.all import *

SSH_PORT = 22

# here we saving clients that pass the fuzz check.
OK_CLIENTS_PORTS = []


def is_income_SSH_packet(pkt):
    """
:   param pkt: packet was sniffed.
:   type pkt: scapy packet
:   return: True if packet is income ssh.
:   rtype: Boolian.
    """
    if TCP in pkt:
        return pkt[TCP].dport == SSH_PORT
    return False


def ssh_fuzzing_dedector(ssh_pkt):
    """
:   function stop the entire program if the
:   payload of the first ssh packet is not
:   a valid identification string.   
:   param ssh_pkt: scapy income ssh packet
:   rtype: None
    """
    if Raw in ssh_pkt:
       
        # check just for new clients.
        if ssh_pkt[TCP].sport not in OK_CLIENTS_PORTS:
            
            # check the 'protocol identification string' massage.
            if ssh_pkt[Raw].load.startswith(b"SSH-2.0-") and ssh_pkt[Raw].load.endswith(b"\r\n"):
                
                # append client to list if is OK (= not fuzzing.)
                OK_CLIENTS_PORTS.append(ssh_pkt[TCP].sport)
            
            # when the client is newer, but using the protocol is uncorrect.
            else:
                print("fuzzing detected!")
                exit()


def main():
    sniff(lfilter = is_income_SSH_packet, prn = ssh_fuzzing_dedector)
    

if __name__ == '__main__':
    main()