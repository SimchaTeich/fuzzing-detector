from scapy.all import *
from gibberish_detector import detector


Detector = detector.create_from_model('big.model')
SSH_PORT = 22


def is_SSH_packet(pkt):
    """
:   function return True if packet is ssh type. 
    """
    if TCP in pkt:
        return pkt[TCP].dport == SSH_PORT or pkt[TCP].sport == SSH_PORT
    return False


def ssh_fuzzing_dedector(ssh_pkt):
    """
:   function stop the entire program if 'gibberish'
:   is the contant of the ssh_packet   
:   param ssh_pkt: ssh packet
:   rtype: None
    """
    if Raw in ssh_pkt:
        if Detector.is_gibberish(ssh_pkt[Raw].load):
            print("fuzzing detected!")
            exit()


def main():
    sniff(lfilter = is_SSH_packet, prn = ssh_fuzzing_dedector)
    

if __name__ == '__main__':
    main()