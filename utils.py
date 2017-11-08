import fcntl, socket, struct
from scapy.all import *

def getHwAddrFromInterface(ifname):
    """
    Get Hardware's Mac Address based on interface string
    :param ifname: string
    :return: string
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])


def getHwAddrFromIp(ip):
    """
    Get Hardware Mac Address from ip string
    :param ip: string
    :return: string
    """
    ans, unans = arping(ip)
    for s,r in ans:
        return r[Ether].src
