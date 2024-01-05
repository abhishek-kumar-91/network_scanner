from scapy.all import *
from prettytable import PrettyTable
from mac_vendor_lookup import MacLookup
from argparse import ArgumentParser
from sys import exit, stderr, argv

class NetworkScanner:
    def __init__(self, host):
        for host in host:
            self.host = host
            self.alive = {}
            self.createPacket()
            self.sendPacket()
            self.getAlive()
            self.printAlive()

    def createPacket(self):
        layer1 = Ether(dst = "ff:ff:ff:ff:ff:ff")
        layer2 = ARP(pdst = self.host)
        packet = layer1 / layer2
        self.packet = packet

    def sendPacket(self):
        answered, unanswered = srp(self.packet, timeout = 1, verbose = False)
        if answered:
            self.answered = answered
        else:
            print("No host is up..")
            sys.exit(1)

    def getAlive(self):
        for sent, recevied in answered:
            self.alive[recevied.psrc] = recevied.hwsrc

    def printAlive(self):
        table = PrettyTable(["IP", "MAC", "VENDOR"])
        for ip, mac in self.alive.items():
            try:
                table.add_row([ip, mac, MacLookup().lookup(mac)])
            except:
                table.add_row([ip, mac, "unknown"])
        print(table)



def getArgs():
    parser = ArgumentParser(description = "Network Scanner")
    parser.add_argument("--h", dest= "hosts", nargs="+", help="hosts to scan")
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    return arg.hosts


hosts = getArgs()
NetworkScanner(hosts)
