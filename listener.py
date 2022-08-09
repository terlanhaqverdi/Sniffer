import scapy.all as scapy
from scapy_http import http
import optparse
def function():
    parser=optparse.OptionParser()
    parser.add_option("-i","--iface",dest="interface",help="Enter interface")
    user_input=parser.parse_args()[0]
    if not user_input.interface:
        print("Enter interface")
    return user_input

def sniffing(interface):
    scapy.sniff(iface=interface,store=False,prn=listening_func,)

def listening_func(packet):
    packet.show()
    
    
user_interface=function()
sniffing(user_interface.interface)

