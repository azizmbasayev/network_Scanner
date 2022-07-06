import scapy.all as scapy
import optparse

def get_user_input():
    parse_obje = optparse.OptionParser()
    parse_obje.add_option("-i","--ip_address",dest="ip",help="IP Address")

    (user_input,arguments) = parse_obje.parse_args()

    if not user_input.ip:
        print("Enter IP Address")
    return user_input.ip

def scan_network(ip):
    arp_request_packet = scapy.ARP(pdst=ip)

    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    combined_packet = broadcast_packet/arp_request_packet
    (answered_list,unanswered_list) = scapy.srp(combined_packet,timeout=1)
    answered_list.summary()

user_ip = get_user_input()
scan_network(user_ip)

