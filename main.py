# Michal Kilian - ID: 116211 - PKS - zadanie 1
# module that contains the start of an analysis of a pcap file
from binascii import *
from scapy.all import *

import arp_filter
import dumper
import file_info
import functions
import icmp_filter
import packet_info
import statistics
import tcp_filter
import udp_filter
import argparse


# main function that contains switches for filter type and file path
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p')
    parser.add_argument('-f')
    args = parser.parse_args()

    if not args.f:
        print("Invalid file path")
        return
    else:
        file_info.FILE_PATH = "packets\\" + args.f
        file_info.FILE_NAME = file_info.FILE_PATH[8:]

    if not args.p:
        print("Invalid filter type")
        return
    else:
        analyze(args.p)


# analyze function that starts the analysis of a pcap file
def analyze(filter_type):
    pcap = rdpcap(file_info.FILE_PATH)
    packet_list = []
    list_of_packet_dict = []

    for element in pcap:
        packet_list.append(hexlify(raw(element)).decode())
    for i in range(len(packet_list)):
        pack = packet_info.PacketData()
        pack = analyze_general_info(i, packet_list[i], pack)
        list_of_packet_dict.append(pack.make_dictionary())

    to_be_dumped = {"name": "Michal Kilian, ID: 116211", "pcap_name": file_info.FILE_NAME,
                    "packets": list_of_packet_dict, "ipv4_senders": statistics.get_ipv4_senders(),
                    "max_send_packets_by": statistics.get_max_send_packets_ip()}
    dumper.yaml_dump(to_be_dumped, "outputs/all-output.yaml")

    if filter_type == "HTTP" or filter_type == "HTTPS" or filter_type == "TELNET" or filter_type == "SSH" or \
            filter_type == "FTP-DATA" or filter_type == "FTP-CONTROL":
        tcp_filter.TcpFilter(list_of_packet_dict, filter_type)
    elif filter_type == "TFTP":
        udp_filter.UdpFilter(list_of_packet_dict)
    elif filter_type == "ICMP":
        icmp_filter.IcmpFilter(list_of_packet_dict)
    elif filter_type == "ARP":
        arp_filter.ArpFilter(list_of_packet_dict)


# function that analyzes general information about a frame
def analyze_general_info(i, element, pack):
    pack.frame_number = i + 1
    pack.len_frame_pcap = functions.get_len_pcap(element)
    pack.len_frame_medium = functions.get_len_medium(element)
    pack.frame_type = functions.get_frame_type(element)
    pack.src_mac = functions.get_mac(element, "src")
    pack.dst_mac = functions.get_mac(element, "dst")
    pack.additional_info = functions.get_additional_info(element, pack)
    pack.hexa_frame = functions.get_hexa_frame(element)
    return pack


main()
