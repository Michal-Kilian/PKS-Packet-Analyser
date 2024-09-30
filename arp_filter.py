# Michal Kilian - ID: 116211 - PKS - zadanie 1
# module that contains the ArpFilter class
from collections import defaultdict

import dumper
import file_info


# class that analyzes the communication of arp frames
class ArpFilter:
    list_of_packet_dict = []
    arp_packets = []
    sorted_by_ip = defaultdict(list)
    complete_comms = []
    partial_comms = []
    to_be_dumped = {}

    # initialize function that starts the analysis of a communication
    def __init__(self, list_of_packet_dict):
        self.list_of_packet_dict = list_of_packet_dict
        self.filter_packets()
        self.sort_by_ip()
        self.get_comms()
        self.get_dump()

    # function that filters all frames so that only arp frames are saved here
    def filter_packets(self):
        for element in self.list_of_packet_dict:
            if element.get("ether_type") == "ARP":
                self.arp_packets.append(element)

    # function that sorts all arp frames by their ip address
    def sort_by_ip(self):
        for element in self.arp_packets:
            src_ip = element.get("src_ip")
            dst_ip = element.get("dst_ip")
            key_to_dict = tuple(sorted([src_ip, dst_ip]))
            self.sorted_by_ip[key_to_dict].append(element)

    # function that analyzes the communication and returns complete and partial communication
    def get_comms(self):
        number_complete_comm = 0
        number_partial_comm = 0
        current_comm = []
        looking_for_reply = False

        for packets in self.sorted_by_ip.values():
            for packet in packets:
                arp_opcode = packet.get("arp_opcode")

                if not looking_for_reply:
                    if arp_opcode == "REPLY":
                        number_partial_comm += 1
                        self.partial_comms.append({"number_comm": number_partial_comm,
                                                   "packets": packet})
                    elif arp_opcode == "REQUEST":
                        current_comm.append(packet)
                        looking_for_reply = True

                elif looking_for_reply:
                    if arp_opcode == "REPLY":
                        current_comm.append(packet)
                        number_complete_comm += 1
                        self.complete_comms.append({"number_comm": number_complete_comm,
                                                    "src_comm": current_comm[0].get("src_ip"),
                                                    "dst_comm": current_comm[0].get("dst_ip"), "packets": current_comm})
                        looking_for_reply = False
                        current_comm = []
                    elif arp_opcode == "REQUEST":
                        current_comm.append(packet)
            if current_comm:
                for packet in current_comm:
                    number_partial_comm += 1
                    self.partial_comms.append({"number_comm": number_partial_comm,
                                               "packets": packet})

    # function that returns the final dictionary about to be dumped
    def get_dump(self):
        self.to_be_dumped = {"name": "Michal Kilian, ID: 116211", "pcap_name": file_info.FILE_NAME,
                             "filter name": "ARP", "complete_comms": self.complete_comms,
                             "partial_comms": self.partial_comms}
        dumper.yaml_dump(self.to_be_dumped, "outputs/arp-output.yaml")
