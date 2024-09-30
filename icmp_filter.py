# Michal Kilian - ID: 116211 - PKS - zadanie 1
# module that contains the IcmpFilter class
from collections import defaultdict

import dumper
import file_info


# class that analyzes the communication of icmp frames
class IcmpFilter:
    list_of_packet_dict = []
    icmp_packets = []
    sorted_by_id = defaultdict(list)
    merged_icmp_packets = []
    complete_comms = []
    partial_comms = []
    to_be_dumped = {}

    # initialize function that starts the analysis of a communication
    def __init__(self, list_of_packet_dict):
        self.list_of_packet_dict = list_of_packet_dict
        self.filter_packets()
        self.sort_by_id()
        self.merge_fragments()
        self.get_comms()
        self.get_dump()

    # function that filters all frames so that only icmp frames are saved here
    def filter_packets(self):
        for element in self.list_of_packet_dict:
            if element.get("protocol") == "ICMP":
                self.icmp_packets.append(element)

    # function that sorts all icmp frames by their identification value
    def sort_by_id(self):
        for element in self.icmp_packets:
            key = element.get("id")
            self.sorted_by_id[key].append(element)

    # function that merges fragments of icmp frame
    def merge_fragments(self):
        for elements in self.sorted_by_id.values():
            current_frag = []
            for element in elements:
                if element.get("icmp_type"):
                    current_frag.append(element)
                else:
                    current_frag.append(element)
                    self.merged_icmp_packets.append(current_frag)
                    current_frag = []

    # function that analyzes the communication and returns complete and partial communication
    def get_comms(self):
        number_complete_comm = 0
        number_partial_comm = 0
        current_comm = []
        looking_for_reply = False

        for elements in self.merged_icmp_packets:
            icmp_type = elements[0].get("icmp_type")
            if icmp_type != "ECHO REQUEST" or icmp_type != "ECHO REPLY":
                number_partial_comm += 1
                self.partial_comms.append({"number_comm": number_partial_comm, "packets": elements[-1]})

            if not looking_for_reply:
                if icmp_type == "ECHO REPLY":
                    number_partial_comm += 1
                    self.partial_comms.append({"number_comm": number_partial_comm, "packets": elements[-1]})

                elif icmp_type == "ECHO REQUEST":
                    current_comm.append(elements[-1])
                    looking_for_reply = True

            elif looking_for_reply:
                if icmp_type == "ECHO REPLY":
                    current_comm.append(elements[-1])
                    number_complete_comm += 1
                    self.complete_comms.append({"number_comm": number_complete_comm,
                                                "src_comm": current_comm[-1].get("src_ip"),
                                                "dst_comm": current_comm[-1].get("dst_ip"), "packets": current_comm})
                elif icmp_type == "ECHO REQUEST":
                    number_partial_comm += 1
                    self.partial_comms.append({"number_comm": number_partial_comm,
                                               "packets": current_comm[-1]})
                    current_comm = [elements[-1]]
        if current_comm:
            for packet in current_comm:
                number_partial_comm += 1
                self.partial_comms.append({"number_comm": number_partial_comm,
                                           "packets": packet})

    # function that returns the final dictionary about to be dumped
    def get_dump(self):
        self.to_be_dumped = {"name": "Michal Kilian, ID: 116211", "pcap_name": file_info.FILE_NAME,
                             "filter_name": "ICMP", "complete_comms": self.complete_comms,
                             "partial_comms": self.partial_comms}
        dumper.yaml_dump(self.to_be_dumped, "outputs/icmp-output.yaml")
