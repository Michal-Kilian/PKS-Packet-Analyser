# Michal Kilian - ID: 116211 - PKS - zadanie 1
# module that contains the TcpFilter class
from collections import defaultdict

import dumper
import file_info


# class that analyzes the communication of tcp frames
def get_flags(hexa_frame):
    flags = hexa_frame[141:143].replace(" ", "")
    bin_flags = bin(int('1' + flags, 16))[5:]
    complete_flags = []
    if bin_flags[0] == "1":
        complete_flags.append("URGENT")
    if bin_flags[1] == "1":
        complete_flags.append("ACK")
    if bin_flags[2] == "1":
        complete_flags.append("PUSH")
    if bin_flags[3] == "1":
        complete_flags.append("RST")
    if bin_flags[4] == "1":
        complete_flags.append("SYN")
    if bin_flags[5] == "1":
        complete_flags.append("FIN")
    return complete_flags


class TcpFilter:
    list_of_packet_dict = []
    filter_type: str
    tcp_packets = []
    sorted_by_ip = defaultdict(list)
    complete_comms = []
    first_partial_comm = []
    to_be_dumped = {}

    # initialize function that starts the analysis of a communication
    def __init__(self, list_of_packet_dict, filter_type):
        self.list_of_packet_dict = list_of_packet_dict
        self.filter_type = filter_type
        self.filter_packets()
        self.sort_by_ip()
        self.get_comms()
        self.get_dump()

    # function that filters all frames so that only tcp frames are saved here
    def filter_packets(self):
        for element in self.list_of_packet_dict:
            if element.get("app_protocol") == self.filter_type:
                self.tcp_packets.append(element)

    # function that sorts all tcp frames by their ip address
    def sort_by_ip(self):
        for element in self.tcp_packets:
            src_ip = element.get("src_ip")
            dst_ip = element.get("dst_ip")
            key_to_dict = tuple(sorted([src_ip, dst_ip]))
            self.sorted_by_ip[key_to_dict].append(element)

    # function that analyzes the communication and returns complete and partial communication
    def get_comms(self):
        number_complete_comm = 0
        current_comm = []
        comm_opened = False
        opening_state = 0
        closing_state = 0

        for packets in self.sorted_by_ip.values():
            for packet in packets:
                flags = get_flags(packet.get("hexa_frame"))

                if not comm_opened:
                    if opening_state == 0 and "SYN" in flags:
                        opening_state = 1
                    elif opening_state == 1 and "SYN" in flags and "ACK" in flags:
                        opening_state = 2
                    elif opening_state == 2 and "ACK" in flags:
                        opening_state = 3
                        comm_opened = True

                else:
                    if closing_state == 0 and "FIN" in flags:
                        closing_state = 1
                    elif closing_state == 1 and "FIN" in flags and "ACK" in flags:
                        closing_state = 2
                    elif closing_state == 2 and "ACK" in flags:
                        closing_state = 3
                        number_complete_comm += 1
                        self.complete_comms.append({"number_comm": number_complete_comm,
                                                    "src_comm": current_comm[0].get("src_ip"),
                                                    "dst_comm": current_comm[0].get("dst_ip"),
                                                    "packets": current_comm})
                        comm_opened = False
                    else:
                        current_comm.append(packet)

            if current_comm:
                self.first_partial_comm.append({"number_comm": 1, "packets": current_comm})

    # function that returns the final dictionary about to be dumped
    def get_dump(self):
        self.to_be_dumped = {"name": "Michal Kilian, ID: 116211", "pcap_name": file_info.FILE_NAME,
                             "filter_name": self.filter_type, "complete_comms": self.complete_comms,
                             "partial_comms": self.first_partial_comm}
        dumper.yaml_dump(self.to_be_dumped, "outputs/tcp-output.yaml")
