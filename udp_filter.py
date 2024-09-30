# Michal Kilian - ID: 116211 - PKS - zadanie 1
# module that contains the UdpFilter class
from collections import defaultdict

import dumper
import file_info


# class that analyzes the communication of udp frames
class UdpFilter:
    list_of_packet_dict = []
    tftp_packets = []
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

    # function that filters all frames so that only udp frames are saved here
    def filter_packets(self):
        for element in self.list_of_packet_dict:
            if element.get("protocol") == "UDP":
                self.tftp_packets.append(element)

    # function that sorts all udp frames by their ip address
    def sort_by_ip(self):
        for element in self.tftp_packets:
            src_ip = element.get("src_ip")
            dst_ip = element.get("dst_ip")
            key = tuple(sorted([src_ip, dst_ip]))
            self.sorted_by_ip[key].append(element)

    # function that analyzes the communication and returns complete and partial communication
    def get_comms(self):
        number_complete_comm = 0
        current_comm = []
        comm_started = False

        for packets in self.sorted_by_ip.values():
            for packet in packets:
                src_port = packet.get("src_port")
                dst_port = packet.get("dst_port")

                if comm_started:
                    if dst_port == 69:
                        number_complete_comm += 1
                        self.complete_comms.append({"number_comm": number_complete_comm,
                                                    "packets": current_comm})
                        comm_started = True
                        current_comm = [packet]
                    else:
                        if dst_port == current_comm[-1].get("src_port"):
                            current_comm.append(packet)

                elif not comm_started:
                    if dst_port == 69:
                        comm_started = True
                        current_comm.append(packet)

    # function that returns the final dictionary about to be dumped
    def get_dump(self):
        self.to_be_dumped = {"name": "Michal Kilian, ID: 116211", "pcap_name": file_info.FILE_NAME,
                             "filter_name": "TFTP", "complete_comms": self.complete_comms,
                             "partial_comms": self.partial_comms}
        dumper.yaml_dump(self.to_be_dumped, "outputs/udp-output.yaml")
