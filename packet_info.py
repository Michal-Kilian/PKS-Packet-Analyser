# Michal Kilian - ID: 116211 - PKS - zadanie 1
# module that contains the PacketData class
import functions


# data class that contains all information about a frame
class PacketData:
    frame_number: int
    len_frame_pcap: int
    len_frame_medium: int
    frame_type: [str, str]
    src_mac: str
    dst_mac: str
    additional_info: {}
    hexa_frame: str

    # function that returns a dictionary from all of frame's data
    def make_dictionary(self):
        dictionary = {"frame_number": self.frame_number, "len_frame_pcap": self.len_frame_pcap,
                      "len_frame_medium": self.len_frame_medium, "frame_type": self.frame_type, "src_mac": self.src_mac,
                      "dst_mac": self.dst_mac}
        if self.additional_info:
            merged = functions.merge_dict(dictionary, self.additional_info)
            merged.update({"hexa_frame": self.hexa_frame})
            return merged
        else:
            dictionary.update({"hexa_frame": self.hexa_frame})
            return dictionary
