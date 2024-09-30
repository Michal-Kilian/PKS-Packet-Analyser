# Michal Kilian - ID: 116211 - PKS - zadanie 1
# module that contains functions that are widely used for a large amount of packets
from ruamel.yaml.scalarstring import LiteralScalarString
import json
import ethernet_analyzer


# function that loads the data from an external file
def load_external_file():
    file = open("external_file.txt")
    data = json.load(file)
    all_data = {}
    for i in data["Additional info"]:
        all_data.update(i)
    return all_data


# assignment of dictionaries with the data from an external file
external_file_info = load_external_file()
frame_types = external_file_info.get("Frame type")
sap_types = external_file_info.get("Sap")
pid_types = external_file_info.get("Ether type")


# function that analyzes the additional information about a packet
def get_additional_info(element, pack):
    if pack.frame_type[0] == "ff":
        pack.frame_type = pack.frame_type[1]
        return {}
    elif pack.frame_type[0] == "aa":
        pack.frame_type = pack.frame_type[1]
        return {"pid": get_pid(element)}
    elif pack.frame_type[0] == "else":
        pack.frame_type = pack.frame_type[1]
        return {"sap": get_sap(element)}
    elif pack.frame_type[0] == "1536":
        pack.frame_type = pack.frame_type[1]
        return ethernet_analyzer.analyze_eth(element)


# function that returns the total length of a frame
def get_len_pcap(element):
    return int(len(element) / 2)


# function that returns the total length of a frame transmitted through a medium
def get_len_medium(element):
    return int(len(element) / 2 + 4)


# function that returns the source and destination mac addresses of a frame
def get_mac(element, mac_type):
    mac = ""
    if mac_type == "src":
        mac = element[12:24]
    elif mac_type == "dst":
        mac = element[0:12]
    return ':'.join(mac[i:i + 2] for i in range(0, len(mac), 2)).upper()


# function that returns the frame type
def get_frame_type(element):
    if int(element[24:28], base=16) >= 1536:
        return ["1536", frame_types.get("1536")]
    elif element[28:30] in frame_types:
        return [element[28:30], frame_types.get(element[28:30])]
    else:
        return ["else", frame_types.get("else")]


# function that returns the sap value
def get_sap(element):
    sap = element[30:32]
    if sap in sap_types:
        return sap_types.get(sap)


# function that returns the pid value
def get_pid(element):
    pid = element[40:44]
    if pid in pid_types:
        return pid_types.get(pid)


# function that returns the hexa frame in an acceptable structure
def get_hexa_frame(element):
    hexa_frame = ' '.join(element[i:i + 2] for i in range(0, len(element), 2)).upper()
    return LiteralScalarString('\n'.join(hexa_frame[j:j + 47] for j in range(0, len(hexa_frame), 48)) + "\n")


# function that merges 2 dictionaries
def merge_dict(dict1, dict2):
    merged_dicts = dict1.copy()
    merged_dicts.update(dict2)
    return merged_dicts


# function that converts a hexadecimal number to a decimal number
def hex_to_dec(hex_number):
    number_int = int(hex_number, base=16)
    return str(number_int)


# function that converts a binary number to a hexadecimal number
def bin_to_hex(bin_number):
    dec_number = int(bin_number, 2)
    hex_number = hex(dec_number)
    return hex_number
