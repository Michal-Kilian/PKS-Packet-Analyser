# Michal Kilian - ID: 116211 - PKS - zadanie 1
# module that further analyzes an ethernet frame
import statistics
import functions
import json


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
ether_types = external_file_info.get("Ether type")
ipv4_protocols = external_file_info.get("IPv4 Protocol")
ports = external_file_info.get("Port")
icmp_types = external_file_info.get("ICMP Type")
arp_op_codes = external_file_info.get("ARP Operation Code")


# function that returns the ether type of frame
def get_ether_type(element):
    ether_type = element[24:28]
    if ether_type in ether_types:
        return ether_types.get(ether_type)


# function that returns the arp operation code of a frame
def get_arp_opcode(element):
    arp_opcode = element[40:44]
    if arp_opcode in arp_op_codes:
        return arp_op_codes.get(arp_opcode)


# function that returns the source and destination addresses of an arp frame
def get_arp_ip(element, ip_type):
    arp_ip = ""
    if ip_type == "src":
        arp_ip = element[56:64]
    elif ip_type == "dst":
        arp_ip = element[76:84]
    arp_ip_hex = [arp_ip[i:i + 2] for i in range(0, len(arp_ip), 2)]
    arp_ip_dec = []
    for number in arp_ip_hex:
        arp_ip_dec.append(functions.hex_to_dec(number))
    return '.'.join(arp_ip_dec)


# function that returns the source and destination addresses of an ipv4 frame
def get_ipv4_ip(element, ip_type):
    ipv4_ip = ""
    if ip_type == "src":
        ipv4_ip = element[52:60]
    elif ip_type == "dst":
        ipv4_ip = element[60:68]
    ipv4_ip_hex = [ipv4_ip[i:i + 2] for i in range(0, len(ipv4_ip), 2)]
    ipv4_ip_dec = []
    for number in ipv4_ip_hex:
        ipv4_ip_dec.append(functions.hex_to_dec(number))
    return '.'.join(ipv4_ip_dec)


# function that returns a protocol of a frame
def get_protocol(element):
    protocol = element[46:48]
    if protocol in ipv4_protocols:
        return ipv4_protocols.get(protocol)


# function that returns the port of communication of a frame
def get_port(element, port_type):
    if port_type == "src":
        return int(functions.hex_to_dec(element[68:72]))
    elif port_type == "dst":
        return int(functions.hex_to_dec(element[72:76]))


# function that returns an app protocol of a frame
def get_app_protocol(src_port, dst_port):
    if str(src_port) in ports:
        return ports.get(str(src_port))
    elif str(dst_port) in ports:
        return ports.get(str(dst_port))


# function that returns an icmp type of icmp frame
def get_icmp_type(element):
    icmp_type = functions.hex_to_dec(element[68:70])
    if icmp_type in icmp_types:
        return icmp_types.get(icmp_type)


# function that returns an icmp identification value of icmp frame
def get_icmp_id(element):
    icmp_id = element[36:40]
    return int(functions.hex_to_dec(icmp_id))


# function that returns the boolean value whether there are more fragments of icmp frame
def get_icmp_flags_mf(element):
    flags_mf = element[40:44]
    bin_flags_mf = bin(int('1' + flags_mf, 16))[3:]
    if bin_flags_mf[2] == '0':
        return False
    else:
        return True


# function that returns the fragment offset value of icmp frame
def get_icmp_frag_offset(element):
    frag_offset = element[40:44]
    hex_frag_offset = []
    bin_frag_offset = bin(int('1' + frag_offset, 16))[3:]
    if bin_frag_offset[3] == '0':
        hex_frag_offset.append('0')
    elif bin_frag_offset[3] == '1':
        hex_frag_offset.append('1')
    for i in range(1, 4):
        hex_frag_offset.append(hex(int(bin_frag_offset[i * 4:i * 4 + 4], 2))[2:])
    return int(functions.hex_to_dec(''.join(hex_frag_offset)))


# function that systematically analyzes an ethernet frame, depending on its ether type and protocol
def analyze_eth(element):
    ether_type_key = list(ether_types.keys())[list(ether_types.values()).index(get_ether_type(element))]
    additional_eth_info = {}
    additional_eth_info.update({"ether_type": get_ether_type(element)})

    if ether_type_key == "0806":
        additional_eth_info.update({"arp_opcode": get_arp_opcode(element), "src_ip": get_arp_ip(element, "src"),
                                    "dst_ip": get_arp_ip(element, "dst")})

    elif ether_type_key == "0800":
        protocol_key = list(ipv4_protocols.keys())[list(ipv4_protocols.values()).index(get_protocol(element))]

        src_ip = get_ipv4_ip(element, "src")
        dst_ip = get_ipv4_ip(element, "dst")
        additional_eth_info.update({"src_ip": src_ip, "dst_ip": dst_ip})

        statistics.update_ipv4_senders(src_ip)

        if protocol_key == "11" or protocol_key == "06":
            src_port = get_port(element, "src")
            dst_port = get_port(element, "dst")
            additional_eth_info.update({"protocol": get_protocol(element), "src_port": src_port, "dst_port": dst_port})
            app_protocol = get_app_protocol(src_port, dst_port)
            if app_protocol:
                additional_eth_info.update({"app_protocol": get_app_protocol(src_port, dst_port)})

        elif protocol_key == "01":
            additional_eth_info.update({"id": get_icmp_id(element), "flags_mf": get_icmp_flags_mf(element),
                                        "frag_offset": get_icmp_frag_offset(element),
                                        "protocol": get_protocol(element)})
            icmp_type = get_icmp_type(element)
            if icmp_type:
                additional_eth_info.update({"icmp_type": icmp_type})

        elif get_protocol(element):
            additional_eth_info.update({"protocol": get_protocol(element)})

    return additional_eth_info
