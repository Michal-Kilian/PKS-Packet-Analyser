# Michal Kilian - ID: 116211 - PKS - zadanie 1
# module that contains functions calculating ipv4 communication statistics
ipv4_senders = {}


# function that updates the dictionary containing ipv4 senders
def update_ipv4_senders(ip):
    if ip not in ipv4_senders:
        ipv4_senders.update({ip: 0})
    else:
        ipv4_senders[ip] += 1


# function that returns the dictionary containing ipv4 senders
def get_ipv4_senders():
    list_of_ipv4_senders = []
    for ip in ipv4_senders:
        list_of_ipv4_senders.append({"node": ip, "number_of_sent_packets": ipv4_senders.get(ip)})
    return list_of_ipv4_senders


# function that calculates the frame with the maximum packets sent and returns it
def get_max_send_packets_ip():
    max_value = max(ipv4_senders.items(), key=lambda x: x[1], default=0)
    senders_with_max_value = []

    for key, value in ipv4_senders.items():
        if value == max_value[1]:
            senders_with_max_value.append(key)
    return senders_with_max_value
