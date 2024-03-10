import socket
import struct


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def get_mac_addr(bytes_Addr):
    bytes_str = map("{:02x}".format, bytes_Addr)
    return ":".join(bytes_str).upper()


def ipv4_packet(data):
    version = data[0]
    header_length = (version & 15)*4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def ipv4(addr):
    print(addr)
    return '.'.join(map(str, addr))


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H ", data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_packet(data):
    src_port, dest_port, seq_num, ack_num, offset_reserved_flags = struct.unpack(
        "! H H L L H", data[:14])
    offset = (offset_reserved_flags >> 12)*4
    flag_urg = (offset & 32) >> 5
    flag_ack = (offset & 16) >> 4
    flag_psh = (offset & 8) >> 3
    flag_rst = (offset & 4) >> 2
    flag_syn = (offset & 2) >> 1
    flag_fin = (offset & 1)
    return src_port, dest_port, seq_num, ack_num, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


def udp_packet(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:]


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, ether_proto, data = ethernet_frame(raw_data)
        print("ETHERNET FRAME :")
        print(
            f"\t- destination mac : {dest_mac} source mac : {src_mac} ethernet protocol : {ether_proto} ")

        if ether_proto == 8:
            (version, ttl, proto, src, dest, data) = ipv4_packet(data)
            print("\t- IPv4 Packet :")
            print(
                f"\t\t- Version : {version} TTL : {ttl} Protocol {proto} Source : {src} Destination : {dest} \n {data}")
            if proto == 1:
                (icmp_type, code, checksum, data) = icmp_packet(data)
                print("\t- ICMP Packet :")
                print(
                    f"\t\t- Icmp Type : {icmp_type} Code : {code} Checksum : {checksum} \n {data}")

            elif proto == 6:
                (src_port, dest_port, seq_num, ack_num, flag_urg, flag_ack,
                flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_packet(data)
                print("\t- TCP Packet :")
                print(
                    f"\t- Source Port : {src_port} Destination Port : {dest_port} Sequance Number : {seq_num} Acknoledge Number : {ack_num}")
                print(
                    f"\t\t\t- URG : {flag_urg} Ack : {flag_ack} PSH : {flag_psh} RST : {flag_rst} SYN : {flag_syn} FIN : {flag_fin} \n {data}")

            elif proto == 17:
                (src_port, dest_port, size, data) = udp_packet(data)
                print("\t- UDP packet : ")
                print(
                    f"\t- Source Port : {src_port} Destination Port : {dest_port} Size : {size} \n {data}")

            else:
                print(data)

        else:
            print(data)


main()
