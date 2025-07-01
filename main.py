import fcntl
import os
import struct
import subprocess
import socket

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


def main():
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", b"tun9", IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    # 1. assign ip address and bring it up.
    # sudo ip addr add 192.168.9.0/24 dev tun9
    # sudo ip link set dev tun9 up
    subprocess.check_call("ip addr add 192.168.9.0/24 dev tun9", shell=True)
    subprocess.check_call("ip link set dev tun9 up", shell=True)
    # 2. capture traffic
    # tcpdump -v -i tun9
    # 3. ping 192.168.9.1
    # 4. nc 192.168.9.1 80
    # 4. nc -u 192.168.9.1 80
    while True:
        packet = list(os.read(tun, 2048))  # MTU is 1500, so 2048 is enough
        if not packet:
            print("No packet read.")
            continue
        # https://datatracker.ietf.org/doc/html/rfc791#section-3.1
        version = bytes(packet[0:1])[0] >> 4
        if version == 6:
            # print("skip ipv6 packet")
            continue
        header_length = bytes(packet[0:1])[0] & 0x0F
        print("IHL*4:", header_length * 4)
        total_length_bytes = bytes(packet[2:4])
        total_length = int.from_bytes(total_length_bytes, byteorder="big")
        print("Total Length:", total_length)
        payload_length = total_length - header_length * 4
        print("Payload Length:", payload_length)
        protocol = bytes(packet[9:10])[0]
        print(protocol)  # 1 for icmp, 6 for tcp, 17 for udp
        src, dst = packet[12:16], packet[16:20]
        src_ip = socket.inet_ntoa(bytes(src))
        dst_ip = socket.inet_ntoa(bytes(dst))
        print("src", src_ip)
        print("dst", dst_ip)

        if protocol == 1:
            packet[12:16], packet[16:20] = packet[16:20], packet[12:16]
            # https://datatracker.ietf.org/doc/html/rfc792
            # ICMP header start from 20byte of IP header
            # icmp_type = packet[20]
            # print("icmp type", icmp_type)
            # icmp_code = packet[21]
            # print("icmp code", icmp_code)
            # NOTE: Modify it to an ICMP Echo Reply packet
            packet[20] = 0  # 0 for `Echo Reply`
            for idx in [22, 23]:  # Clear Checksum
                packet[idx] = 0
            checksum = 0
            length = len(packet)
            # If the total length is odd, the received data is padded
            # with one octet of zeros for computing the checksum.
            padded = packet + [0] if length % 2 != 0 else packet
            for i in range(20, len(padded), 2):  # for every 16-bit
                half_word = (packet[i] << 8) + packet[i + 1]  # 16bit number
                checksum += half_word
            checksum = (checksum >> 16) + (checksum & 0xFFFF)
            checksum = ~checksum & 0xFFFF
            packet[22] = checksum >> 8
            packet[23] = checksum & 0xFF
            os.write(tun, bytes(packet))

    os.close(tun)


if __name__ == "__main__":
    main()
