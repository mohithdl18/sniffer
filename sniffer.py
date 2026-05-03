from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP

def format_flags(tcp_flags):
    flags = []
    if tcp_flags & 0x02: flags.append("SYN")
    if tcp_flags & 0x10: flags.append("ACK")
    if tcp_flags & 0x01: flags.append("FIN")
    if tcp_flags & 0x04: flags.append("RST")
    if tcp_flags & 0x08: flags.append("PSH")
    if tcp_flags & 0x20: flags.append("URG")
    return ",".join(flags) if flags else "None"

def process_packet(pkt):
    print("\n" + "="*60)

    # ------------------ ETHERNET ------------------
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        print(f"Destination MAC : {eth.dst}")
        print(f"Source MAC      : {eth.src}")
        print(f"EtherType       : {hex(eth.type)}")

    # ------------------ IP ------------------
    if pkt.haslayer(IP):
        ip = pkt[IP]
        print(f"Source IP       : {ip.src}")
        print(f"Destination IP  : {ip.dst}")
        print(f"TTL             : {ip.ttl}")
        print(f"Protocol        : {ip.proto}")
        print(f"Total Length    : {ip.len}")
        print(f"Header Checksum : {ip.chksum}")

        # ------------------ TCP ------------------
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            print("Protocol Name   : TCP")
            print(f"Source Port     : {tcp.sport}")
            print(f"Destination Port: {tcp.dport}")
            print(f"Sequence Number : {tcp.seq}")
            print(f"Ack Number      : {tcp.ack}")
            print(f"Flags           : {format_flags(tcp.flags)}")

        # ------------------ UDP ------------------
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            print("Protocol Name   : UDP")
            print(f"Source Port     : {udp.sport}")
            print(f"Destination Port: {udp.dport}")

        # ------------------ ICMP ------------------
        elif pkt.haslayer(ICMP):
            print("Protocol Name   : ICMP")

def main():
    print("Capturing 10 packets...\n")
    sniff(prn=process_packet, count=10)

if __name__ == "__main__":
    main()