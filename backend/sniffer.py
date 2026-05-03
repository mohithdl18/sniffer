from scapy.all import sniff
from datetime import datetime

sniffing = False


def start_sniffing(callback):
    global sniffing
    sniffing = True

    def stop_filter(pkt):
        return not sniffing  # stop when False

    def process_packet(pkt):
        try:
            data = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "length": int(len(pkt)),
                "interface": str(getattr(pkt, "sniffed_on", "unknown")),
            }

            # Ethernet
            if pkt.haslayer("Ether"):
                eth = pkt["Ether"]
                data["src_mac"] = str(eth.src)
                data["dst_mac"] = str(eth.dst)
                data["ethertype"] = hex(int(eth.type))

            # IP
            if pkt.haslayer("IP"):
                ip = pkt["IP"]
                data["src"] = str(ip.src)
                data["dst"] = str(ip.dst)
                data["ttl"] = int(ip.ttl)
                data["proto"] = int(ip.proto)
                data["total_length"] = int(ip.len)

            # TCP
            if pkt.haslayer("TCP"):
                tcp = pkt["TCP"]
                data["protocol"] = "TCP"
                data["sport"] = int(tcp.sport)
                data["dport"] = int(tcp.dport)
                data["seq"] = int(tcp.seq)
                data["ack"] = int(tcp.ack)
                data["window"] = int(tcp.window)

                flags = int(tcp.flags)
                if flags & 0x04:
                    data["flag"] = "RST"
                elif flags & 0x02:
                    data["flag"] = "SYN"
                elif flags & 0x10:
                    data["flag"] = "ACK"
                else:
                    data["flag"] = str(flags)

            elif pkt.haslayer("UDP"):
                udp = pkt["UDP"]
                data["protocol"] = "UDP"
                data["sport"] = int(udp.sport)
                data["dport"] = int(udp.dport)
                data["checksum"] = int(udp.chksum) if udp.chksum else 0
                data["flag"] = ""

            elif pkt.haslayer("ICMP"):
                icmp = pkt["ICMP"]
                data["protocol"] = "ICMP"
                data["icmp_type"] = int(icmp.type)
                data["icmp_code"] = int(icmp.code)
                data["flag"] = ""

            else:
                data["protocol"] = "OTHER"
                data["flag"] = ""

            # DNS
            if pkt.haslayer("DNS") and pkt.haslayer("DNSQR"):
                try:
                    data["dns_query"] = pkt["DNSQR"].qname.decode(errors="ignore")
                except:
                    data["dns_query"] = "N/A"

            # HTTP
            if pkt.haslayer("Raw"):
                try:
                    payload = bytes(pkt["Raw"].load).decode(errors="ignore")
                    if payload.startswith(("GET", "POST", "PUT", "DELETE")):
                        parts = payload.split("\r\n")[0].split()
                        if len(parts) >= 2:
                            data["http_method"] = parts[0]
                            data["http_url"] = parts[1]
                except:
                    pass

            # 🚫 Skip useless packets
            if (
                data.get("protocol") == "OTHER" and
                (not data.get("src") or not data.get("dst"))
            ):
                return

            callback(data)

        except Exception as e:
            print("Packet error:", e)

    sniff(prn=process_packet, stop_filter=stop_filter, store=False)


def stop_sniffing():
    global sniffing
    sniffing = False