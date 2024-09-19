from scapy.all import sniff, get_if_list, Ether, IP, TCP, UDP, ICMP
import time

# Callback function to process captured packets
def packet_handler(packet):
    print(f"\n[+] New Packet Captured: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Ethernet layer
    if packet.haslayer(Ether):
        eth = packet.getlayer(Ether)
        print(f"Source MAC: {eth.src} -> Destination MAC: {eth.dst}")
    
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"Source IP: {ip.src} -> Destination IP: {ip.dst}")
        
        # ICMP Packet
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            print(f"ICMP Type: {icmp.type} Code: {icmp.code}")
        
        # TCP Packet
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print(f"TCP Segment: Source Port: {tcp.sport} -> Destination Port: {tcp.dport}")
        
        # UDP Packet
        if packet.haslayer(UDP):
            udp = packet[UDP]
            print(f"UDP Segment: Source Port: {udp.sport} -> Destination Port: {udp.dport}")
    
    # Print a simple summary of the packet
    print(packet.summary())

# Start sniffing on a network interface
def start_sniffing(interface):
    print(f"[*] Starting network sniffer on interface: {interface}")
    sniff(iface=interface, prn=packet_handler)

if __name__ == "__main__":
    # Find available interfaces
    interfaces = get_if_list()
    print("Available Network Interfaces: ", interfaces)
    
    # Ask the user to choose an interface to sniff on
    interface = input("Enter the network interface to sniff on (e.g., Wi-Fi, Ethernet): ")
    
    # Start sniffing on the selected interface
    try:
        start_sniffing(interface)
    except KeyboardInterrupt:
        print("\n[!] Stopping the network sniffer.")