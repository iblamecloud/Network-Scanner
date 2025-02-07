from scapy.all import ARP, Ether, srp
import requests

def get_mac_vendor(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text.strip()
        else:
            return "Unknown Vendor"
    except requests.exceptions.RequestException:
        return "Lookup Failed"

def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    answered = srp(packet, timeout=3, verbose=False)[0]
    devices = []

    for sent, received in answered:
        mac_vendor = get_mac_vendor(received.hwsrc)
        devices.append({
            "IP": received.psrc,
            "MAC": received.hwsrc,
            "Vendor": mac_vendor
        })

    return devices

def print_results(devices):
    print("\nNetwork Scan Results:")
    print("=" * 50)
    print(f"{'IP Address':<18}{'MAC Address':<20}{'Vendor'}")
    print("=" * 50)
    for device in devices:
        print(f"{device['IP']:<18}{device['MAC']:<20}{device['Vendor']}")
    print("=" * 50)

if __name__ == "__main__":
    target_network = input("Enter Network IP Range (e.g., 192.168.1.1/24): ")
    print("\nScanning the network...")
    devices_found = scan_network(target_network)

    if devices_found:
        print_results(devices_found)
    else:
        print("\nNo devices found. Ensure you have the right network range.")