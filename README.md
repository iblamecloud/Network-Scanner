# Network-Scanner
This Python network scanner uses ARP requests to identify devices on a local network. It sends requests across a specified IP range and returns a list of active devices with their IP addresses, MAC addresses, and associated manufacturers, retrieved through an external API.

# Network Scanner with MAC Vendor Lookup

This Python script scans a specified IP range in a local network and retrieves the associated MAC addresses and their corresponding vendors. The results are displayed in a user-friendly format, showing each device's IP address, MAC address, and vendor name.

## Features:
- Scans an IP range using ARP requests.
- Retrieves MAC address vendors using the MacVendors API.
- Displays the results in a formatted table with IP, MAC, and Vendor information.

## Requirements:
- Python 3.x
- `scapy` library for network packet manipulation
- `requests` library for making HTTP requests

You can install the required libraries with the following commands:

```bash
pip install scapy requests
```

### How to Use:
-Clone or download the repository.
-Install the required libraries using pip.
-Run the script:
```bash
python network_scanner.py
```
When prompted, enter the IP range to scan (e.g., 192.168.1.1/24).
The script will output a list of devices found in the network with their IP addresses, MAC addresses, and the associated vendors.

### Example:
Enter Network IP Range (e.g., 192.168.1.1/24): 192.168.1.1/24

Scanning the network...

Network Scan Results:
==================================================
IP Address        MAC Address         Vendor
==================================================
192.168.1.1       00:14:22:01:23:45  Cisco Systems, Inc
192.168.1.10      00:1A:2B:3C:4D:5E  Apple, Inc
==================================================


### Code Explanation:
-get_mac_vendor(mac_address): Fetches the vendor name based on the MAC address using the MacVendors API.
-scan_network(ip_range): Scans the specified IP range using ARP requests and collects the devices found.
-print_results(devices): Formats and prints the results of the network scan.

### Troubleshooting:
Ensure that you have permission to scan the network and that your device is connected to the network you're scanning.
The script may not work if run on networks with advanced security features such as firewall rules blocking ARP requests.
