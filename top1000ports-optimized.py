import nmap

# Create Nmap PortScanner object
nm = nmap.PortScanner()

# Prompt user for the target IP address or range
ipaddr = input('Enter IP address or range to scan: ')

# Set Nmap scan options
scan_arguments = '--top-ports 1000 --script-timeout 10m --max-retries 2 -Pn -sS -T4'
print(f"Scanning {ipaddr} with arguments: {scan_arguments}")

# Perform the scan
nm.scan(ipaddr, arguments=scan_arguments)

# Process and print scan results
for host in nm.all_hosts():
    print(f"\nHost: {host} ({nm[host].hostname()})")
    print(f"State: {nm[host].state()}")
    
    # Check for available services
    if 'tcp' in nm[host]:
        print("Open TCP ports and services:")
        for port, details in nm[host]['tcp'].items():
            print(f"  Port: {port}, State: {details['state']}, Service: {details.get('name', 'unknown')}")

    # Handle other protocols if necessary
    for proto in nm[host].all_protocols():
        if proto != 'tcp':  # Skip TCP since we already handled it
            print(f"\nProtocol: {proto}")
            for port, details in nm[host][proto].items():
                print(f"  Port: {port}, State: {details['state']}, Service: {details.get('name', 'unknown')}")
