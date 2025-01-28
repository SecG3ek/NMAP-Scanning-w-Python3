import nmap  # Import the Nmap module for network scanning

# Create an Nmap PortScanner object to perform scans
nm = nmap.PortScanner()

# Define the target IP address or range to scan
# Here, we're scanning from 192.168.0.1 to 192.168.0.10
ipaddr = input(' Enter IP address to scan: ')
target = ipaddr

# Set Nmap scan options
# -T4: Aggressive timing template for faster scanning
# -p 1-100: Scan ports from 1 to 100
nm.scan(target, arguments='-T4 -p 1-1000')

# Iterate over all discovered hosts
for host in nm.all_hosts():
    # Print the host's IP address and its resolved hostname (if available)
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    
    # Print the state of the host (e.g., up or down)
    print('State : %s' % nm[host].state())
    
    # Loop through all protocols discovered on this host (e.g., TCP, UDP)
    for proto in nm[host].all_protocols():
        # Print the protocol (e.g., TCP or UDP)
        print('Protocol : %s' % proto)
        
        # Get a list of all ports scanned for this protocol
        port_list = nm[host][proto].keys()
        
        # Loop through each port in the list and print its state (e.g., open, closed)
        for port in port_list:
            print('Port : %s\tState : %s' % (port, nm[host][proto][port]['state']))
