import nmap
 
# Create Nmap PortScanner object
nm = nmap.PortScanner()
 
# Define target IP address or range
ipaddr = input(' Enter IP address to scan: ')
target = ipaddr
 
# Set Nmap scan options
nm.scan(target, arguments='--top-ports 1000 --script-timeout 10m --max-retries 2 -Pn -sS -T4')
 
# Print scan results
for host in nm.all_hosts():
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())
    for proto in nm[host].all_protocols():
        print('Protocol : %s' % proto)
        port_list = nm[host][proto].keys()
        for port in port_list:
            print('Port : %s\tState : %s' % (port, nm[host][proto][port]['state']))