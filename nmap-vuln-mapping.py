import os

# Function to perform Nmap scan with comprehensive options and save results to a file
def perform_nmap_scan(target_ip, output_file):
    nmap_command = f"nmap -p- -sV --script vulners,vulscan/,http-vuln-* --script-args vulscanoutput=results.xml -oN {output_file} {target_ip}"
    os.system(nmap_command)

# Function to parse Nmap scan results and extract vulnerabilities
def parse_nmap_results(output_file):
    vulnerabilities = []
    with open(output_file, 'r') as file:
        lines = file.readlines()
        for line in lines:
            if 'open' in line and 'http' in line:
                parts = line.split()
                if len(parts) > 3:  # Ensure there are enough elements to avoid index error
                    service = parts[2]
                    version = parts[3]
                    vulnerabilities.append(f"Vulnerability found in {service} ({version})")
                else:
                    vulnerabilities.append("Potential vulnerability found, but version information is missing.")
    return vulnerabilities

# Set target IP and output file
ipaddr = input('Enter IP Address: ')
target_ip = ipaddr
output_file = 'nmap_scan_results.txt'

# Perform Nmap scan with comprehensive options
perform_nmap_scan(target_ip, output_file)

# Parse Nmap results and extract vulnerabilities
vulnerabilities = parse_nmap_results(output_file)

# Display the vulnerabilities
if vulnerabilities:
    print("Vulnerabilities found:")
    for vulnerability in vulnerabilities:
        print(vulnerability)
else:
    print("No vulnerabilities found.")
