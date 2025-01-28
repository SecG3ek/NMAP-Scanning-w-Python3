import nmap
import networkx as nx
import matplotlib.pyplot as plt
     
def visualize_network_scan_results(target_ip):
        # Perform Nmap scan
        nm = nmap.PortScanner()
        nm.scan(target_ip, arguments='-F')
        
        # Extract scan results
        hosts = nm.all_hosts()
        open_ports = []
        for host in hosts:
            open_ports.extend(nm[host]['tcp'].keys())
        
        # Create network graph
        G = nx.Graph()
        G.add_nodes_from(hosts)
        for port in open_ports:
            G.add_edge(target_ip, port)
        
        # Visualize network graph
        plt.figure(figsize=(10, 6))
        pos = nx.spring_layout(G)
        nx.draw_networkx(G, pos, with_labels=True, node_color='lightgreen', node_size=500, font_size=10)
        plt.title('Network Visualization: Open Ports on {}'.format(target_ip))
        plt.axis('off')
        plt.show()

print("Enter IP address to perform an Nmap scan and visualize the open ports.")
    # Get input from user
target_ip = input("Enter the target IP address: ")
     
    # Perform Nmap scan and visualize the results
visualize_network_scan_results(target_ip)