# Import necessary libraries
import os
from dotenv import load_dotenv
import matplotlib.pyplot as plt
from censys.search import CensysHosts

# Load environment variables from .env file
load_dotenv(dotenv_path="./apiToken.env")

# Access Censys API keys from environment variables
CENSYS_API_ID = os.getenv('CENSYS_API_ID')
CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET')

# Initialize the Censys API client
censys_client = CensysHosts(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)

def search_dicom_censys_and_plot():
    print("Searching IPs in Censys in Spain...")

    # Define the query
    query = '(services.port: 104 or services.port: 11112) and location.country_code: ES'
    
    # Start the search with the first cursor
    results = censys_client.search(query, pages=0)
    
    # Dictionary to store the number of hosts for each number of ports
    port_count_distribution = {}
    
    pageCounter = 1
    hostCounter = 0

    # Process the results
    for page in results:
        print(f"Page number: {pageCounter} \n")
        

        for host in page:
            num_ports = len(host.get('services', []))
            if num_ports not in port_count_distribution:
                port_count_distribution[num_ports] = 0
            port_count_distribution[num_ports] += 1
            hostCounter += 1
        
        print(f"Analized hosts: {hostCounter}")
        
        pageCounter += 1

    
    # First Graph
    
    x = list(port_count_distribution.keys())
    y = list(port_count_distribution.values())

    plt.figure(figsize=(12, 6))
    plt.bar(x, y, color='blue', alpha=0.7)
    plt.title('Number of Ports per Host (DICOM Protocol)', fontsize=16)
    plt.xlabel('Number of Ports', fontsize=14)
    plt.ylabel('Number of Hosts', fontsize=14)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    
    plt.xticks(x)
    plt.tight_layout()
    plt.show()


    # Second Graph

    ranges = [1, 5, 10, 20, 50, 100]
    grouped_data = {f"{ranges[i]}-{ranges[i+1]-1}": 0 for i in range(len(ranges)-1)}
    grouped_data[f"{ranges[-1]}+"] = 0

    for num_ports, count in port_count_distribution.items():
        added = False
        for i in range(len(ranges)-1):
            if ranges[i] <= num_ports < ranges[i+1]:
                grouped_data[f"{ranges[i]}-{ranges[i+1]-1}"] += count
                added = True
                break
        if not added:
            grouped_data[f"{ranges[-1]}+"] += count

    x = list(grouped_data.keys())
    y = list(grouped_data.values())

    # Plotting
    plt.figure(figsize=(14, 8))
    plt.bar(x, y, color='blue', alpha=0.7)
    plt.title('Number of Ports per Host (Grouped)', fontsize=16)
    plt.xlabel('Range of Ports', fontsize=14)
    plt.ylabel('Number of Hosts', fontsize=14)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.xticks(rotation=45, fontsize=12)
    plt.tight_layout()
    plt.show()

if __name__ == '__main__':
    search_dicom_censys_and_plot()
