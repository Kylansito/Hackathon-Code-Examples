# Import the Censys API
import censys
import shodan
from censys.search import CensysHosts
import json
import os
from dotenv import load_dotenv

# Cargar variables de entorno desde el archivo .env
load_dotenv(dotenv_path="./apiToken.env")

# Acceder a las claves de API desde las variables de entorno
CENSYS_API_ID = os.getenv('CENSYS_API_ID')
CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')


# Initialize the Censys API
censys_client = CensysHosts(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
shodan_client = shodan.Shodan(SHODAN_API_KEY)

ipsAndPorts = {}
ips = []

totalIPsShodan = 0
countIPsShodan = 1

# Find all IPs in Spain that use the DICOM protocol (Port 104 and 11112)

def search_dicom_censys():
    print("Searching IPs in Censys in Spain...")

    # Define the query
    query = '(services.port: 104 or services.port: 11112) and location.country_code: ES'
    
    # Start the search with the first cursor
    results = censys_client.search(query, pages=0)  # Gets a Censys search object

    count = 1
    with open('dicom_ips.txt', 'w') as file:
        for page in results:
            print(f"Page number: {count} \n")
            for host in page:
                ip = host['ip']
                ips.append(ip)
                ports = [] 
                for service in host['services']:
                    ports.append(service['port'])
                ipsAndPorts[ip] = ports
            
            count += 1

def search_dicom_shodan():
    global totalIPsShodan
    try:
        print("Searching IPs in Shodan in Spain...")
        
        # Define query and parameters
        query = "port:104,11112 country:ES"

        with open('dicom_shodan_ips.txt', 'w') as file:
            # Perform paginated queries
                print("Fetching information for IPs using DICOM: ")
                results = shodan_client.search(query, limit=0)
                totalIPsShodan = results['total']
                nPages = totalIPsShodan // 100 + (1 if totalIPsShodan % 100 else 0)
                
                for page in range(nPages):
                    print(f"Fetching page {page + 1} \n")
                    results = shodan_client.search(query, limit=100, offset=page * 100)
                    shodan_ips = []

                    for result in results['matches']:
                        ip = result['ip_str']
                        shodan_ips.append(ip)
                    
                    portsForIP = host_shodan(shodan_ips)
                    file.write(json.dumps(portsForIP, indent=4))
                    print(f"\n Page {page + 1} information saved successfully. \n")
                
    except Exception as e:
        print(f"Error searching in Shodan: {e}")

def host_shodan(ips):
    portsForIP = {}
    global countIPsShodan
    for ip in ips:
        ports = []
        try:
            print(f"({countIPsShodan}/{totalIPsShodan}) Fetching information for IP: {ip}")
            host_info = shodan_client.host(ip)
            for item in host_info['data']:
                ports.append(item['port'])
            portsForIP[ip] = ports
            countIPsShodan += 1
        except shodan.APIError as e:
            print(f"API Error: {e}")
    return portsForIP

if __name__ == '__main__':
    search_dicom_censys()
    print(f"Total IPs found: {len(ips)}")
    with open('dicom_ips.txt', 'w') as file:
        file.write(json.dumps(ipsAndPorts, indent=4))
    print("File created successfully.")
    
    # search_dicom_shodan()
