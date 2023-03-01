import nmap
import subprocess
import csv
import argparse
import sys


# Open the file for writing
with open("output.txt", "w") as f:
    # Redirect stdout to the file
    sys.stdout = f

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--host", help="host address")
    args = parser.parse_args()

    target_host = args.host

    nm = nmap.PortScanner()

    # Scan localhost for ports 80,443
    result = nm.scan(target_host,'80,443')

    #print("Hosts: ", target_host)

    # Get all hostnames for the host
    hosts = nm.all_hosts()

    # Create output files
    csv_file = open('scan_results.csv', 'w', newline='')
    txt_file = open('scan_results.txt', 'w')

    # Create CSV writer
    csv_writer = csv.writer(csv_file)

    # Write header row to CSV
    csv_writer.writerow(['Host', 'Port', 'Protocol', 'State'])

    # Print open ports
    for host in hosts:
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('Protocol : %s' % proto)

            lport = nm[host][proto].keys()
            #lport.sort()
            for port in lport:
                print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
                # Write scan results to CSV
                csv_writer.writerow([host, port, proto, nm[host][proto][port]['state']])
                # Write scan results to text file
                txt_file.write(f"{host}, {port}, {proto}, {nm[host][proto][port]['state']}\n")

                if port == 80:
                    # Run feroxbuster on the host                    
                    subprocess.run(["feroxbuster", "--status-codes", "200,401,403,500", "-u", f"http://{host}", "-w", "dict.txt"])
                    
                    # Run nuclei on the host
                    subprocess.run(["nuclei", "-u", f"http://{host}:80"])
                          
                    # Run wapiti on the host
                    subprocess.run(["wapiti", "-u", f"http://{host}"])
                          
                    # Run nikto on the host
                    subprocess.run(["nikto", "-h", f"http://{host}"])
                    
                if port == 443:
                    # Run feroxbuster on the host
                    subprocess.run(["feroxbuster", "--status-codes", "200,401,403,500", "-u", f"https://{host}:443", "-w", "dict.txt"])
                    
                    # Run nuclei on the host
                    subprocess.run(["nuclei", "-u", f"https://{host}:443"])
                    
                    # Run wapiti on the host
                    subprocess.run(["wapiti", "-u", f"https://{host}:443"])
                          
                    # Run nikto on the host
                    subprocess.run(["nikto", "-h", f"https://{host}:443"])



    # Close output files
    csv_file.close()
    txt_file.close()
    
    sys.stdout = sys.__stdout__
    
