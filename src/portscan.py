import nmap
import json

nm = nmap.PortScanner()

scan_res = nm.scan('127.0.0.1')

with open("./data/output.json", mode="w") as output_file:
    json.dump(scan_res, output_file)
