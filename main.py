#Importing Packages
import requests
from bs4 import BeautifulSoup
import scrapy
from scrapy.crawler import CrawlerProcess
import socket
import nmap

#Get input form user
print("Enter the URL to the website you wish to scrape: ")
target_url = input()

#Sanitizing input
target_url = (target_url.replace("http://", "").replace("https://", "").
              replace("/",""))
print("Sanitized target url: ", target_url)

# Resolve domain name to IP address
try:
    target_ip = socket.gethostbyname(target_url)
    print(f"Resolved IP address: {target_ip}")
except socket.gaierror:
    print("Error: Could not resolve the domain name.")
    exit()

scanner = nmap.PortScanner()
scanner.scan(target_url)


def portScan(url):
    print("Port scanning...")
    spacer = " "
    for host in scanner.all_hosts():
        print("Host: ", host)
        print("State: ", scanner[host].state())
        for proto in scanner[host].all_protocols():
            print("Protocol: ", proto)
            ports = scanner[host][proto].keys()
            for port in ports:
                print("Port", port, (7 - len(str(port)))*spacer, "|"," State: ", scanner[host][proto][port]['state'])

portScan(target_url)