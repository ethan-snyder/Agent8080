#Importing Packages
import requests
from bs4 import BeautifulSoup
import scrapy
from scrapy.crawler import CrawlerProcess
import socket
import nmap
from termcolor import colored

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

optionsTCP = "-sS -sV -O -A -p1-1000,8000-8005,8080-8085"
optionsUDP = "-sU -p53,67,68,69,88,123,137,138,139,161,162,500,1434,1900,2049,5060,5061,5353,11211"

scannerTCP = nmap.PortScanner()
scannerTCP.scan(target_url, arguments=optionsTCP)

scannerUDP = nmap.PortScanner()
scannerUDP.scan(target_url, arguments=optionsUDP)

def scanARP(targetIP):
    print("\033[31mARP SCANNING...\033[0m")
    for host in scannerUDP.all_hosts():
        print(f"Host: {host}")
        print(f"State: {scannerUDP[host].state()}")
        for proto in scannerUDP[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = scannerUDP[host][proto].keys()
            for port in ports:
                port_info = scannerUDP[host][proto][port]
                print(
                    f"Port {port:5} | State: {port_info['state']:10} | "
                    f"Service: {port_info.get('name', 'unknown'):15} | "
                    f"Version: {port_info.get('version', 'unknown')}")


def portScanTCP(url):
    print("\033[31mTCP SCANNING...\033[0m")
    for host in scannerTCP.all_hosts():
        print(f"Host: {host}")
        print(f"State: {scannerTCP[host].state()}")
        for proto in scannerTCP[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = scannerTCP[host][proto].keys()
            for port in ports:
                port_info = scannerTCP[host][proto][port]
                print(
                    f"Port {port:5} | State: {port_info['state']:10} | "
                    f"Service: {port_info.get('name', 'unknown'):15} | "
                    f"Version: {port_info.get('version', 'unknown')}")
    #Printing OS information
    if 'osmatch' in scannerTCP[host]:
        print("\033[31m\n--------------------------------------------------------------------------------"
              "OS Information---------------------------------------------------------------------"
              "-----------\033[0m")
        for os in scannerTCP[host]['osmatch']:
            print(f"{os['name']}, Accuracy: {os['accuracy']}%")
    if 'osclass' in os:
        for osclass in os['osclass']:
            print(f"  OS Family: {osclass.get('osfamily', 'Unknown')}")
            print(f"  OS Generation: {osclass.get('osgen', 'Unknown')}")
            print(f"  Vendor: {osclass.get('vendor', 'Unknown')}")
            print(f"  OS Class: {osclass.get('type', 'Unknown')}")



portScanTCP(target_url)
scanARP(target_url)