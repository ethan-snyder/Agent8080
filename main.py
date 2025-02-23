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

#
# #Sanitizing input
# target_url = (target_url.replace("http://", "").replace("https://", "").
#               replace("/",""))
# print("Sanitized target url: ", target_url)
#
# # Resolve domain name to IP address
# try:
#     target_ip = socket.gethostbyname(target_url)
#     print(f"Resolved IP address: {target_ip}")
# except socket.gaierror:
#     print("Error: Could not resolve the domain name.")
#     exit()

options = "-sS -sV -O -A -p1-1000,8000-8005,8080-8085"

scanner = nmap.PortScanner()
scanner.scan(target_url, arguments=options)


def portScan(url):
    print("\033[31mPort scanning...\033[0m")
    for host in scanner.all_hosts():
        print(f"Host: {host}")
        print(f"State: {scanner[host].state()}")
        for proto in scanner[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = scanner[host][proto].keys()
            for port in ports:
                port_info = scanner[host][proto][port]
                print(
                    f"Port {port:5} | State: {port_info['state']:10} | "
                    f"Service: {port_info.get('name', 'unknown'):15} | "
                    f"Version: {port_info.get('version', 'unknown')}")
    #Printing OS information
    if 'osmatch' in scanner[host]:
        print("\n--------------------------------------------------------------------------------"
              "OS Information---------------------------------------------------------------------"
              "-----------")
        for os in scanner[host]['osmatch']:
            print(f"{os['name']}, Accuracy: {os['accuracy']}%")
    if 'osclass' in os:
        for osclass in os['osclass']:
            print(f"  OS Class: {osclass.get('type', 'Unknown')}")
            print(f"  OS Family: {osclass.get('osfamily', 'Unknown')}")
            print(f"  Vendor: {osclass.get('vendor', 'Unknown')}")
            print(f"  OS Generation: {osclass.get('osgen', 'Unknown')}")


portScan(target_url)