# !/usr/bin/env python
# -*- coding:utf-8 -*-
__author__ = 'bit4'

import os
import argparse
import urlparse
import socket
from lib.common import *
from subbrute import subbrute
import threading
import multiprocessing
from domainsites.callsites import callsites
from searchengine.searchimpl import callengines

from config import GoogleCSE_API_Key,proxies

#In case you cannot install some of the required development packages, there's also an option to disable the SSL warning:
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass

#Check if we are running this on windows platform
is_windows = sys.platform.startswith('win')

#Console Colors
if is_windows:
    G = Y = B = R = W = G = Y = B = R = W = '' #use no terminal colors on windows
else:
    G = '\033[92m' #green
    Y = '\033[93m' #yellow
    B = '\033[94m' #blue
    R = '\033[91m' #red
    W = '\033[0m'  #white

def banner():
    print """%s

          #####  ######  ######  #    #   ####
            #    #       #       ##  ##  #    #
            #    #####   #####   # ## #  #    #
            #    #       #       #    #  #    #
            #    #       #       #    #  #    #
            #    ######  ######  #    #   ####

            %s%s

         # Coded By bit4 - https://github.com/bit4woo

  """ % (R, W, Y)

def parser_error(errmsg):
    banner()
    print "Usage: python "+sys.argv[0]+" [Options] use -h for help"
    print R+"Error: "+errmsg+W
    sys.exit()

def parse_args():
    #parse the arguments
    parser = argparse.ArgumentParser(epilog = '\tExample: \r\npython '+sys.argv[0]+" -d google.com")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain name to enumrate it's subdomains", required=True)
    parser.add_argument('-b', '--bruteforce', help='Enable the subbrute bruteforce module',nargs='?', default=False)
    parser.add_argument('-p', '--ports', help='Scan the found subdomains against specified tcp ports')
    #parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime',nargs='?', default=False)
    #parser.add_argument('-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)
    parser.add_argument('-o', '--output', help='Save the results to text file')
    parser.add_argument('-x', '--proxy', help='The http proxy to visit google')
    return parser.parse_args()

def write_file(filename, subdomains):
    #saving subdomains results to output file
    print "%s[-] Saving results to file: %s%s%s%s"%(Y,W,R,filename,W)
    with open(str(filename), 'wb') as f:
        for subdomain in subdomains:
            f.write(subdomain+"\r\n")

class portscan():

    def __init__(self,subdomains,ports):
        self.subdomains = subdomains
        self.ports = ports
        self.threads = 20
        self.lock = threading.BoundedSemaphore(value=self.threads)

    def port_scan(self,host,ports):
        openports = []
        self.lock.acquire()
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((host, int(port)))
                if result == 0:
                    openports.append(port)
                s.close
            except Exception as e:
                pass
        self.lock.release()
        if len(openports) > 0:
            print "%s%s%s - %sFound open ports:%s %s%s%s"%(G,host,W,R,W,Y,', '.join(openports),W)

    def run(self):
        for subdomain in self.subdomains:
            t = threading.Thread(target=self.port_scan,args=(subdomain,self.ports))
            t.start()

def main():
    args = parse_args()
    domain = args.domain
    #threads = args.threads
    savefile = args.output
    ports = args.ports
    bruteforce_list = []
    subdomains = []

    if args.proxy != None:
        proxy = args.proxy
        proxy = {args.proxy.split(":")[0]: proxy}
    else:
        proxy = proxies

    #Check Verbosity
    #global verbose
    #verbose = args.verbose
    #if verbose or verbose is None:
        #verbose = True

    #Check Bruteforce Status
    enable_bruteforce = args.bruteforce
    if enable_bruteforce or enable_bruteforce is None:
        enable_bruteforce = True

    #Validate domain
    if not is_domain(domain):
        print R+"Error: Please enter a valid domain"+W
        sys.exit()


    #Print the Banner
    banner()
    print B+"[-] Enumerating subdomains now for %s"% domain+W

    subdomains.extend(callsites(domain,proxy))
    domains,emails = callengines(domain,500,proxy)
    subdomains.extend(domains)
    #print subdomains

    if enable_bruteforce:
        print G+"[-] Starting bruteforce module now using subDomainsBrute.."+W
        record_type = False
        path_to_file = os.path.dirname(os.path.realpath(__file__))
        subs = os.path.join(path_to_file, 'dict', 'names.txt')
        resolvers = os.path.join(path_to_file, 'resolvers.txt')
        process_count = 10
        output = False
        json_output = False
        bruteforce_list = subbrute.print_target(domain, record_type, subs, resolvers, process_count, output, json_output, subdomains)

        subdomains.extend(bruteforce_list)
        print subdomains
        print len(subdomains)


    print "[+] {0} domains found in total".format(len(subdomains))
    print "[+] {0} emails found in total".format(len(emails))

    if subdomains is not None:
        subdomains = sorted(subdomains)
        emails = sorted(emails)
        subdomains.extend(emails) #this function return value is NoneType ,can't use in function directly
        #print type(subdomains)
        if savefile:
            write_file(savefile, subdomains)
        else:
            write_file(domain, subdomains)


        if ports:
            print G+"[-] Start port scan now for the following ports: %s%s"%(Y,ports)+W
            ports = ports.split(',') #list
            pscan = portscan(subdomains,ports)
            pscan.run()

        else:
            for subdomain in subdomains:
                print G+subdomain+W

if __name__=="__main__":
    main()
