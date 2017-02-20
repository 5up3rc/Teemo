__author__ = 'bit4'


#from wydomain
from domainsites.Alexa import Alexa
from domainsites.Chaxunla import Chaxunla
from domainsites.CrtSearch import CrtSearch
from domainsites.DNSdumpster import DNSdumpster
from domainsites.Googlect import Googlect
from domainsites.Ilink import Ilink
from domainsites.Netcraft import Netcraft
from domainsites.PassiveDNS import PassiveDNS
from domainsites.Pgpsearch import Pgpsearch
from domainsites.Sitedossier import Sitedossier
from domainsites.ThreatCrowd import ThreatCrowd
from domainsites.Threatminer import Threatminer

def callsites(key_word,proxy=None):
    final_domains = []
    final_emails = []
    enums = [enum(key_word, proxy) for enum in Alexa,Chaxunla,CrtSearch,DNSdumpster,Googlect,Ilink,Netcraft,PassiveDNS,Pgpsearch,Sitedossier,ThreatCrowd,Threatminer]
    for enum in enums:
        domain = enum.run()
        final_domains.extend(domain)
        #final_emails.extend(email)
    return list(set(final_domains))

if __name__ == "__main__":
    print callsites("meizu.com",proxy="http://127.0.0.1:9999")