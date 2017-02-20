__author__ = 'bit4'

import multiprocessing
import threading
import urlparse
import requests
import re

class Virustotal(multiprocessing.Process):
    def __init__(self, domain, subdomains=None, q=None, lock=threading.Lock(), proxy=None):
        subdomains = subdomains or []
        self.base_url = 'https://www.virustotal.com/en/domain/{domain}/information/'
        #self.domain = urlparse.urlparse(domain).netloc
        self.domain = domain
        self.subdomains = []
        self.session = requests.Session()
        self.engine_name = "Virustotal"
        multiprocessing.Process.__init__(self)
        self.lock = lock
        self.q = []
        self.timeout = 10
        self.print_banner()
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)
        print "[-] {0} found {1} domains".format(self.engine_name, len(self.q))
        return self.q

    def print_banner(self):
        print "[-] Searching now in %s.." %(self.engine_name)
        return

    def req(self, url):
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/40.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-GB,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        }

        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
        except Exception as e:
            print e
            resp = None

        return self.get_response(resp)

    def get_response(self,response):
    	if response is None:
    		return 0
        if hasattr(response, "text"):
            return response.text
        else:
            return response.content

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        link_regx = re.compile('<div class="enum.*?">.*?<a target="_blank" href=".*?">(.*?)</a>',re.S)
        try:
            links = link_regx.findall(resp)
            for link in links:
                subdomain = link.strip()
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain not in self.subdomains and subdomain != self.domain:
                    #if verbose:
                        #print "%s%s: %s%s"%(R, self.engine_name, W, subdomain)
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            pass


if __name__ == "__main__":
    x = Virustotal("meizu.com","https://127.0.0.1:9999")
    print x.run()