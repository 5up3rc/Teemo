__author__ = 'bit4'
#wydomain
# encoding: utf-8

import re
import time
import logging
from lib.common import http_request_get, http_request_post, is_domain

class Alexa(object):
    """docstring for Alexa"""
    def __init__(self, domain,proxy=None):
        super(Alexa, self).__init__()
        self.domain = domain
        self.subset = []
        self.engine_name = "Alexa"

    def run(self):
        try:
            self.fetch_chinaz()
            self.fetch_alexa_cn()
            self.subset = list(set(self.subset))
            print "[-] {0} found {1} domains".format(self.engine_name, len(self.subset))
            return self.subset
        except Exception as e:
            logging.info(str(e))
            print "[-] {0} found {1} domains".format(self.engine_name, len(self.subset))
            return self.subset

    def fetch_chinaz(self):
        """get subdomains from alexa.chinaz.com"""

        url = 'http://alexa.chinaz.com/?domain={0}'.format(self.domain)
        r = http_request_get(url).content
        subs = re.compile(r'(?<="\>\r\n<li>).*?(?=</li>)')
        result = subs.findall(r)
        for sub in result:
            if is_domain(sub):
                self.subset.append(sub)

    def fetch_alexa_cn(self):
        """get subdomains from alexa.cn"""
        sign = self.get_sign_alexa_cn()
        if sign is None:
            raise Exception("sign_fetch_is_failed")
        else:
            (domain,sig,keyt) = sign

        pre_domain = self.domain.split('.')[0]

        url = 'http://www.alexa.cn/api_150710.php'
        payload = {
            'url': domain,
            'sig': sig,
            'keyt': keyt,
            }
        r = http_request_post(url, payload=payload).text

        for sub in r.split('*')[-1:][0].split('__'):
            if sub.split(':')[0:1][0] == 'OTHER':
                break
            else:
                sub_name = sub.split(':')[0:1][0]
                sub_name = ''.join((sub_name.split(pre_domain)[0], domain))
                if is_domain(sub_name):
                    self.subset.append(sub_name)

    def get_sign_alexa_cn(self):
        """alexa.cn dectect signtrue, sig & keyt"""

        url = 'http://www.alexa.cn/index.php?url={0}'.format(self.domain)
        r = http_request_get(url).text
        sign = re.compile(r'(?<=showHint\(\').*?(?=\'\);)').findall(r)
        if len(sign) >= 1:
            return sign[0].split(',')
        else:
            return None

if __name__ == "__main__":
        x = Alexa("meizu.com",proxy="http://127.0.0.1:9999")
        print  x.run()