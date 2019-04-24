import time

import ipaddr
import requests
import os

from ioc_analyzer.utils import longint_to_str


class Shodan:

    base_url = None
    api_key = None

    def __init__(self, base_url, access_key, secret_key, **kwargs):
        self.base_url = base_url
        self.api_key = access_key

    def test_connectivity(self):
        return True

    def get_ip_data(self, ip, **kwargs):
        data = {}
        start_time = time.time()
        print("starting shodan for  ip  " + ip)

        try:
            ipaddr.IPAddress(ip)
        except ValueError:
            print("ending shodan for ip  " + str(time.time() - start_time))
            print("NOT A VALID IP - ", ip)
            return data

        site_url = '/shodan/host/' + ip + "?key=" + self.api_key
        r = requests.get(url=self.base_url + site_url)

        if r.status_code == 200:
            try:
                data = r.json()
            except Exception as e:
                print("IP Shodan exception  occured - - - - -" + site_url, e)
        else:
            print("IP Shodan exception  occured - - - - -" + site_url, r.status_code)

        if data:
            data["updated"] = int(time.time())
            data = longint_to_str(data)

        print("ending shodan for ip  " + ip + "   " + str(time.time() - start_time))
        return data

    def get_domain_data(self, domain_name, **kwargs):
        start_time = time.time()
        print("starting shodan for doamin   " + domain_name)
        domain_url = "/shodan/host/search" + "?key=" + self.api_key + "&query=" + 'hostname:' + domain_name
        data = {}
        r = requests.get(url=self.base_url + domain_url)

        if r.status_code == 200:
            try:
                data = r.json()
            except Exception as e:
                print("Shodan exception  occured - - - - -" + "----domain---" + domain_name, e)

        else:
            print("Shodan Error  occured - - - - -" + domain_name, r.status_code)

        if data:
            data["updated"] = int(time.time())
            data = longint_to_str(data)

        print("ending shodan for domain  " + domain_name + "  " + str(time.time() - start_time))
        return data

    def get_type_mapping(self):
        type_mapping = {
            "ip": self.get_ip_data,
            "domain": self.get_domain_data
        }
        return type_mapping

    def execute_shodan_query(self, args):
        type_mapping = self.get_type_mapping()
        return type_mapping.get(args.type)


def get_shodan_data(args):
    base_url = "https://api.shodan.io"
    access_key = os.environ.get("SHODAN_ACCESS_KEY")
    shodan = Shodan(base_url, access_key, None).execute_shodan_query(args)
    return shodan(args.query) if shodan else None
