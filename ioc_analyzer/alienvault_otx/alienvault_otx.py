import time
import json
import ipaddr
import requests
import os

from ioc_analyzer.utils import longint_to_str


class AlienVaultOTX:

    def __init__(self, base_url, access_key, secret_key, **kwargs):
        self.base_url = base_url
        self.api_key = access_key

    def test_connectivity(self):
        return True

    def get_ip_data(self, ip, **kwargs):
        data = {}
        start_time = time.time()
        print("starting alienvault OTX for  ip  " + ip)

        try:
            ipaddr.IPAddress(ip)
        except ValueError:
            print("ending shodan for ip  " + str(time.time() - start_time))
            print("NOT A VALID IP - ", ip)
            return data

        site_url = 'api/v1/indicators/IPv4/' + ip + '/general'
        r = requests.get(url=self.base_url + site_url)

        if r.status_code == 200:
            try:
                data = r.json()
            except Exception as e:
                print("IP alienvault otx exception  occured - - - - -" + site_url, e)
        else:
            print("IP alienvault otx exception  occured - - - - -" + site_url, r.status_code)

        if data:
            data["updated"] = int(time.time())
            data = longint_to_str(data)

        print("ending alienvailt otx for ip  " + ip + "   " + str(time.time() - start_time))
        return data

    def get_domain_data(self, domain_name, **kwargs):
        start_time = time.time()
        print("starting alienvault OTX for doamin   " + domain_name)
        domain_url = 'api/v1/indicators/domain/' + domain_name + '/general'

        data = {}
        r = requests.get(url=self.base_url + domain_url)

        if r.status_code == 200:
            try:
                data = r.json()
            except Exception as e:
                print("alienvault otx exception  occured - - - - -" + "----domain---" + domain_name, e)

        else:
            print("alienvault otx Error  occured - - - - -" + domain_name, r.status_code)

        if data:
            data["updated"] = int(time.time())
            data = longint_to_str(data)

        print("ending alienvault otx for domain  " + domain_name + "  " + str(time.time() - start_time))
        return data

    def get_type_mapping(self):
        type_mapping = {
            "ip": self.get_ip_data,
            "domain": self.get_domain_data
        }
        return type_mapping

    def execute_query(self, args):
        type_mapping = self.get_type_mapping()
        return type_mapping.get(args.type)


def get_alienvault_otx_data(args):
    keys = None
    with open('api_keys.json', 'r') as f:
        keys = f.read()
    access_key = None
    if keys:
        dict_data = json.loads(keys)
        access_key = dict_data["ALIENVAULT_OTX_KEY"]
    base_url = "https://otx.alienvault.com/"
    access_key = access_key or os.environ.get("ALIENVAULT_OTX_KEY")
    alienvault = AlienVaultOTX(base_url, access_key, None).execute_query(args)
    return alienvault(args.query) if alienvault else None
