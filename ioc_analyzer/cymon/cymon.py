import time
import json
import ipaddr
import requests
import os

from ioc_analyzer.utils import longint_to_str


class Cymon:

    def __init__(self, base_url, access_key, secret_key, **kwargs):
        self.base_url = base_url
        self.api_key = access_key

    def test_connectivity(self):
        return True

    def get_ip_data(self, ip, **kwargs):
        data = {}
        start_time = time.time()
        print("starting cymon for  ip  " + ip)

        try:
            ipaddr.IPAddress(ip)
        except ValueError:
            print("ending cymon for ip  " + str(time.time() - start_time))
            print("NOT A VALID IP - ", ip)
            return data

        site_url = '/api/nexus/v1/ip/' + ip
        token = "Token " + self.api_key
        header = {'Authorization': token}
        r = requests.get(url=self.base_url + site_url, headers=header)

        if r.status_code == 200:
            try:
                data = r.json()
            except Exception as e:
                print("IP cymon exception  occured - - - - -" + site_url, e)
        else:
            print("IP cymon exception  occured - - - - -" + site_url, r.status_code)

        if data:
            data["updated"] = int(time.time())
            data = longint_to_str(data)

        print("ending cymon for ip  " + ip + "   " + str(time.time() - start_time))
        return data

    def get_domain_data(self, domain_name, **kwargs):
        start_time = time.time()
        print("starting cymon for doamin   " + domain_name)

        domain_url = '/api/nexus/v1/domain/' + domain_name
        token = "Token " + self.api_key
        header = {'Authorization': token}
        r = requests.get(url=self.base_url + domain_url, headers=header)

        if r.status_code == 200:
            try:
                data = r.json()
            except Exception as e:
                print("domain cymon exception  occured - - - - -" + domain_url, e)
        else:
            print("domain cymon exception  occured - - - - -" + domain_url, r.status_code)

        if data:
            data["updated"] = int(time.time())
            data = longint_to_str(data)

        print("ending cymon for ip  " + ip + "   " + str(time.time() - start_time))
        return data

    def get_type_mapping(self):
        type_mapping = {
            "ip": self.get_ip_data,
            "domain": self.get_domain_data
        }

        return type_mapping

    def execute_query(self, args):
        type_mappings = self.get_type_mapping()
        return type_mappings.get(args.type)


def get_cymon_data(args):
    keys = None
    with open('api_keys.json', 'r') as f:
        keys = f.read()
    access_key = None
    if keys:
        dict_data = json.loads(keys)
        access_key = dict_data["CYMON_KEY"]
    base_url = "https://cymon.io"
    access_key = access_key or os.environ.get("CYMON_KEY")
    cymon = Cymon(base_url, access_key, None).execute_query(args)
    return cymon(args.query) if cymon else None


