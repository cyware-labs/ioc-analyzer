import time
import json
import ipaddr
import requests
import os

from ioc_analyzer.utils import longint_to_str


class VirusTotal:
    base_url = None
    api_key = None

    def __init__(self, base_url, access_key, secret_key, **kwargs):
        self.base_url = base_url
        self.api_key = access_key
        self.data = []
        self.links = []

    def test_connectivity(self):
        return True

    def get_hash_data(self, hash_value, **kwargs):
        start_time = time.time()
        print("starting virus total for  file hash  " + hash_value)

        site_url = 'file/report'
        data = {}

        params = {'resource': hash_value, 'apikey': self.api_key}
        r = requests.get(url=self.base_url + site_url, params=params)

        if r.status_code == 200:
            try:
                data = r.json()
            except Exception as e:
                print("Hash Virus Total exception  occured - - - - -" + str(hash_value),
                      e)

        if data:
            data["updated"] = int(time.time())
            data = longint_to_str(data)

        print("ending virus total for  file hash  " + hash_value + "    " + str(
            time.time() - start_time))
        return data

    def get_ip_data(self, ip, **kwargs):
        start_time = time.time()
        print("starting virus total for  ip   " + ip)

        site_url = 'ip-address/report'
        data = {}

        try:
            ip_details = ipaddr.IPAddress(ip)
        except ValueError:
            print("NOT A VALID IP - ", ip)
            return data

        if ip_details.version == 4:
            params = {'ip': ip, 'apikey': self.api_key}
            r = requests.get(url=self.base_url + site_url, params=params)

            if r.status_code == 200:
                try:
                    data = r.json()
                except Exception as e:
                    print("IP Virus Total exception  occured - - - - -" + str(ip), e)

            # elif r.status_code == 204:
            #     time.sleep(15.1)
            #     r = requests.get(url=virus_total_base_url + site_url, params=params)
            #
            #     if r.status_code == 200:
            #         try:
            #             data = r.json()
            #         except Exception as e:
            #             print("IP Virus Total exception  occured - - - - -" +
            # virus_total_base_url, e)

            if data:
                data["updated"] = int(time.time())
                data = longint_to_str(data)

            print(
                "ending virus total for ip  " + ip + "  " + str(time.time() - start_time))
            return data
        else:
            print(
                "ending virus total for ip  " + ip + "  " + str(time.time() - start_time))
            print("NOT A VALID IPV4 ", ip)
            return data

    def get_domain_data(self, domain_name, **kwargs):
        start_time = time.time()
        print("starting virus total for  domain   " + domain_name)

        site_url = 'domain/report'
        params = {'domain': domain_name, 'apikey': self.api_key}

        data = {}
        r = requests.get(url=self.base_url + site_url, params=params)

        if r.status_code == 200:
            try:
                data = r.json()
                resolutions = data.get("resolutions")

                if resolutions and len(resolutions) > 0:
                    ip = resolutions[0]["ip_address"]

            except Exception as e:
                print(
                    "Domain Virus Total exception  occured - - - - -" + str(domain_name),
                    e)

        # elif r.status_code == 204:
        #     time.sleep(15.1)
        #
        #     r = requests.get(url=virus_total_base_url + site_url, params=params)
        #     if r.status_code == 200:
        #         try:
        #             data = r.json()
        #
        #         except Exception as e:
        #             print("Domain Virus Total exception  occured - - - - -" +
        # virus_total_base_url, e)

        if data:
            data["updated"] = int(time.time())
            data = longint_to_str(data)

        print("ending virus total for domain  " + domain_name + "  " + str(
            time.time() - start_time))
        return data

    def get_url_data(self, url, **kwargs):
        start_time = time.time()
        print("starting virus total for  url   " + url)

        site_url = 'url/report'
        params = {'resource': url, 'apikey': self.api_key}

        data = {}
        r = requests.post(url=self.base_url + site_url, params=params)
        if r.status_code == 200:
            try:
                data = r.json()
            except Exception as e:
                print("Url Virus Total exception  occured - - - - -" + str(url), e)

        elif r.status_code == 204:
            time.sleep(15.1)

            r = requests.post(url=self.base_url + site_url, params=params)
            if r.status_code == 200:
                try:
                    data = r.json()

                except Exception as e:
                    print("Url Virus Total exception  occured - - - - -" + str(url), e)

        print(data)
        if data:
            data["updated"] = int(time.time())
            data = longint_to_str(data)

        print("ending virus total for url  " + url + "  " + str(
            time.time() - start_time))
        return data

    def get_type_mapping(self):
        type_mapping = {
            "ip": self.get_ip_data,
            "domain": self.get_domain_data,
            "hash": self.get_hash_data,
            "url": self.get_url_data
        }
        return type_mapping

    def execute_query(self, args):
        type_mapping = self.get_type_mapping()
        return type_mapping.get(args.type)


def get_virus_total_data(args):
    keys = None
    with open('api_keys.json', 'r') as f:
        keys = f.read()
    access_key = None
    if keys:
        dict_data = json.loads(keys)
        access_key = dict_data["VIRUS_TOTAL_KEY"]
    base_url = "https://www.virustotal.com/vtapi/v2/"
    access_key = access_key or os.environ.get('VIRUS_TOTAL_KEY')
    virus_total = VirusTotal(base_url, access_key, None).execute_query(args)
    return virus_total(args.query) if virus_total else None
