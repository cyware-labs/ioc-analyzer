import time

from ioc_analyzer.py_whois.query import DirectDomainLookup
from ioc_analyzer.utils import longint_to_str


class Whois:
    def __init__(self, **kwargs):
        pass

    def test_connectivity(self):
        return True

    def get_whois_asn_data(self, asn, **kwargs):
        print("starting whois for  asn   " + asn)
        data = {}
        start_time = time.time()

        whois_domain = DirectDomainLookup()
        try:
            data = whois_domain.get_details(domain=asn, whois_server="whois.iana.org")
        except Exception as e:
            print("WhoIS exception  occured ----asn---" + asn, e)

        print("ending whois for asn  " + asn + "   " + str(time.time() - start_time))
        return data

    def get_ip_data(self, ip, **kwargs):
        print("starting whois for  ip   " + ip)
        data = {}
        ip_data = {}
        asn_data = {}

        start_time = time.time()

        whois_domain = DirectDomainLookup()
        try:
            ip_data = whois_domain.get_details(domain=ip, whois_server="whois.iana.org")
        except Exception as e:
            print("WhoIS exception  occured ----ip---" + ip, e)

        if ip_data:
            # find asn data
            asn = None
            if ip_data.get("origin"):
                asn = ip_data.get("origin")
            elif ip_data.get("originAS"):
                asn = ip_data.get("originAS")
            elif ip_data.get("OriginAS"):
                asn = ip_data.get("OriginAS")

            if asn:
                asn_data = self.get_whois_asn_data(asn)

            data["ip_data"] = ip_data
            data["asn_data"] = asn_data
            data["updated"] = int(time.time())
            data = longint_to_str(data)

        print("ending whois for ip  " + ip + "   " + str(time.time() - start_time))
        return data

    def get_domain_data(self, domain_name, **kwargs):
        print("starting whois for  domain   " + domain_name)
        data = {}
        start_time = time.time()

        whois_domain = DirectDomainLookup()
        try:
            data = whois_domain.get_details(domain=domain_name)
        except Exception as e:
            print("WhoIS exception  occured ----domain---" + domain_name, e)

        if data and data.get("Domain Name"):
            data["updated"] = int(time.time())
            data = longint_to_str(data)

        print("ending whois for domain  " + domain_name + "   " + str(time.time() - start_time))
        return data

    def get_type_mapping(self):
        type_mapping = {
            "ip": self.get_ip_data,
            "domain": self.get_domain_data,
            "asn": self.get_whois_asn_data
        }
        return type_mapping

    def execute_whois_query(self, args):
        type_mapping = self.get_type_mapping()
        return type_mapping.get(args.type)


def get_whois_data(args):
    whois = Whois().execute_whois_query(args)
    return whois(args.query) if whois else None         
