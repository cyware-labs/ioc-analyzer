import socket

from ioc_analyzer.py_whois.parser import RawTextWhoIsParser
from ioc_analyzer.py_whois.tld import tld_whois_dict

DEFAULT_WHOIS_PORT = 43


class SocketWrapper(object):
    NEW_LINE_CHAR = '\n'

    def __init__(self, server, port=DEFAULT_WHOIS_PORT):
        self.server = server
        self.port = port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.server, self.port))
        self.socket = s

    def query(self, data):
        data += self.NEW_LINE_CHAR
        self.socket.send(data.encode())
        message = ''
        while True:
            return_data = self.socket.recv(1000)
            if not return_data:
                break

            message += return_data.decode('utf-8', 'ignore')

        return message


class DirectDomainLookup(object):
    REFER_KEYS = ['refer', 'Registrar WHOIS Server']

    def get_whois_server(self, domain):
        tld = domain.split('.')[-1]
        whois_server = tld_whois_dict.get(tld)
        if not whois_server:
            raise Exception('Whois server not found')

        return whois_server['host']

    def get_details(self, domain, recursive=True, parse_data=True, whois_server=None):
        if whois_server is None:
            whois_server = self.get_whois_server(domain)

        raw_data = SocketWrapper(whois_server).query(domain)
        parsed_data = RawTextWhoIsParser().parse(raw_data)

        if recursive:
            for key in self.REFER_KEYS:
                if key in parsed_data and whois_server != parsed_data[key]:
                    return self.get_details(domain, recursive=recursive,
                                            parse_data=parse_data,
                                            whois_server=parsed_data[key])

        if parse_data:
            return parsed_data

        return raw_data
