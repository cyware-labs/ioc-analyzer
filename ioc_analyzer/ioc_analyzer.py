import argparse
from ioc_analyzer.ioc_factory import IOCFactory
from pprint import pprint


def ioc_analyzer():
    parser = argparse.ArgumentParser()

    parser.add_argument("query", help="Print the word in upper case letters")
    parser.add_argument(
        "-t",
        '--type',
        dest="type",
        default='ip',
        help="Type of the query IP, Domain, hash, URL"
    )
    parser.add_argument(
        '-s',
        '--shodan',
        action='store_true',
        dest='shodan',
        default=False,
        help="Seach query in shodan"
    )
    parser.add_argument(
        '-vi',
        '--virus_total',
        action='store_true',
        dest='virus_total',
        default=False,
        help="Search query in Virus Total"
    )
    parser.add_argument(
        '-w',
        '--whois',
        action='store_true',
        dest='whois',
        default=False,
        help="Search query in whois"
    )
    parser.add_argument(
        '-A',
        '--all',
        action='store_true',
        dest='all',
        default=False,
        help="Search query in all tools"
    )

    args = parser.parse_args()
    pprint(IOCFactory(args).run_command())
