from ioc_analyzer.py_whois.whois import get_whois_data
from ioc_analyzer.shodan.shodan import get_shodan_data
from ioc_analyzer.virus_total.virus_total import get_virus_total_data


class IOCFactory(object):

    def __init__(self, args):
        self.args = args

    def get_command_mapping(self):
        command_mapping = {
            ('whois', True): get_whois_data,
            ('shodan', True): get_shodan_data,
            ('virus_total', True): get_virus_total_data,
        }
        return command_mapping

    def run_command(self):
        args_attr = self.args.__dict__
        result = {}
        command_mapping = self.get_command_mapping()
        for attr in args_attr:
            if attr != 'all' and args_attr[attr] is True:
                result[attr] = command_mapping.get((attr, args_attr[attr]))(self.args)

        all_flag = True
        for attr in args_attr:
            if args_attr[attr] is True:
                all_flag = False

        if args_attr['all'] is True or all_flag is True:
            for command in command_mapping:
                result[command[0]] = command_mapping[command](self.args)

        return result


