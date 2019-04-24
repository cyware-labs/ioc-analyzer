from ioc_analyzer.py_whois.whois import get_whois_data


class IOCFactory(object):

    def __init__(self, args):
        self.args = args

    def get_command_mapping(self):
        command_mapping = {
            ('whois', True): get_whois_data,
            ('shodan', True): True,
            ('virus_total', True): True,
            ('all', True): True
        }
        return command_mapping

    def run_command(self):
        args_attr = self.args.__dict__
        print(args_attr)
        result = {}
        command_mapping = self.get_command_mapping()
        for attr in args_attr:
            if args_attr[attr] is True:
                result[attr] = command_mapping.get((attr, args_attr[attr]))(self.args)

        return result


