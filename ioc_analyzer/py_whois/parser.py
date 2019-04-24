from abc import ABC
from abc import abstractmethod


class AbstractBaseParser(ABC):
    """
    Abstract base class to parse whois data
    """
    @abstractmethod
    def parse(self, data, *args, **kwargs):
        """Method to parse the data"""
        pass


class RawTextWhoIsParser(AbstractBaseParser):
    """Class to parse whois data provided in the plain text format"""

    def parse(self, data, *args, **kwargs):
        data_lines = data.splitlines()
        data_dict = {}
        for data_line in data_lines:
            date_key_val = data_line.split(': ')
            if len(date_key_val) == 2:
                key = date_key_val[0].replace(">>>", "").replace("%", "").replace("#", "")
                value = date_key_val[1].replace("<<<", "")
                value = value.strip()
                if not value:
                    value = None
                data_dict[key.strip()] = value

        data_dict["raw_data"] = data
        return data_dict

