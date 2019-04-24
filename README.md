


# IOC Analyzer

## Installation
```
pip install -e git+https://github.com/cyware-labs/ioc-analyzer.git#egg=ioc-analyzer
```

## Usage

Domain Search (only whois)
```
ioc_analyzer <domain_name> -w --type=domain
```

IP Search (only shodan)
```
ioc_analyzer <ip_address> -s --type=ip
```

Hash Search(only virus total)
```
ioc_analyzer <hash> -v --type=hash
```

ASN Search(only whois)
```
ioc_analyzer <asn_block> -w --type=asn
```

Domain Search in all tools
```
ioc_analyzer <domain_name> -all --type=domain
```

For further help
```
ioc_analyzer --help
```

## Contact Us
Cyware Labs (https://cyware.com)
