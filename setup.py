from setuptools import setup, find_packages

requirement = [
    '''
    certifi==2019.3.9
    chardet==3.0.4
    idna==2.8
    ipaddr==2.2.0
    requests==2.21.0
    urllib3==1.24.2
    '''
]

setup(
    name="ioc_analyzer",
    version="0.1",
    packages=find_packages(),
    entry_points={
        'console_scripts': ['ioc_analyzer=ioc_analyzer.ioc_analyzer:ioc_analyzer']
    },
    install_requires=requirement
)