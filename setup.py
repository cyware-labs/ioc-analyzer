from setuptools import setup, find_packages

setup(
    name="ioc_analyzer",
    version="0.1",
    packages=find_packages(),
    entry_points={
        'console_scripts': ['ioc_analyzer=ioc_analyzer.ioc_analyzer:ioc_analyzer']
    }
)