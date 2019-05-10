from setuptools import setup, find_packages

setup(
    name='kerberos_as',
    packages=find_packages(),
    scripts=['scripts/kerberos-as', 'scripts/start-kerberos-as-server'],
    package_data={'kerberos_as': 'config'}
)