from setuptools import setup, find_packages

setup(
    name='kerberos_client',
    packages=find_packages(),
    scripts=['scripts/kerberos-client']
#    install_requires=['os', 'cryptography', 'secrets']
)