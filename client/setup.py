from setuptools import setup, find_packages

setup(
    name='kerberos_client',
    packages=find_packages(),
    scripts=['scripts/kerberos-client'],
    package_data={'kerberos_client': 'client.data'},
    install_requires=[
        'cryptography', 'requests'
    ]
)