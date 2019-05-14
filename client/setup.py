from setuptools import setup, find_packages

setup(
    name='kerberos_client',
    packages=find_packages(),
    python_requires='>=3.7',
    install_requires=[
        'cryptography', 'requests'
    ],
    scripts=['scripts/kerberos-client'],
    # package_data={'kerberos_client': 'client.data'}
)