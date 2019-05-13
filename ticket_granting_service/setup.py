from setuptools import setup, find_packages

setup(
    name='kerberos_tgs',
    packages=find_packages(),
    scripts=['scripts/kerberos-tgs', 'scripts/start-kerberos-tgs-server'],
    install_requires=[
        'flask', 'Flask-PyMongo', 'cryptography'
    ]
)