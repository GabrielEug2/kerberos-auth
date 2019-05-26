from setuptools import setup, find_packages

setup(
    name='kerberos_tgs',
    packages=find_packages(),
    python_requires='>=3.7',
    install_requires=[
        'flask', 'Flask-PyMongo', 'pymongo', 'cryptography'
    ],
    scripts=['scripts/kerberos-tgs', 'scripts/start-kerberos-tgs-server']
)