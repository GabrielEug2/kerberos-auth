from setuptools import setup, find_packages

setup(
    name='kerberos_as',
    packages=find_packages(),
    python_requires='>=3.7',
    install_requires=[
        'flask', 'sqlalchemy', 'PyMySQL', 'cryptography'
    ],
    scripts=['scripts/kerberos-as', 'scripts/start-kerberos-as-server']
)