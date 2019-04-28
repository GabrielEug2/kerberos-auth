from kerberos_as.db import Base
from sqlalchemy import Column, String

from kerberos_as.utils.crypto import AES

class Client(Base):
    __tablename__ = 'clients'

    client_id = Column(String(30), primary_key=True)
    key = Column(String(100))

    def __init__(self, client_id):
        self.client_id = client_id
        self.key = AES.generate_new_key()


class Server(Base):
    __tablename__ = 'servers'

    server_id = Column(String(30), primary_key=True)
    key = Column(String(100))

    def __init__(self, server_id):
        self.server_id = server_id
        self.key = AES.generate_new_key()