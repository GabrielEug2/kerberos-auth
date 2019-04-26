from kerberos_as.db import Base
from sqlalchemy import Column, String

import secrets

class Client(Base):
    __tablename__ = 'clients'

    client_id = Column(String(30), primary_key=True)
    key = Column(String(100))

    def __init__(self, client_id):
        self.client_id = client_id
        self.key = self._generate_key()

    def _generate_key(self):
        return secrets.token_hex(32)