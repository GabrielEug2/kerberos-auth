
from sqlalchemy import Column, String

from kerberos_as.database import Base

class Client(Base):
    __tablename__ = 'clients'

    client_id = Column(String(30), primary_key=True)
    key = Column(String(100))

    def __init__(self, client_id, client_key):
        self.client_id = client_id
        self.key = client_key.decode()