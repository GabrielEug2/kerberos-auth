
# See: http://flask.pocoo.org/docs/1.0/patterns/sqlalchemy/#declarative

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker

#DB_URL = 'sqlite:///database.db'
DB_URL = 'mysql+mysqldb://kerberos_as:kerberos_as@127.0.0.1/kerberos_auth_service'

engine = create_engine(DB_URL)
Session = scoped_session(sessionmaker(bind=engine))

Base = declarative_base(bind=engine)
Base.query = Session.query_property()

def init_db():
    # Cria o banco e as tabelas, se ainda não existirem
    import kerberos_as.models

    Base.metadata.create_all(bind=engine)

def drop_db():
    Base.metadata.drop_all(bind=engine)