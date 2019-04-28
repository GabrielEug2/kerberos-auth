
# See: http://flask.pocoo.org/docs/1.0/patterns/sqlalchemy/#declarative

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker

#engine = create_engine('sqlite:///database.db')
engine = create_engine('mysql+mysqldb://kerberos_as:kerberos_as@127.0.0.1/kerberos_auth_service')
Session = scoped_session(sessionmaker(bind=engine))

Base = declarative_base(bind=engine)
Base.query = Session.query_property()

def init_db():
    import kerberos_as.models

    Base.metadata.create_all(bind=engine)