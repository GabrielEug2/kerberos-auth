
# See: http://flask.pocoo.org/docs/1.0/patterns/sqlalchemy/#declarative

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

#DB_URL = 'sqlite:///database.db'
DB_URL = 'mysql+pymysql://kerberos_as:kerberos_as@127.0.0.1/kerberos_as_db'

engine = create_engine(DB_URL)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

def init_db():
    # import all modules here that might define models so that
    # they will be registered properly on the metadata.  Otherwise
    # you will have to import them first before calling init_db()
    import kerberos_as.models
    Base.metadata.create_all(bind=engine)