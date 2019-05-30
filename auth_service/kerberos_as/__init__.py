
import os

from flask import Flask

def create_app():
    app = Flask(__name__)

    app.config.from_envvar('AS_CONFIG_FILE')

    # Setup database
    os.environ['SQLALCHEMY_DATABASE_URI'] = app.config['DB_URI']

    from kerberos_as.database import init_db
    init_db()

    # Remove session after each request
    from kerberos_as.database import db_session

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        db_session.remove()
    
    # Register blueprints
    from kerberos_as import routes
    app.register_blueprint(routes.bp)

    return app