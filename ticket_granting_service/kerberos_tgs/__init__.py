
from flask import Flask

from kerberos_tgs.database import init_db

def create_app():
    app = Flask(__name__)

    app.config.from_envvar('TGS_CONFIG_FILE')

    # Setup database
    app.config["MONGO_URI"] = "mongodb://localhost:27017/kerberos_tgs_db"
    init_db(app)

    # Register blueprints
    from kerberos_tgs import routes
    app.register_blueprint(routes.bp)

    return app