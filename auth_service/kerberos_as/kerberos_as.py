from flask import Flask
from flask import request
from flask import jsonify

import json
from kerberos_as.utils.crypto import AES

from kerberos_as.models import Client

from kerberos_as.db import init_db
from kerberos_as.db import Session
from sqlalchemy.orm.exc import NoResultFound

app = Flask(__name__)
init_db()

@app.route('/require_access', methods=['POST'])
def require_access():
    request_data = json.loads(request.get_json())

    app.logger.info(json.dumps(request_data, indent=4))

    try:
        client = Client.query.filter_by(client_id=request_data['client_id']).one()
    
        content = AES.decrypt(request_data['encrypted_content'], client.key)
        
        response = 'm2_placeholder'
    except NoResultFound:
        print("Cliente não registrado")
        response = { 'Error': 'cliente não registrado' }

    return jsonify(response)

@app.teardown_appcontext
def shutdown_session(exception=None):
    Session.remove()