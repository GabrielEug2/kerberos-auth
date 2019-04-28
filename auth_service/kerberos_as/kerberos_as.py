from flask import Flask
from flask import request
from flask import jsonify

import json
from kerberos_as.utils.crypto import AES

from kerberos_as.models import Client
from kerberos_as.models import Server

from kerberos_as import db

app = Flask(__name__)

session = db.Session()

tgs_server = Server.query.filter_by(server_id='TGS').first()
if tgs_server is not None:
    TGS_KEY = tgs_server.key
else:
    print("TGS não registrado")
    print("Configure a aplicação primeiro.")
    exit()

session.close()


@app.route('/require_access', methods=['POST'])
def require_access():
    request_data = json.loads(request.get_json())

    app.logger.info(f"Received: \n{json.dumps(request_data, indent=4)}")

    # Procura o cliente
    session = db.Session()

    client = Client.query.filter_by(client_id=request_data['client_id']).first()
    client_exists = client is not None

    if client_exists:
        m1_content = AES.decrypt(
            request_data['encrypted_data']['content'],
            client.key,
            request_data['encrypted_data']['iv']
        )
        m1_content = json.loads(m1_content)
        
        # Constroi m2
        key_client_TGS = AES.generate_new_key()

        data_to_client = {
            'key client-tgs': key_client_TGS,
            'n1': m1_content['n1']
        }
        encrypted_data_to_client, iv_to_client = AES.encrypt(json.dumps(data_to_client), client.key)

        data_to_tgs = {
            'client_id': client.client_id,
            'ticket_expiration_date': m1_content['ticket_expiration_date'],
            'key client-tgs': key_client_TGS
        }
        encrypted_data_to_tgs, iv_to_tgs = AES.encrypt(json.dumps(data_to_tgs), TGS_KEY)

        m2 = {
            'client_response': {
                'content': encrypted_data_to_client,
                'iv': iv_to_client
            },
            'ticket client-tgs': {
                'content': encrypted_data_to_tgs,
                'iv': iv_to_tgs
            }
        }

        response = m2
    else:
        print("Cliente não registrado")
        response = {
            'Erro': 'cliente não registrado'
        }

    app.logger.info(f"Sent: \n{json.dumps(response, indent=4)}")

    session.close()

    return jsonify(response)