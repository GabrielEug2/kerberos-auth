from flask import Flask
from flask import request
from flask import jsonify

import json
from kerberos_as.utils.AES import AES

from kerberos_as.database import db_session
from kerberos_as.models import Client

import os

app = Flask(__name__)
if 'KERBEROS_AS_CONFIG' in os.environ:
    app.config.from_envvar('KERBEROS_AS_CONFIG')

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()


@app.route('/request_access', methods=['POST'])
def require_access():
    request_data = json.loads(request.get_json())

    app.logger.info(f"Received: \n{json.dumps(request_data, indent=4)}")

    # Procura o cliente
    client = Client.query.filter_by(client_id=request_data['clientId']).first()
    client_exists = client is not None

    if client_exists:
        # Abre a parte criptografada da mensagem
        m1_data_as_bytes = AES.decrypt(
            request_data['encryptedData'].encode(),
            client.key.encode()
        )
        
        m1_decrypted_data = json.loads(m1_data_as_bytes.decode())

        # Constroi m2
        key_client_TGS = AES.generate_new_key()

        data_for_client = {
            'sessionKey_ClientTGS': key_client_TGS.decode(),
            'n1': m1_decrypted_data['n1']
        }

        data_for_client_as_bytes = json.dumps(data_for_client).encode()
        encrypted_bytes_for_client = AES.encrypt(data_for_client_as_bytes, client.key.encode())

        data_for_tgs = {
            'clientId': client.client_id,
            'requestedExpirationTime': m1_decrypted_data['requestedExpirationTime'],
            'sessionKey_ClientTGS': key_client_TGS.decode()
        }

        data_for_TGS_as_bytes = json.dumps(data_for_tgs).encode()
        encrypted_bytes_for_tgs = AES.encrypt(data_for_TGS_as_bytes, app.config['TGS_KEY'])

        m2 = {
            'encryptedData': encrypted_bytes_for_client.decode(),
            'ticketForTGS': encrypted_bytes_for_tgs.decode()
        }

        response = m2
    else:
        print("Cliente não registrado")
        response = {
            'Erro': 'cliente não registrado'
        }

    app.logger.info(f"Sending: \n{json.dumps(response, indent=4)}")

    return jsonify(response)
