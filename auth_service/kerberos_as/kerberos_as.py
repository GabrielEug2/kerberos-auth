import os
import json

from flask import Flask
from flask import request
from flask import jsonify

from kerberos_as.utils.AES import AES
from kerberos_as.database import db_session
from kerberos_as.models import Client


app = Flask(__name__)

if 'KERBEROS_AS_CONFIG' in os.environ:
    app.config.from_envvar('KERBEROS_AS_CONFIG')

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()


@app.route('/request_access', methods=['POST'])
def require_access():
    m1_data = request.get_json()

    app.logger.debug(f"Received: \n{json.dumps(m1_data, indent=4)}")

    if ('clientId' not in m1_data) or ('encryptedData' not in m1_data):
        app.logger.info("m1 mal formatada")

        response = { 'error': 'Requisição não possui os campos necessários' }
        return jsonify(response)

    # Procura o cliente
    client = Client.query.filter_by(client_id=m1_data['clientId']).first()
    client_exists = client is not None

    if client_exists:
        # Abre a parte criptografada de m1
        m1_decrypted_bytes = AES.decrypt(
            m1_data['encryptedData'].encode(),
            client.key.encode()
        )
        m1_decrypted_data = json.loads(m1_decrypted_bytes.decode())

        if (('serviceId' not in m1_decrypted_data) or
            ('requestedExpirationTime' not in m1_decrypted_data) or
            ('n1' not in m1_decrypted_data)
           ):
            app.logger.info("m1 mal formatada")

            response = { 'error': 'Requisição não possui os campos necessários' }
            return jsonify(response)

        # Constroi m2
        key_client_TGS = AES.generate_new_key()

        data_for_client = {
            'sessionKey_ClientTGS': key_client_TGS.decode(),
            'n1': m1_decrypted_data['n1']
        }
        bytes_for_client = json.dumps(data_for_client).encode()
        encrypted_bytes_for_client = AES.encrypt(bytes_for_client, client.key.encode())

        data_for_tgs = {
            'clientId': client.client_id,
            'requestedExpirationTime': m1_decrypted_data['requestedExpirationTime'],
            'sessionKey_ClientTGS': key_client_TGS.decode()
        }
        bytes_for_TGS = json.dumps(data_for_tgs).encode()
        encrypted_bytes_for_tgs = AES.encrypt(bytes_for_TGS, app.config['TGS_KEY'])

        m2 = {
            'dataForClient': encrypted_bytes_for_client.decode(),
            'ticketForTGS': encrypted_bytes_for_tgs.decode()
        }

        app.logger.info(
            f"Permissão concedida para '{client.client_id}': \n"
            f"  ID do serviço: {m1_decrypted_data['serviceId']}\n"
            f"  Prazo de validade requisitado: {m1_decrypted_data['requestedExpirationTime']}\n"
            f"  Chave de sessão para comunicação com o TGS: {key_client_TGS.decode()}"
        )

        response = m2
    else:
        app.logger.info(f"Cliente {m1_data['clientId']} não está registrado")

        response = { 'error': 'Cliente não está registrado' }

    return jsonify(response)
