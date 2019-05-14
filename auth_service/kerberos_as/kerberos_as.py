import os
import json

from flask import Flask
from flask import request
from flask import jsonify

from kerberos_as.utils.crypto import Crypto
from kerberos_as.utils import dictutils
from kerberos_as.models import Client
from kerberos_as.database import db_session


app = Flask(__name__)
if 'KERBEROS_AS_CONFIG' in os.environ:
    app.config.from_envvar('KERBEROS_AS_CONFIG')

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()


@app.route('/request_access', methods=['POST'])
def request_access():
    message1 = request.get_json()
    app.logger.debug(f"Received: \n{json.dumps(message1, indent=4)}")

    if not dictutils.has_keys(message1, ['clientId', 'encryptedData']):
        app.logger.info('Mensagem não segue o formato especificado')
        return jsonify(error=('Mensagem não segue o formato especificado. '
                              'Verifique a documentação.'))

    # Procura o cliente
    client = Client.query.filter_by(client_id=message1['clientId']).first()
    client_exists = client is not None

    if not client_exists:
        app.logger.info(f"Cliente {message1['clientId']} não está registrado")
        return jsonify(error='Cliente não registrado.')

    # Abre a parte criptografada da mensagem
    decrypted_bytes = Crypto.decrypt(message1['encryptedData'].encode(), client.key.encode())
    decrypted_data = json.loads(decrypted_bytes.decode())

    if not dictutils.has_keys(decrypted_data, ['serviceId','requestedExpirationTime', 'n1']):
        app.logger.info('Falha ao abrir campo criptografado da mensagem')
        return jsonify(error=('Falha ao abrir campo criptografado da mensagem.\n'
                              'Ou a requisição não segue o formato especificado '
                              'ou a chave usada na criptografia é diferente da '
                              'registrada para este cliente.'))

    # Constroi a messagem 2 e envia como resposta
    key_client_TGS = Crypto.generate_new_key()

    data_for_client = {
        'sessionKey_ClientTGS': key_client_TGS.decode(),
        'n1': decrypted_data['n1']
    }
    encrypted_bytes_for_client = Crypto.encrypt(json.dumps(data_for_client).encode(),
                                                client.key.encode())

    data_for_tgs = {
        'clientId': client.client_id,
        'requestedExpirationTime': decrypted_data['requestedExpirationTime'],
        'sessionKey_ClientTGS': key_client_TGS.decode()
    }
    encrypted_bytes_for_tgs = Crypto.encrypt(json.dumps(data_for_tgs).encode(),
                                             app.config['TGS_KEY'].encode())

    message2 = {
        'dataForClient': encrypted_bytes_for_client.decode(),
        'ticketForTGS': encrypted_bytes_for_tgs.decode()
    }

    app.logger.info(f"Permissão concedida para '{client.client_id}': \n"
                    f"    ID do serviço: {decrypted_data['serviceId']}\n"
                    f"    Prazo de validade requisitado: {decrypted_data['requestedExpirationTime']}\n"
                    f"    Chave de sessão para comunicação com o TGS: {key_client_TGS.decode()}")
    return jsonify(message2)