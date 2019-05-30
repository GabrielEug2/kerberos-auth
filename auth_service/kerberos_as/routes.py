import json
from datetime import datetime

from flask import Blueprint, request, jsonify
from flask import current_app

from kerberos_as.exceptions import BadMessageError
from kerberos_as.models import Client
from kerberos_as.database import db_session


bp = Blueprint('routes', __name__)


@bp.route('/sign_up', methods=['POST'])
def sign_up():
    message = request.get_json()
    current_app.logger.debug(f"Received: \n{json.dumps(message, indent=4)}")

    if not ('clientId' in message) or not ('password' in message):
        current_app.logger.info('Mensagem não segue o formato especificado')
        return jsonify(error='Mensagem não segue o formato especificado.')

    id_already_taken = Client.query.filter_by(client_id=message['clientId']).first() is not None

    if not id_already_taken:
        client_key = Crypto.generate_key_from_password(message['password'],
                                                       salt=message['clientId'].encode())
        client = Client(message['clientId'], client_key)
        db_session.add(client)
        db_session.commit()

        current_app.logger.info(f"Novo cliente registrado: {message['clientId']}")
        return jsonify(ok="Cliente registrado com sucesso")
    else:
        current_app.logger.info("Cliente já está registrado")
        return jsonify(error="Cliente já está registrado.")


@bp.route('/request_tgt', methods=['POST'])
def request_tgt():
    message1 = request.get_json()
    current_app.logger.debug(f"Received: \n{json.dumps(message1, indent=4)}")

    expected_m1_fields = ['clientId', 'encryptedData']
    if not all(key in message1 for key in expected_m1_fields):
        current_app.logger.info('Mensagem não segue o formato especificado')
        return jsonify(error='Mensagem não segue o formato especificado.')

    client = Client.query.filter_by(client_id=message1['clientId']).first()

    client_exists = client is not None
    if not client_exists:
        current_app.logger.info(f"Cliente \"{message1['clientId']}\" não está registrado")
        return jsonify(error='Cliente não registrado.')

    try:
        client_bytes = Crypto.decrypt(message1['encryptedData'].encode(),
                                      client.key.encode())
        client_data = json.loads(client_bytes.decode())

        current_app.logger.debug(f"Dados descriptografados: \n{json.dumps(client_data, indent=4)}")

        expected_client_fields = ['serviceId', 'requestedTime', 'n1']
        if not all(key in client_data for key in expected_client_fields):
            raise BadMessageError("Parte criptografada da mensagem não tem os campos esperados")

        if not TimeVerifier.requested_time_is_valid(client_data['requestedTime']):
            raise BadMessageError("Tempo solicitado não segue o formato especificado")
    except json.JSONDecodeError:
        current_app.logger.info("Falha ao descriptografar a mensagem")
        return jsonify(error='Falha ao descriptografar a mensagem')
    except BadMessageError as e:
        current_app.logger.info(e)
        return jsonify(error=f"Mensagem mal formatada. Erro: {e}")

    if client_data['serviceId'] != 'TGS':
        current_app.logger.info('Cliente solicitou um TGT para um TGS '
                               f"desconhecido: \"{client_data['serviceId']}\"")
        return jsonify(error='TGS desconhecido.')

    tgt_expiration_time = client_data['requestedTime']
    key_client_TGS = Crypto.generate_key()

    data_for_client = {
        'sessionKey_ClientTGS': key_client_TGS.decode(),
        'n1': client_data['n1']
    }
    encrypted_bytes_for_client = Crypto.encrypt(json.dumps(data_for_client).encode(),
                                                client.key.encode())

    data_for_tgs = {
        'clientId': client.client_id,
        'TGT_expirationTime': tgt_expiration_time,
        'sessionKey_ClientTGS': key_client_TGS.decode()
    }
    encrypted_bytes_for_tgs = Crypto.encrypt(json.dumps(data_for_tgs).encode(),
                                             current_app.config['TGS_KEY'].encode())

    message2 = {
        'encryptedData': encrypted_bytes_for_client.decode(),
        'TGT': encrypted_bytes_for_tgs.decode()
    }

    current_app.logger.info(f"Cliente \"{client.client_id}\" autenticado: \n"
                    f"    Tempo solicitado para uso do TGS: {client_data['requestedTime']}\n"
                    f"    Chave de sessão cliente-TGS fornecida: {key_client_TGS.decode()}")
    return jsonify(message2)