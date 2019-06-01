import json

from flask import Blueprint, request, jsonify
from flask import current_app

from kerberos_as.time_validator import TimeValidator
from kerberos_as.models import Client
from kerberos_as.database import db_session


bp = Blueprint('routes', __name__)


@bp.route('/request_tgt', methods=['POST'])
def request_tgt():
    message1 = request.get_json()
    current_app.logger.debug(f"Received: \n{json.dumps(message1, indent=4)}")

    expected_m1_fields = ['clientId', 'encryptedData']
    if not all(key in message1 for key in expected_m1_fields):
        current_app.logger.info('Mensagem recebida não segue o formato especificado')
        return jsonify(error='Mensagem não segue o formato especificado.')

    client = Client.query.filter_by(client_id=message1['clientId']).first()
    client_exists = client is not None

    if client_exists:
        try:
            decrypted_bytes = Crypto.decrypt(message1['encryptedData'].encode(),
                                             client.key.encode())
            decrypted_data = json.loads(decrypted_bytes.decode())
        except (json.JSONDecodeError, AttributeError):
            current_app.logger.info('Falha ao descriptografar a mensagem')
            return jsonify(error='Falha ao descriptografar a mensagem')

        current_app.logger.debug(f"Dados descriptografados: \n{json.dumps(decrypted_data, indent=4)}")

        expected_decrypted_fields = ['serviceId', 'requestedTime', 'n1']
        if not all(key in decrypted_data for key in expected_decrypted_fields):
            current_app.logger.info('Parte criptografada da mensagem não tem os campos esperados')
            return jsonify(error='Parte criptografada da mensagem não tem os campos esperados')

        if not TimeValidator.requested_time_is_valid(decrypted_data['requestedTime']):
            current_app.logger.info('Tempo solicitado não segue nenhum dos formatos válidos')
            return jsonify(error='Tempo solicitado não segue nenhum dos formatos válidos')
        
        if decrypted_data['serviceId'] != 'TGS':
            current_app.logger.info("Cliente solicitou um TGT para um serviço (TGS) "
                                   f"desconhecido: {decrypted_data['serviceId']}")
            return jsonify(error='Serviço (TGS) desconhecido')

        tgt_expiration_time = decrypted_data['requestedTime']
        key_client_TGS = Crypto.generate_key()

        data_for_client = {
            'sessionKey_ClientTGS': key_client_TGS.decode(),
            'n1': decrypted_data['n1']
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
                                f"    Tempo autorizado para uso do TGS: {tgt_expiration_time}\n"
                                f"    Chave de sessão cliente-TGS fornecida: {key_client_TGS.decode()}")
        return jsonify(message2)
    else:
        current_app.logger.info(f"Cliente \"{message1['clientId']}\" não está registrado")
        return jsonify(error='Cliente não registrado.')


@bp.route('/sign_up', methods=['POST'])
def sign_up():
    message = request.get_json()
    current_app.logger.debug(f"Received: \n{json.dumps(message, indent=4)}")

    if not ('clientId' in message) or not ('password' in message):
        current_app.logger.info('Mensagem recebida não segue o formato especificado')
        return jsonify(error='Mensagem não segue o formato especificado.')

    id_already_taken = Client.query.filter_by(client_id=message['clientId']).first() is not None

    if not id_already_taken:
        # Salt determininístico para que o cliente consiga 
        # gerar a mesma chave quando for enviar M1
        client_key = Crypto.generate_key_from_password(
            password=message['password'],
            salt=message['clientId'].encode()
        )

        client = Client(message['clientId'], client_key)
        db_session.add(client)
        db_session.commit()

        current_app.logger.info(f"Novo cliente registrado: {message['clientId']}")
        return jsonify(ok='Cliente registrado com sucesso')
    else:
        current_app.logger.info(f"Falha ao registrar cliente {message['clientId']}: "
                                 "já existe um cliente registrado com este ID")
        return jsonify(error='Cliente já está registrado.')