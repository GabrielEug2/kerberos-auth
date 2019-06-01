
import json
from datetime import datetime

from flask import Blueprint, request, jsonify
from flask import current_app

from kerberos_tgs.time_validator import TimeValidator
from kerberos_tgs.time_autorizer import TimeAutorizer
from kerberos_tgs.database import mongo


bp = Blueprint('routes', __name__)


@bp.route('/request_access_ticket', methods=['POST'])
def request_access_ticket():
    message3 = request.get_json()
    current_app.logger.debug(f"Received: \n{json.dumps(message3, indent=4)}")

    expected_m3_fields = ['encryptedData', 'TGT']
    if not all(key in message3 for key in expected_m3_fields):
        current_app.logger.info('Mensagem não segue o formato especificado')
        return jsonify(error='Mensagem não segue o formato especificado.')

    try:
        tgt_bytes = Crypto.decrypt(message3['TGT'].encode(),
                                   current_app.config['TGS_KEY'].encode())
        tgt = json.loads(tgt_bytes.decode())
    except (json.JSONDecodeError, AttributeError):
        current_app.logger.info('Falha ao descriptografar o ticket')
        return jsonify(error='Falha ao descriptografar o ticket')

    current_app.logger.debug(f"TGT descriptografado: \n{json.dumps(tgt, indent=4)}")

    expected_tgt_fields = ['clientId', 'TGT_expirationTime', 'sessionKey_ClientTGS']
    if not all(key in tgt for key in expected_tgt_fields):
        current_app.logger.info('Ticket não tem os campos esperados')
        return jsonify(error='Ticket não tem os campos esperados')
    
    if not TimeValidator.tgt_expiration_time_is_valid(tgt['TGT_expirationTime']):
        current_app.logger.info('Prazo de validade do TGT não segue o formato especificado')
        return jsonify(error='Prazo de validade do TGT não segue o formato especificado')

    try:
        decrypted_bytes = Crypto.decrypt(message3['encryptedData'].encode(),
                                         tgt['sessionKey_ClientTGS'].encode())
        decrypted_data = json.loads(decrypted_bytes.decode())
    except (json.JSONDecodeError, AttributeError):
        current_app.logger.info('Falha ao descriptografar a mensagem')
        return jsonify(error='Falha ao descriptografar a mensagem')

    current_app.logger.debug(f"Dados descriptografados: \n{json.dumps(decrypted_data, indent=4)}")

    expected_client_fields = ['clientId', 'serviceId', 'requestedTime', 'n2']
    if not all(key in decrypted_data for key in expected_client_fields):
        current_app.logger.info('Parte criptografada da mensagem não tem os campos esperados')
        return jsonify(error='Parte criptografada da mensagem não tem os campos esperados')

    if not TimeValidator.requested_time_is_valid(decrypted_data['requestedTime']):
        current_app.logger.info('Tempo solicitado não segue nenhum dos formatos válidos')
        return jsonify(error='Tempo solicitado não segue nenhum dos formatos válidos')

    client_matches = decrypted_data['clientId'] == tgt['clientId']

    service = mongo.db.services.find_one({"_id": decrypted_data['serviceId']})
    service_exists = service is not None

    tgt_expiration_time = datetime.strptime(tgt['TGT_expirationTime'],
                                            TimeValidator.TGT_EXPIRATION_TIME_FORMAT)
    tgt_expired = datetime.now() > tgt_expiration_time

    if (client_matches and (not tgt_expired) and service_exists):
        autorized_time = TimeAutorizer.compute_autorized_time(decrypted_data['requestedTime'])
        key_client_service = Crypto.generate_key()

        data_for_client = {
            'sessionKey_ClientService': key_client_service.decode(),
            'autorizedTime': autorized_time,
            'n2': decrypted_data['n2']
        }
        encrypted_bytes_for_client = Crypto.encrypt(json.dumps(data_for_client).encode(),
                                                    tgt['sessionKey_ClientTGS'])

        data_for_service = {
            'clientId': tgt['clientId'],
            'autorizedTime': autorized_time,
            'sessionKey_ClientService': key_client_service.decode()
        }
        encrypted_bytes_for_service = Crypto.encrypt(json.dumps(data_for_service).encode(),
                                                     service['key'])

        message4 = {
            'encryptedData': encrypted_bytes_for_client.decode(),
            'accessTicket': encrypted_bytes_for_service.decode()
        }

        current_app.logger.info(f"Ticket fornecido para '{tgt['clientId']}': \n"
                        f"    ID do serviço: {service._id}\n"
                        f"    Tempo solicitado: {decrypted_data['requestedTime']}\n"
                        f"    Tempo autorizado: {autorized_time}\n"
                        f"    Chave de sessão client-serviço fornecida: {key_client_service.decode()}")
        return jsonify(message4)
    elif not client_matches:
        current_app.logger.info(f"Cliente {decrypted_data['clientId']} tentou "
                                 "utilizar um TGT que não lhe pertence "
                                f"(dono: {tgt['clientId']})")
        return jsonify(error='Acesso negado. Ticket não é válido para esse cliente')
    elif tgt_expired:
        current_app.logger.info('TGT não é mais válido')
        return jsonify(error='TGT não é mais válido')
    else:
        current_app.logger.info(f"Serviço solicitado não existe: {decrypted_data['serviceId']}")
        return jsonify(error='Serviço desconhecido.')