
import json
from datetime import datetime

from flask import Blueprint, request, jsonify
from flask import current_app

from kerberos_tgs.exceptions import BadMessageError
from kerberos_tgs.time_manager import TimeManager
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

        current_app.logger.debug(f"TGT descriptografado: \n{json.dumps(tgt, indent=4)}")

        expected_tgt_fields = ['clientId', 'TGT_expirationTime', 'sessionKey_ClientTGS']
        if not all(key in tgt for key in expected_tgt_fields):
            raise BadMessageError("Ticket não tem os campos esperados")

        if not TimeManager.tgt_expiration_date_is_valid(tgt['TGT_expirationTime']):
            raise BadMessageError("Prazo de validade não segue o formato especificado")
    except json.JSONDecodeError:
        current_app.logger.info("Falha ao descriptografar o ticket")
        return jsonify(error='Falha ao descriptografar o ticket')
    except BadMessageError as e:
        current_app.logger.info(e)
        return jsonify(error=f"Ticket mal formatado. {e}")
    
    try:
        client_bytes = Crypto.decrypt(message3['encryptedData'].encode(),
                                      tgt['sessionKey_ClientTGS'])
        client_data = json.loads(client_bytes.decode())

        current_app.logger.debug(f"Dados descriptografados: \n{json.dumps(client_data, indent=4)}")

        expected_client_fields = ['clientId', 'serviceId', 'requestedTime', 'n2']
        if not all(key in client_data for key in expected_client_fields):
            raise BadMessageError("Parte criptografada da mensagem não tem os campos esperados")

        if not TimeManager.requested_time_is_valid(client_data['requestedTime']):
            raise BadMessageError("Tempo solicitado não segue o formato especificado")
    except json.JSONDecodeError:
        current_app.logger.info('Falha ao descriptografar a mensagem')
        return jsonify(error='Falha ao descriptografar a mensagem')
    except BadMessageError as e:
        current_app.logger.info(e)
        return jsonify(error=f"Mensagem mal formatada. Erro: {e}")
    
    service = mongo.db.services.find_one({"_id": client_data['serviceId']})
    tgt_expiration_time = TimeManager.expiration_date_str_to_date(tgt['expirationDate'])

    client_matches = client_data['clientId'] == tgt['clientId']
    tgt_is_valid = datetime.now() < tgt_expiration_time
    service_exists = service is not None

    if (client_matches and tgt_is_valid and service_exists):
        autorized_time = TimeManager.compute_autorized_time(client_data['requestedTime'])
        key_client_service = Crypto.generate_key()

        data_for_client = {
            'sessionKey_ClientService': key_client_service.decode(),
            'autorizedTime': autorized_time,
            'n2': client_data['n2']
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
                        f"    ID do serviço: {client_data['serviceId']}\n"
                        f"    Tempo solicitado: {client_data['requestedTime']}\n"
                        f"    Tempo autorizado: {autorized_time}\n"
                        f"    Chave de sessão client-serviço fornecida: {key_client_service.decode()}")
        return jsonify(message4)
    elif not client_matches:
        current_app.logger.info(f"Cliente {client_data['clientId']} tentou "
                                'utilizar um TGT que não lhe pertence '
                                f"(dono do ticket: {tgt['clientId']}")
        return jsonify(error='Acesso negado. Ticket não é válido para esse cliente')
    elif not tgt_is_valid:
        current_app.logger.info('TGT não é mais válido')
        return jsonify(error='TGT não é mais válido')
    else:
        current_app.logger.info(f"Serviço solicitado ({client_data['serviceId']}) não existe")
        return jsonify(error='Serviço desconhecido.')