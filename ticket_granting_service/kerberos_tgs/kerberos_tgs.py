import os
import json

from flask import Flask
from flask import request
from flask import jsonify
from flask_pymongo import PyMongo

from kerberos_tgs.utils.crypto import Crypto
from kerberos_tgs.utils import dictutils


app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/kerberos_tgs_db"
if 'KERBEROS_TGS_CONFIG' in os.environ:
    app.config.from_envvar('KERBEROS_TGS_CONFIG')

mongo = PyMongo(app)

@app.route('/request_ticket', methods=['POST'])
def request_ticket():
    message3 = request.get_json()
    app.logger.debug(f"Received: \n{json.dumps(message3, indent=4)}")

    if not dictutils.has_keys(message3, ['encryptedData', 'ticket']):
        app.logger.info('Mensagem não segue o formato especificado')
        return jsonify(error=('Mensagem não segue o formato especificado. '
                              'Verifique a documentação.'))

    # Abre o ticket
    tgs_ticket_bytes = Crypto.decrypt(message3['ticket'].encode(),
                                      app.config['TGS_KEY'].encode())
    tgs_ticket = json.loads(tgs_ticket_bytes.decode())

    expected_tgs_ticket_fields = [
        'clientId', 'requestedExpirationTime', 'sessionKey_ClientTGS'
    ]
    if not dictutils.has_keys(tgs_ticket, expected_tgs_ticket_fields):
        app.logger.info('Falha ao abrir o ticket do AS')
        return jsonify(error='Falha ao abrir o ticket.')

    # Abre a parte criptografada com a chave de sessão
    decrypted_bytes = Crypto.decrypt(message3['encryptedData'].encode(),
                                     tgs_ticket['sessionKey_ClientTGS'])
    decrypted_data = json.loads(decrypted_bytes.decode())

    expected_encrypted_fields = [
        'clientId', 'serviceId', 'requestedExpirationTime', 'n2'
    ]
    if not dictutils.has_keys(decrypted_data, expected_encrypted_fields):
        app.logger.info('Falha ao abrir campo criptografado da mensagem')
        return jsonify(error=('Falha ao abrir campo criptografado da mensagem.\n'
                              'Ou a requisição não segue o formato especificado '
                              'ou a chave de sessão usada é diferente da '
                              'fornecida pelo AS.'))

    # Verifica se os dados conferem
    if (decrypted_data['clientId'] != tgs_ticket['clientId'] or
        decrypted_data['requestedExpirationTime'] != tgs_ticket['requestedExpirationTime']
       ):
        app.logger.info('Dados do cliente não batem com os contidos no ticket do AS')
        return jsonify(error='Dados não batem com os do ticket.')

    # Procura o serviço
    service = mongo.db.services.find_one({"_id": decrypted_data['serviceId']})

    # Constroi M4
    # Autoriza o tanto que o cliente pediu, mas poderia só deixar uma parte do tempo
    key_client_service = Crypto.generate_new_key()
    autorized_expiration_time = decrypted_data['requestedExpirationTime']

    data_for_client = {
        'sessionKey_ClientService': key_client_service.decode(),
        'autorizedExpirationTime': autorized_expiration_time,
        'n2': decrypted_data['n2']
    }
    encrypted_bytes_for_client = Crypto.encrypt(json.dumps(data_for_client).encode(),
                                                tgs_ticket['sessionKey_ClientTGS'])

    data_for_service = {
        'clientId': tgs_ticket['clientId'],
        'autorizedExpirationTime': autorized_expiration_time,
        'sessionKey_ClientService': key_client_service.decode(),
    }
    encrypted_bytes_for_service = Crypto.encrypt(json.dumps(data_for_service).encode(),
                                                 service['key'])

    message4 = {
        'dataForClient': encrypted_bytes_for_client.decode(),
        'accessTicket': encrypted_bytes_for_service.decode()
    }

    app.logger.info(f"Ticket fornecido para '{tgs_ticket['clientId']}: \n"
                    f"    ID do serviço: {decrypted_data['serviceId']}\n"
                    f"    Prazo de validade autorizado: {autorized_expiration_time}\n"
                    f"    Chave de sessão para comunicação com o serviço: {key_client_service.decode()}")
    return jsonify(message4)