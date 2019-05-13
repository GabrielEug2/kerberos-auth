import os
import json

from flask import Flask
from flask import request
from flask import jsonify
from flask_pymongo import PyMongo

from kerberos_as.utils.AES import AES


app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/myDatabase"
mongo = PyMongo(app)

if 'KERBEROS_TGS_CONFIG' in os.environ:
    app.config.from_envvar('KERBEROS_TGS_CONFIG')


@app.route('/request_ticket', methods=['POST'])
def request_ticket():
    m3_data = request.get_json()

    app.logger.debug(f"Received: \n{json.dumps(m3_data, indent=4)}")

    expected_m3_fields = [
        'encryptedData', 'ticket'
    ]
    if not has_keys(m3_data, expected_m3_fields):
        app.logger.info('m3 não segue o formato especificado')
        return jsonify(error=('Requisição não segue o formato especificado. '
                              'Verifique a documentação.'))

    # Abre o ticket
    ticket_decrypted_bytes = AES.decrypt(
        m3_data['ticket'].encode(),
        app.config['TGS_KEY']
    )
    ticket_decrypted_data = json.loads(ticket_decrypted_bytes.decode())

    expected_ticket_fields = [
        'clientId', 'requestedExpirationTime', 'sessionKey_ClientTGS'
    ]
    if not has_keys(ticket_decrypted_data, expected_ticket_fields):
        app.logger.info('Falha ao abrir o ticket do AS')
        return jsonify(error='Falha ao abrir o ticket.')

    # Abre a parte criptografada com a chave de sessão
    m3_decrypted_bytes = AES.decrypt(
        m3_data['encryptedData'].encode(),
        ticket_decrypted_data['sessionKey_ClientTGS']
    )
    m3_decrypted_data = json.loads(m3_decrypted_bytes.decode())

    expected_encrypted_fields = [
        'clientId', 'serviceId', 'requestedExpirationTime', 'n2'
    ]
    if not has_keys(m3_decrypted_data, expected_encrypted_fields):
        app.logger.info('Falha ao descriptografar m3')
        return jsonify(error='Falha ao descriptografar m3.')

    # Verifica se os dados conferem
    if (m3_decrypted_data['clientId'] != ticket_decrypted_data['clientId'] or
        m3_decrypted_data['requested_expiration_time'] != ticket_decrypted_data['requested_expiration_time']
       ):
        app.logger.info('Dados do cliente não batem com os contidos no ticket do AS')
        return jsonify(error='Dados não batem com os do ticket.')

    # Procura o serviço
    service = mongo.db.services.find({
        "service_id": m3_decrypted_data['serviceId']
    })

    # Constroi m4

    #M4 = [{K_c_s + T_A + N2}K_c_tgs + T_c_s]
    #Onde T_c_s = {ID_C + T_A + K_c_s}K_s

    return jsonify(m4)


def has_keys(dictionary, keys):
    if all(key in dictionary for key in keys):
        return True
    else:
        return False