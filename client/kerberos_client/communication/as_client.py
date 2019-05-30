import json
import requests

from kerberos_client.crypto import Crypto
from kerberos_client.random import Random
from kerberos_client.exceptions import ServerDownError, ServerError, InvalidResponseError

class AS:
    """Cliente para comunicação com o Serviço de Autenticação (AS)"""

    AS_URL = 'http://localhost:5000'

    @classmethod
    def sign_up(cls, client_id, password):
        """Se registra no AS com o ID especificado.
        
        Args:
            client_id (str): ID desejado
            password (str): Senha
        
        Raises:
            ServerDownError: se o AS não respondeu
            ServerError: se o AS retornou uma mensagem de erro
            InvalidResponseError: se a resposta do AS veio em um formato inesperado
        """

        message = {
            'clientId': client_id,
            'password': password
        }

        try:
            response = requests.post(f"{cls.AS_URL}/sign_up", json=message)
        except requests.exceptions.ConnectionError:
            raise ServerDownError("Auth Service is down")

        try:
            response = response.json()

            if 'ok' in response:
                return
            else:
                raise ServerError(response['error'])
        except (KeyError, ValueError):
            raise InvalidResponseError("Erro ao fazer o parsing da resposta do AS")
    
    @classmethod
    def request_ticket_granting_ticket(cls, client_id, client_key, service_id, requested_time):
        """Obtem um Ticket Granting Ticket (TGT) e uma chave de sessão para uso no TGS.

        Args:
            client_id (str): ID do cliente atual
            client_key (bytes): Chave do cliente atual
            service_id (str): ID do serviço (TGS) que o cliente quer acessar
            requested_time (str): Tempo solicitado para uso do serviço (TGS)

        Returns:
            tuple: informações relacionadas ao ticket para uso no TGS.
                Contém:

                ticket (bytes): TGT criptografado do AS para o TGS
                session_key (bytes): Chave para comunicação com o TGS

        Raises:
            ServerDownError: se o AS não respondeu
            ServerError: se o AS retornou uma mensagem de erro
            InvalidResponseError: se a resposta do AS veio em um formato inesperado
        """

        data_to_encrypt = {
            'serviceId': service_id,
            'requestedTime': requested_time,
            'n1': Random.rand_int()
        }
        encrypted_bytes = Crypto.encrypt(json.dumps(data_to_encrypt).encode(), client_key)

        message1 = {
            'clientId': client_id,
            'encryptedData': encrypted_bytes.decode()
        }
        
        try:
            response = requests.post(f"{cls.AS_URL}/request_tgt", json=message1)
        except requests.exceptions.ConnectionError:
            raise ServerDownError("Auth Service is down")

        try:
            message2 = response.json()

            expected_m2_fields = ['encryptedData', 'TGT']
            if all(key in message2 for key in expected_m2_fields):
                ticket = message2['TGT'].encode()

                decrypted_bytes = Crypto.decrypt(message2['encryptedData'].encode(), client_key)
                decrypted_data = json.loads(decrypted_bytes.decode())
                session_key = decrypted_data['sessionKey_ClientTGS'].encode()
                
                return ticket, session_key
            else:
                raise ServerError(message2['error'])
        except (KeyError, ValueError):
            raise InvalidResponseError("Erro ao fazer o parsing da resposta do AS")