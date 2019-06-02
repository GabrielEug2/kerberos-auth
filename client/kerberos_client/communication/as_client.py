import json
import requests

from kerberos_client.crypto import Crypto
from kerberos_client.random import Random
from kerberos_client.exceptions import (ServerDownError,
                                        ServerError,
                                        InvalidResponseError,
                                        ResponseDoesNotMatch)

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
            client_id (str): ID do cliente que está solicitando o ticket
            client_key (bytes): Chave do cliente que está solicitando o ticket
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
            ResponseDoesNotMatch: se a resposta do AS não corresponde ao pedido
            InvalidResponseError: se a resposta do AS veio em um formato inesperado
        """

        n1 = Random.rand_int()

        data_to_encrypt = {
            'serviceId': service_id,
            'requestedTime': requested_time,
            'n1': n1
        }
        encrypted_bytes = Crypto.encrypt(json.dumps(data_to_encrypt).encode(), client_key)

        message1 = {
            'clientId': client_id,
            'encryptedData': encrypted_bytes.decode()
        }
        
        try:
            response = requests.post(f"{cls.AS_URL}/request_tgt", json=message1)
        except requests.exceptions.ConnectionError:
            raise ServerDownError("Falha ao se conectar ao AS")

        try:
            message2 = response.json()

            expected_m2_fields = ['encryptedData', 'TGT']
            if all(key in message2 for key in expected_m2_fields):
                decrypted_bytes = Crypto.decrypt(message2['encryptedData'].encode(), client_key)
                decrypted_data = json.loads(decrypted_bytes.decode())

                if n1 != decrypted_data['n1']:
                    raise ResponseDoesNotMatch(f"n1 não confere \nEnviado: {n1} \n"
                                               f"Recebido: {decrypted_data['n1']}")

                ticket = message2['TGT'].encode()
                session_key = decrypted_data['sessionKey_ClientTGS'].encode()
                    
                return ticket, session_key
            else:
                raise ServerError(message2['error'])
        except (KeyError, ValueError):
            raise InvalidResponseError("Erro ao fazer o parsing da resposta do AS")