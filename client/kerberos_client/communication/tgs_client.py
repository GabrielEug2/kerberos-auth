import json

import requests

from kerberos_client.crypto import Crypto
from kerberos_client.random import Random
from kerberos_client.exceptions import (ServerDownError,
                                        ServerError,
                                        InvalidResponseError,
                                        ResponseDoesNotMatch)

class TGS:
    """Cliente para comunicação com o Serviço de Concessão de Tickets (TGS)"""
    
    TGS_URL = 'http://localhost:6000'

    @classmethod
    def request_access_ticket(cls, client_id, service_id, requested_time,
                                   session_key, ticket):
        """Obtem uma chave de sessão e um ticket para uso no serviço desejado.

        Args:
            client_id (str): ID do cliente que está solicitando o ticket
            service_id (str): ID do serviço que o cliente quer acessar
            requested_time (str): Tempo solicitado para uso do serviço
            ticket (bytes): Ticket para o TGS, fornecido pelo AS
            session_key (bytes): Chave de sessão para comunicação com
                o TGS, fornecida pelo AS

        Returns:
            tuple: informações relacionadas ao ticket para uso no serviço.
                Contém:

                ticket (bytes): Ticket criptografado do TGS para o serviço
                session_key (bytes): Chave para comunicação com o serviço

        Raises:
            ServerDownError: se o TGS não respondeu
            ServerError: se o TGS retornou uma mensagem de erro
            ResponseDoesNotMatch: se a resposta do TGS não corresponde ao pedido
            InvalidResponseError: se a resposta do TGS veio em um formato inesperado
        """

        n2 = Random.rand_int()

        data_to_encrypt = {
            'clientId': client_id,
            'serviceId': service_id,
            'requestedTime': requested_time,
            'n2': n2
        }
        encrypted_bytes = Crypto.encrypt(json.dumps(data_to_encrypt).encode(), session_key)

        message3 = {
            'encryptedData': encrypted_bytes.decode(),
            'TGT': ticket.decode()
        }
        
        try:
            response = requests.post(f"{cls.TGS_URL}/request_access_ticket", json=message3)
        except requests.exceptions.ConnectionError:
            raise ServerDownError("Falha ao se conectar ao TGS")

        try:
            message4 = response.json()

            expected_m4_fields =['encryptedData', 'accessTicket']
            if all(key in message4 for key in expected_m4_fields):
                decrypted_bytes = Crypto.decrypt(message4['encryptedData'].encode(), session_key)
                decrypted_data = json.loads(decrypted_bytes.decode())

                if n2 != decrypted_data['n2']:
                    raise ResponseDoesNotMatch("n2 não confere")

                access_ticket = message4['accessTicket'].encode()
                service_session_key = decrypted_data['sessionKey_ClientService'].encode()
                autorized_time = decrypted_data['autorizedTime']

                return access_ticket, service_session_key, autorized_time
            else:
                raise ServerError(message4['error'])
        except (KeyError, ValueError):
            raise InvalidResponseError("Erro ao fazer o parsing da resposta do TGS")