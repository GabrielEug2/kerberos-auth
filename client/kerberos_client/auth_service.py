import json

import requests

from kerberos_client.utils.crypto import Crypto
from kerberos_client.utils.random_generator import RandomGenerator
from kerberos_client.exceptions import ServiceDownError, ServerError, InvalidResponseError

class AS:
    """Cliente para comunicação com o Serviço de Autenticação (AS)"""

    AS_URL = 'http://localhost:5000'

    @classmethod
    def request_access_to_service(cls, client_id, client_key, service_id,
                                  requested_expiration_time):
        """Obtem uma chave de sessão e um ticket para uso no TGS.

        Args:
            client_id (str): ID do cliente atual
            client_key (bytes): Chave do cliente atual
            service_id (str): ID do serviço que o cliente quer acessar
            requested_expiration_time (str): Tempo solicitado para uso do serviço

        Returns:
            session_key (bytes): Chave que deve ser usada para a
                criptografia na comunicação com o TGS
            ticket (bytes): Ticket contendo informações do AS para o TGS.

        Raises:
            ServiceDownError: se o AS não respondeu
            ServerError: se o AS retornou uma mensagem de erro
            InvalidResponseError: se a resposta do AS veio em um formato inesperado
        """

        # Constroi M1
        data_to_encrypt = {
            'serviceId': service_id,
            'requestedExpirationTime': requested_expiration_time,
            'n1': RandomGenerator.rand_int()
        }
        encrypted_bytes = Crypto.encrypt(json.dumps(data_to_encrypt).encode(), client_key)

        message1 = {
            'clientId': client_id,
            'encryptedData': encrypted_bytes.decode()
        }
        
        # Envia a M1 para o AS, recebe como resposta M2
        try:
            response = requests.post(f"{cls.AS_URL}/request_access", json=message1)
        except requests.exceptions.ConnectionError:
            raise ServiceDownError("Auth Service is down")

        message2 = response.json()

        # Interpreta M2
        if dictutils.has_keys(message2, ['dataForClient', 'ticketForTGS']):
            decrypted_bytes = Crypto.decrypt(message2['dataForClient'].encode(), client_key)
            decrypted_data = json.loads(decrypted_bytes.decode())

            session_key = decrypted_data['sessionKey_ClientTGS'].encode()
            ticket = message2['ticketForTGS'].encode()

            return session_key, ticket
        elif 'error' in message2:
            raise ServerError(message2['error'])
        else:
            raise InvalidResponseError("Resposta do AS não possui os campos esperados")