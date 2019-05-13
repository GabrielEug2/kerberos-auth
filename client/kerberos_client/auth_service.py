import json

import requests

from kerberos_client.utils.AES import AES
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

        # Constroi m1
        data_to_encrypt = {
            'serviceId': service_id,
            'requestedExpirationTime': requested_expiration_time,
            'n1': RandomGenerator.rand_int()
        }
        bytes_to_encrypt = json.dumps(data_to_encrypt).encode()
        encrypted_bytes = AES.encrypt(bytes_to_encrypt, client_key)

        m1_data = {
            'clientId': client_id,
            'encryptedData': encrypted_bytes.decode()
        }
        
        # Envia m1 pro AS, recebe m2
        try:
            response = requests.post(f"{cls.AS_URL}/request_access", json=m1_data)
        except requests.exceptions.ConnectionError:
            raise ServiceDownError("Auth Service is down")

        m2 = response.json()

        # Interpreta m2
        if ('dataForClient' in m2) and ('ticketForTGS' in m2):
            m2_decrypted_bytes = AES.decrypt(
                m2['dataForClient'].encode(),
                client_key
            )
            m2_decrypted_data = json.loads(m2_decrypted_bytes.decode())

            session_key = m2_decrypted_data['sessionKey_ClientTGS'].encode()
            ticket = m2['ticketForTGS'].encode()

            return session_key, ticket
        elif 'error' in m2:
            raise ServerError(m2['error'])
        else:
            raise InvalidResponseError("Resposta não possui os campos esperados")