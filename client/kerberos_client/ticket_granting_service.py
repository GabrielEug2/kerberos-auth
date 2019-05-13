import json

import requests

from kerberos_client.utils.AES import AES
from kerberos_client.utils.random_generator import RandomGenerator
from kerberos_client.exceptions import ServiceDownError, ServerError, InvalidResponseError

class TGS:
    """Cliente para comunicação com o Serviço de Concessão de Tickets (TGS)"""
    
    TGS_URL = 'http://localhost:6000'

    @classmethod
    def request_ticket_for_service(cls, client_id, service_id, requested_expiration_time,
                                   session_key, ticket):
        """Obtem uma chave de sessão e um ticket para uso no serviço desejado.

        Args:
            client_id (str): ID do cliente atual
            service_id (str): ID do serviço que o cliente quer acessar
            requested_expiration_time (str): Tempo solicitado para uso do serviço
            session_key (bytes): Chave de sessão para comunicação com o TGS,
                fornecida pelo AS
            ticket (bytes): Ticket para o TGS, fornecido pelo AS junto com a chave
                de sessão

        Returns:
            session_key (bytes): Chave que deve ser usada para a
                criptografia na comunicação com o serviço
            ticket (bytes): Ticket contendo informações do TGS para o serviço.

        Raises:
            ServiceDownError: se o TGS não respondeu
            ServerError: se o TGS retornou uma mensagem de erro
            InvalidResponseError: se a resposta do TGS veio em um formato inesperado
        """

        # Constroi m3
        data_to_encrypt = {
            'clientId': client_id,
            'serviceId': service_id,
            'requestedExpirationTime': requested_expiration_time,
            'n2': RandomGenerator.rand_int()
        }
        bytes_to_encrypt = json.dumps(data_to_encrypt).encode()
        encrypted_bytes = AES.encrypt(bytes_to_encrypt, session_key)

        m3_data = {
            'encryptedData': encrypted_bytes.decode(),
            'ticket': ticket.decode()
        }
        
        # Envia m3 pro AS, recebe m4
        try:
            response = requests.post(f"{cls.TGS_URL}/request_ticket", json=m3_data)
        except requests.exceptions.ConnectionError:
            raise ServiceDownError("TGS is down")

        m4 = response.json()

        # Interpreta m4
        # if ('dataForClient' in m2) and ('ticketForTGS' in m2):
        #     m2_decrypted_bytes = AES.decrypt(
        #         m2['dataForClient'].encode(),
        #         client_key
        #     )
        #     m2_decrypted_data = json.loads(m2_decrypted_bytes.decode())

        #     session_key = m2_decrypted_data['sessionKey_ClientTGS'].encode()
        #     ticket = m2['ticketForTGS'].encode()

        #     return session_key, ticket
        # elif 'error' in m2:
        #     raise ServerError(m2['error'])
        # else:
        #     raise InvalidResponseError("Resposta não possui os campos esperados")