import json

import requests

from kerberos_client.utils.crypto import Crypto
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

        # Constroi M3
        data_to_encrypt = {
            'clientId': client_id,
            'serviceId': service_id,
            'requestedExpirationTime': requested_expiration_time,
            'n2': RandomGenerator.rand_int()
        }
        encrypted_bytes = Crypto.encrypt(json.dumps(data_to_encrypt).encode(), session_key)

        message3 = {
            'encryptedData': encrypted_bytes.decode(),
            'ticket': ticket.decode()
        }
        
        # Envia M3 para o TGS, recebe como resposta M4
        try:
            response = requests.post(f"{cls.TGS_URL}/request_ticket", json=message3)
        except requests.exceptions.ConnectionError:
            raise ServiceDownError("TGS is down")

        message4 = response.json()

        # Interpreta M4