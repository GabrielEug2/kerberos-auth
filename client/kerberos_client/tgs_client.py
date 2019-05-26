import json

import requests

from kerberos_client.crypto import Crypto
from kerberos_client.random import Random
from kerberos_client.exceptions import ServiceDownError, ServerError, InvalidResponseError

class TGS:
    """Cliente para comunicação com o Serviço de Concessão de Tickets (TGS)"""
    
    TGS_URL = 'http://localhost:6000'

    @classmethod
    def request_ticket_for_service(cls, client_id, service_id, requested_time,
                                   session_key, ticket):
        """Obtem uma chave de sessão e um ticket para uso no serviço desejado.

        Args:
            client_id (str): ID do cliente atual
            service_id (str): ID do serviço que o cliente quer acessar
            requested_time (str): Tempo solicitado para uso do serviço
            session_key (bytes): Chave de sessão para comunicação com
                o TGS, fornecida pelo AS
            ticket (bytes): Ticket para o TGS, fornecido pelo AS

        Returns:
            tuple: informações relacionadas ao ticket para uso no serviço.
                Contém:

                session_key (bytes): Chave para comunicação com o serviço
                ticket (bytes): Ticket criptografado do TGS para o serviço

        Raises:
            ServiceDownError: se o TGS não respondeu
            ServerError: se o TGS retornou uma mensagem de erro
            InvalidResponseError: se a resposta do TGS veio em um formato inesperado
        """

        # Constroi M3
        data_to_encrypt = {
            'clientId': client_id,
            'serviceId': service_id,
            'requestedTime': requested_time,
            'n2': Random.rand_int()
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

        # Interpreta M4
        try:
            message4 = response.json()

            if all(key in message4 for key in ['dataForClient', 'accessTicket']):
                decrypted_bytes = Crypto.decrypt(message4['dataForClient'].encode(), session_key)
                decrypted_data = json.loads(decrypted_bytes.decode())

                service_session_key = decrypted_data['sessionKey_ClientService'].encode()
                autorized_time = decrypted_data['autorizedTime']
                access_ticket = message4['accessTicket'].encode()

                return service_session_key, access_ticket, autorized_time
            elif 'error' in message4:
                raise ServerError(message2['error'])
            else:
                raise InvalidResponseError("Resposta do TGS não tem os campos esperados")
        except ValueError:
            raise InvalidResponseError("Erro ao fazer o parsing da resposta do TGS")