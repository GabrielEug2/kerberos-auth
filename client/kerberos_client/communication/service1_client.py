import json
import requests
from datetime import datetime

from kerberos_client.crypto import Crypto
from kerberos_client.random import Random
from kerberos_client.exceptions import ServerDownError, ServerError, InvalidResponseError

class Service:
    """Cliente para comunicação com o Serviço 1"""
    
    SERVICE_URL = 'http://localhost:7000'

    @classmethod
    def request(cls, client_id, ticket, session_key, request):
        """Tenta acessar um serviço com o ticket especificado
        
        Args:
            client_id (str): ID do cliente solicitando o serviço
            ticket (bytes): Ticket de acesso, fornecido pelo TGS
            session_key (bytes): Chave de sessão para comunicação
                com o serviço, fornecido pelo TGS
            request (str): Requisição para o serviço

        Returns:
            str: Reposta positiva do serviço

        Raises:
            ServerDownError: se o serviço não respondeu
            ServerError: se o serviço retornou uma mensagem de erro
            InvalidResponseError: se a resposta do serviço veio em um formato inesperado
        """

        data_to_encrypt = {
            'clientId': client_id,
            'currentTime': datetime.now().strftime("%d/%m/%Y %H:%M"),
            'request': request,
            'n3': Random.rand_int()
        }
        encrypted_bytes = Crypto.encrypt(json.dumps(data_to_encrypt).encode(), session_key)

        message5 = {
            'encryptedData': encrypted_bytes.decode(),
            'accessTicket': ticket.decode()
        }
        
        try:
            response = requests.post(f"{cls.SERVICE_URL}/access", json=message5)
        except requests.exceptions.ConnectionError:
            raise ServerDownError("Service1 is down")

        try:
            message6 = response.json()

            if 'encryptedData' in message6:
                decrypted_bytes = Crypto.decrypt(message6['encryptedData'].encode(), session_key)
                decrypted_data = json.loads(decrypted_bytes.decode())

                response = decrypted_data['response']
                n3 = decrypted_data['n3']

                return response
            else:
                raise ServerError(message6['error'])
        except (KeyError, ValueError):
            raise InvalidResponseError("Erro ao fazer o parsing da resposta do servico")