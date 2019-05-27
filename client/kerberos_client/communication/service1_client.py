import json
import requests
from datetime import datetime

from kerberos_client.crypto import Crypto
from kerberos_client.random import Random
from kerberos_client.communications.exceptions import ServiceDownError, ServerError, InvalidResponseError

class Service:
    """Cliente para comunicação com o Serviço 1"""
    
    SERVICE_URL = 'http://localhost:7000'

    @classmethod
    def request(cls, client_id, service_id, ticket, session_key):
        """Tenta acessar um serviço com o ticket especificado
        
        Args:
            client_id (str): ID do cliente solicitando o serviço
            service_id (str): ID do serviço a ser contactado
            ticket (bytes): Ticket de acesso, fornecido pelo TGS
            session_key (bytes): Chave de sessão para comunicação
                com o serviço, fornecido pelo TGS

        Returns:
            str: Reposta positiva do serviço

        Raises:
            ServiceDownError: se o serviço não respondeu
            ServerError: se o serviço retornou uma mensagem de erro
            InvalidResponseError: se a resposta do serviço veio em um formato inesperado
        """

        # Constroi M5
        data_to_encrypt = {
            'clientId': client_id,
            'requestedTime': datetime.now().strftime("%d/%m/%y-%H:%M"),
            'request': "Send me something back",
            'n3': Random.rand_int()
        }
        encrypted_bytes = Crypto.encrypt(json.dumps(data_to_encrypt).encode(), session_key)

        message5 = {
            'encryptedData': encrypted_bytes.decode(),
            'ticket': ticket.decode()
        }
        
        # Envia M5 para o serviço, recebe como resposta M6
        try:
            response = requests.post(f"{cls.SERVICE_URL}/request", json=message5)
        except requests.exceptions.ConnectionError:
            raise ServiceDownError("Service1 is down")

        # Interpreta M6
        try:
            message6 = response.json()

            if 'encryptedData' in message6:
                decrypted_bytes = Crypto.decrypt(message6['encryptedData'].encode(), session_key)
                decrypted_data = json.loads(decrypted_bytes.decode())

                response = decrypted_data['response'].encode()
                n3 = decrypted_data['n3']

                return response
            else:
                raise ServerError(message2['error'])
        except (KeyError, ValueError):
            raise InvalidResponseError("Erro ao fazer o parsing da resposta do TGS")