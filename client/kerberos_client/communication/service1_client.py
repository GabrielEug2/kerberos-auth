import json
import requests
from datetime import datetime

from kerberos_client.crypto import Crypto
from kerberos_client.random import Random
from kerberos_client.exceptions import (ServerDownError,
                                        ServerError,
                                        InvalidResponseError,
                                        ResponseDoesNotMatch)

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
            ResponseDoesNotMatch: se a resposta do serviço não corresponde ao pedido
            InvalidResponseError: se a resposta do serviço veio em um formato inesperado
        """

        n3 = Random.rand_int()
        # Poderia ser um parâmetro pro cliente definir, mas 
        # achei que fazia mais sentido usar sempre a hora atual
        requested_time = datetime.now().strftime("%d/%m/%Y %H:%M")

        data_to_encrypt = {
            'clientId': client_id,
            'requestedTime': requested_time,
            'request': request,
            'n3': n3
        }
        encrypted_bytes = Crypto.encrypt(json.dumps(data_to_encrypt).encode(), session_key)

        message5 = {
            'encryptedData': encrypted_bytes.decode(),
            'accessTicket': ticket.decode()
        }
        
        try:
            response = requests.post(f"{cls.SERVICE_URL}/access", json=message5)
        except requests.exceptions.ConnectionError:
            raise ServerDownError("Falha ao se conectar com o serviço1")

        try:
            message6 = response.json()

            if 'encryptedData' in message6:
                decrypted_bytes = Crypto.decrypt(message6['encryptedData'].encode(), session_key)
                decrypted_data = json.loads(decrypted_bytes.decode())

                if n3 != decrypted_data['n3']:
                    raise ResponseDoesNotMatch(f"n3 não confere \nEnviado: {n3} \n"
                                               f"Recebido: {decrypted_data['n3']}")

                response = decrypted_data['response']

                return response
            else:
                raise ServerError(message6['error'])
        except (KeyError, ValueError):
            raise InvalidResponseError("Erro ao fazer o parsing da resposta do servico")