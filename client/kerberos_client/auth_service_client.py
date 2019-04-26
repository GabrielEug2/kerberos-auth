import requests
import json
from kerberos_client.utils.random_generator import RandomGenerator
from kerberos_client.utils.crypto import AES

AUTH_SERVICE_URL = 'http://localhost:5000'

class AuthServiceClient:
    @classmethod
    def request_access_to_service(cls, client_id, client_key, service_id, ticket_expiration_date):
        # Constroi a mensagem
        data_to_encrypt = {}

        data_to_encrypt['service_id'] = service_id
        data_to_encrypt['ticket_expiration_date'] = ticket_expiration_date
        data_to_encrypt['n1'] = RandomGenerator.rand_int()

        m1_data = {
            'client_id': client_id,
            'encrypted_content': AES.encrypt(json.dumps(data_to_encrypt), client_key)
        }
        m1 = json.dumps(m1_data)
        
        # Envia pro AS
        try:
            response = requests.post(f"{AUTH_SERVICE_URL}/require_access", json=m1)
        except requests.exceptions.ConnectionError:
            print("Serviço de autenticacao esta off")
            exit()

        m2 = response.json()

        print(m2)