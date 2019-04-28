import requests
import json

from kerberos_client.utils.crypto import AES
from kerberos_client.utils.random_generator import RandomGenerator

from kerberos_client.exceptions import ServiceDownError

AUTH_SERVICE_URL = 'http://localhost:5000'

class AuthServiceClient:
    @classmethod
    def request_access_to_service(cls, client_id, client_key, service_id, ticket_expiration_date):
        # Constroi m1
        data_to_encrypt = {
            'service_id': service_id,
            'ticket_expiration_date': ticket_expiration_date,
            'n1': RandomGenerator.rand_int()
        }
        encrypted_data, iv = AES.encrypt(json.dumps(data_to_encrypt), client_key)

        m1_data = {
            'client_id': client_id,
            'encrypted_data': {
                'content': encrypted_data,
                'iv': iv
            }
        }
        m1 = json.dumps(m1_data)
        
        # Envia pro AS
        try:
            response = requests.post(f"{AUTH_SERVICE_URL}/require_access", json=m1)

            m2 = response.json()
            print(m2)
        except requests.exceptions.ConnectionError:
            raise ServiceDownError("Auth Service is down")