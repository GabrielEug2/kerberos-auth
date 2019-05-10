import requests
import json

from kerberos_client.utils.AES import AES
from kerberos_client.utils.random_generator import RandomGenerator

from kerberos_client.exceptions import ServiceDownError

AUTH_SERVICE_URL = 'http://localhost:5000'

class AuthServiceClient:
    @classmethod
    def request_access_to_service(cls, client_id, client_key, service_id, requested_expiration_time):
        # Constroi m1
        data_to_encrypt = {
            'serviceId': service_id,
            'requestedExpirationTime': requested_expiration_time,
            'n1': RandomGenerator.rand_int()
        }

        data_as_bytes = json.dumps(data_to_encrypt).encode()
        encrypted_bytes = AES.encrypt(data_as_bytes, client_key.encode())

        m1_data = {
            'clientId': client_id,
            'encryptedData': encrypted_bytes.decode()
        }
        m1 = json.dumps(m1_data)
        
        # Envia pro AS
        try:
            response = requests.post(f"{AUTH_SERVICE_URL}/request_access", json=m1)

            m2 = response.json()

            print(m2)
        except requests.exceptions.ConnectionError:
            raise ServiceDownError("Auth Service is down")

        return 