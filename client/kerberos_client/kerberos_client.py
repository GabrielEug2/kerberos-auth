
from kerberos_client.auth_service_client import AuthServiceClient

from kerberos_client.exceptions import ServiceDownError

class KerberosClient:
    def __init__(self, client_id, client_key):
        self.client_id = client_id
        self.key = client_key

    def acquire_new_ticket(self, service_id, requested_expiration_time):
        print("Autenticando no AS...")
        try:
            AuthServiceClient.request_access_to_service(
                self.client_id,
                self.key,
                service_id,
                requested_expiration_time
            )
        except ServiceDownError:
            print("  Serviço de autenticação está off")

        #print("Obtendo ticket no TGS...")

    def use_service(self, service_id):
        pass