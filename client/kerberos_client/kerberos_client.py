
from kerberos_client.auth_service_client import AuthServiceClient

class kerberosClient:
    def __init__(self, client_id, client_key):
        self.client_id = client_id
        self.key = client_key

    def acquire_new_ticket(self, service_id, expiration_date):
        print("Autenticando no AS...")
        AuthServiceClient.request_access_to_service(
            self.client_id,
            self.key,
            service_id,
            expiration_date
        )

        #print("Obtendo ticket no TGS...")

    def use_service(self, service_id):
        pass